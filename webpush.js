/*
 * Browser-based Web Push client for the application server piece.
 *
 * Uses the WebCrypto API.
 * Uses the fetch API.  Polyfill: https://github.com/github/fetch
 */

  'use strict';
  var g = window;

  // Semi-handy variable defining the encryption data to be
  // Elliptical Curve (Diffie-Hellman) (ECDH) using the p256 curve.
  var P256DH = {
    name: 'ECDH',
    namedCurve: 'P-256'
  };

  // WebCrypto (defined by http://www.w3.org/TR/WebCryptoAPI/) is detailed
  // at https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
  //
  // this has the various encryption library helper functions for things like
  // EC crypto. It's very nice because it makes calls simple, unfortunately,
  // it also prevents some key auditing.
  //
  // It's worth noting that there's two parts to this. The first uses
  // ECDH to get "key agreement". This allows to parties to get a secure key
  // even over untrusted links.
  //
  // The second part is the actual message encryption using the agreed key
  // created by the ECDH dance.
  //
  var webCrypto = g.crypto.subtle;

  // Per the WebPush API, there are known token values that are used for some
  // portions of the Nonce creations.
  var ENCRYPT_INFO = new TextEncoder('utf-8').encode(
     "Content-Encoding: aesgcm128");
  var NONCE_INFO = new TextEncoder('utf-8').encode("Content-Encoding: nonce");

  function textWrap(text, limit) {
    let tlen = text.length;
    let buff = ""
    for (let i=0;i<=tlen;i+=limit) {
        buff += text.slice(i, Math.min(i+limit, tlen));
        if (i+limit < tlen) {
            buff += "\\\n";
        }
    }
    return buff;
  }

  /* Coerces data into a Uint8Array */
  function ensureView(data) {
    if (typeof data === 'string') {
      return new TextEncoder('utf-8').encode(data);
    }
    if (data instanceof ArrayBuffer) {
      return new Uint8Array(data);
    }
    if (ArrayBuffer.isView(data)) {
      return new Uint8Array(data.buffer);
    }
    throw new Error('webpush() needs a string or BufferSource');
  }

  function hmac(key) {
    this.keyPromise = webCrypto.importKey(
        'raw',
        key,
        {
            name: 'HMAC',
            hash: 'SHA-256'
        },
        true,   // Should be false for production.
        ['sign']);
  }
  hmac.prototype.hash = function(input) {
    return this.keyPromise.then(k => webCrypto.sign('HMAC', k, input));
  }

  function hkdf(salt, ikm) {
    this.prkhPromise = new hmac(salt).hash(ikm)
      .then(prk => new hmac(prk));
  }

  hkdf.prototype.generate = function(info, len) {
    var input = bsConcat([info, new Uint8Array([1])]);
    return this.prkhPromise
      .then(prkh => prkh.hash(input))
      .then(h => {
        if (h.byteLength < len) {
          throw new Error('Length is too long');
        }
        var reply;
        reply  = h.slice(0, len);
        // console.debug("hkdf gen", base64url.encode(new Int8Array(reply)));
        return reply;
      });
  };

  Promise.allMap = function(o) {
    var result = {};
    return Promise.all(
      Object.keys(o).map(
        k => Promise.resolve(o[k]).then(r => result[k] = r)
      )
    ).then(_ => result);
  };

  /* generate a 96-bit IV for use in GCM, 48-bits of which are populated */
  function generateNonce(base, index) {
    var nonce = base.slice(0, 12);
    for (var i = 0; i < 6; ++i) {
      nonce[nonce.length - 1 - i] ^= (index / Math.pow(256, i)) & 0xff;
    }
    return nonce;
  }

  function encrypt(localKey, remoteShare, salt, data) {
    /* Encrypt the data using the temporary, locally generated key,
     * the remotely shared key, and a salt value
     *
     * @param localKey      A temporary, local EC key
     * @param remoteShare   The public EC key shared by the client
     * @param salt          A random "salt" value for the encrypted data
     * @param data          The data to encrypt
     */
    console.debug("calling encrypt(", localKey, remoteShare, salt, data, ")");
    // Note: Promises can make things a bit hard to follow if you're not
    // familiar with how they work. I'm not going to try to duplicate the
    // fine work of articles like
    // http://www.html5rocks.com/en/tutorials/es6/promises/ but suffice
    // to say that the return of each .then() feeds into the next.
    //
    // Import the raw key
    // see: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
    return webCrypto.importKey('raw',
                               remoteShare, // the remotely shared key
                               P256DH,      // P256 Elliptical Curve, Diffie Hellman
                               true,        // Should be false for prodution
                               ['deriveBits'] // Derive the private key from the imported bits.
                               )
      .then(remoteKey => {
          // Ok, we've got a representation of the remote key.
          // Now, derive a shared key from our temporary local key
          // and the remote key we just created.
          console.debug("client p256dh key:", remoteKey);
          var args = {name: P256DH.name,
                      public: remoteKey}
          console.debug("deriving new key: ", args, localKey, 256)
          return webCrypto.deriveBits(args,
                                      localKey,
                                      256)
      })
      .then(sharedKey => {
          // We now have usable AES key material
          // derived from the remote public key.
          var sharedKeyStr = base64url.encode(new Int8Array(sharedKey));
          output("sharedKey", sharedKeyStr);

          // Use hkdf to generate both the encryption array and the nonce.
          // See hkdf() in base64.js
          var kdf = new hkdf(salt, sharedKey);
          // Generate the encryptingData, the base object that contains the
          // key and nonce we'll use to actually encrypt the text to be
          // sent.
          return Promise.allMap({
            // The key is generated from a known pattern that's fed to
            // the hkdf that's been initialized off of the salt and the
            // sharedKey derived from the public half of the ECDH key
            // from the browser (the p256dh key)
            key: kdf.generate(ENCRYPT_INFO, 16)
              .then(gcmBits => {
                output('gcmB', base64url.encode(new Int8Array(gcmBits)));
                return webCrypto.importKey(
                    'raw',          // Import key without an envelope
                    gcmBits,        // the key data
                    'AES-GCM',      // The type of key to generate
                    true,
                    ['encrypt'])    // Use this key for encryption
              }),
              // Now, create the Nonce, from the known nonce info.
            nonce: kdf.generate(NONCE_INFO, 12)
              .then(nonceBits => {
                  output('nonce', base64url.encode(new Int8Array(nonceBits)));
                  return nonceBits})
          })
      })
      .then(encryptingData => {
          // 4096 bytes is the default size, though we burn 1 byte for padding
          console.debug("encryptingData:",encryptingData);
          // divide the data into chunks, then, for each chunk...
          return Promise.all(
              chunkArray(data, 4095)
              .map((slice, index) => {
                   // determine the "padded" data block
                   var padded = bsConcat([new Uint8Array([0]), slice]);
                  // Generate the Initialization Vector (iv) for this block
                  // based on the previously generated nonce and the offset
                  // of the block.
                   var iv = generateNonce(encryptingData.nonce, index);
                   output("iv", base64url.encode(iv));
                   var edata= webCrypto.encrypt(
                     {
                        name: 'AES-GCM',
                        iv: iv,
                     },
                     encryptingData.key,
                     padded);
                   return edata;
          }));
    }).then(data=> {
        // Turn the object into a single array
        return bsConcat(data);
    })
    .catch(
        x => console.error(x)
     );
  }

  /*
   * Request push for a message.  This returns a promise that resolves when the
   * push has been delivered to the push service.
   *
   * @param subscription A PushSubscription that contains endpoint and p256dh
   *                     parameters.
   * @param data         The message to send.
   */
  function webpush(subscription, data, salt) {
    console.debug('data:', data);
    data = ensureView(data);
    // console.debug(new TextDecoder('utf-8').decode(data))

    if (salt == null) {
        console.debug("Making new salt");
        salt = g.crypto.getRandomValues(new Uint8Array(16));
        output('salt', salt);
    }
    return webCrypto.generateKey(
            P256DH,
            true,          // false for production
            ['deriveBits'])
      .then(localKey => {
        // Dump the local public key
        // WebCrypto only allows you to export private keys as jwk.
        webCrypto.exportKey('jwk', localKey.publicKey)
            .then(key=>{
                //output('localKeyPub', base64url.encode(key))
                output('localKeyPub', JSON.stringify(key));
            })
            .catch(x => console.error(x));
        webCrypto.exportKey('raw', localKey.publicKey)
          .then(key=>{
              output('local_key', base64url.encode(key));
          });
        // Dump the local private key
        webCrypto.exportKey('jwk', localKey.privateKey)
            .then(key=> {
                console.debug("Private Key:", key)
                output('localKeyPri', JSON.stringify(key))
            })
            .catch(x => {console.error(x);
                         output('localKeyPri', "Could not display key: " + x);
            });
        console.debug("Local Key", localKey);
        // encode all the data as chunks
        return Promise.allMap({
          payload: encrypt(localKey.privateKey,
                           subscription.p256dh,
                           salt,
                           data),
          pubkey: webCrypto.exportKey('raw', localKey.publicKey)
        });
      })
      .then(results => {
          let options = {}
          let headers = new Headers();
          headers.append('encryption-key',
                'keyid=p256dh;dh=' + base64url.encode(results.pubkey));
          headers.append('encryption',
                'keyid=p256dh;salt=' + base64url.encode(salt));
          headers.append('content-encoding', 'aesgcm128')
          headers.append('ttl', 60)
          options.salt = salt;
          options.dh = results.pubkey;
          options.endpoint = subscription.endpoint;
          // include the headers here because sometimes you can't extract
          // them from a used Headers object.
          options.headers = headers;
          options.payload = results.payload;
          options.method = 'POST';
          return options;
      })
      .catch(err => console.error("Unknown error:", err));
  }

function send(options) {
    console.debug('payload', options.payload);
    let endpoint = options.endpoint;
    let send_options = {
        method: options.method,
        headers: options.headers,
        body: options.payload,
        cache: "no-cache",
        referrer: "no-referrer",
    };
    // Note, fetch doesn't always seem to want to send the Headers.
    // Chances are VERY Good that if this returns an error, the headers
    // were not set. You can check the Network debug panel to see if
    // the request included the headers.
    console.debug("Fetching:", options.endpoint, send_options);
    let req = new Request(options.endpoint, send_options);
    console.debug("request:", req);
    return fetch(req)
        .then(response => {
            if (! response.ok) {
                if (response.status == 400) {
                    show_err("Server returned 400. Probably " +
                    "missing headers.<br>If refreshing doesn't work " +
                    "the 'curl' call below should still work fine.");
                    show_ok(false);
                    throw new Error("Server Returned 400");
                }
                throw new Error('Unable to deliver message: ',
                                JSON.stringify(response));
            } else {
                console.info("Message sent", response.status)
            }
            return true;
        })
        .catch(err =>{
             console.error("Send Failed: ", err);
             show_ok(false);
             return false;
        });
}
