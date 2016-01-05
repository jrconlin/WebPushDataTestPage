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

  function bsConcat(arrays) {
    // Concatinate the byte arrays.
    var size = arrays.reduce((total, a) => total + a.byteLength, 0);
    var index = 0;
    return arrays.reduce((result, a) => {
      result.set(new Uint8Array(a), index);
      index += a.byteLength;
      return result;
    }, new Uint8Array(size));
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
    console.debug("encrypt", localKey, remoteShare, salt, data);
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
          console.debug("remoteKey", remoteKey);
          var args = {name: P256DH.name,
                      public: remoteKey}
          console.debug("deriving: ", args, localKey, 256)
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
          var kdf = new hkdf(salt, sharedKey);
          return Promise.allMap({
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
                   console.debug("slice :",base64url.encode(slice));
                   console.debug("padded:", base64url.encode(padded));
                   console.debug("orig:", new TextDecoder('utf-8').decode(padded));
                   // TODO: WHy is this returning the same value as nonce?
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
              output('localKeyPubRaw', base64url.encode(key));
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
      }).then(results => {
        let options = {
            method: 'PUT',
            headers: {
                'Encryption-Key': 'keyid=p256dh;dh=' + base64url.encode(
                    results.pubkey),
                'Encryption': 'keyid=p256dh;salt=' + base64url.encode(salt),
                'Content-Encoding': 'aesgcm128',
            },
            body: results.payload
        };
        output('osalt', base64url.encode(salt));
        output('odh', base64url.encode(results.pubkey));
        output('odata', new TextDecoder('utf-8').decode(results.payload));
        let outStr = "";
        var sbody = "";
        for (let k in new TextDecoder('utf-8').decode(results.payload)) {
            sbody += "\\x" + (results.payload[k]).toString(16);
        }
        outStr += 'echo -e "' + sbody + '" > foo.dat;\n';
        outStr += "curl -v -X " + options.method + " " +
                           subscription.endpoint + " ";
        for (let k in options.headers) {
            outStr += " -H \"" + k + ": "+ options.headers[k] +"\" "
        }
        outStr += ' --data-binary @foo.dat';
        output('curl', outStr);
        return fetch(subscription.endpoint, options);
      })
      .then(response => {
        if (response.status < 200 || response.status > 299) {
          throw new Error('Unable to deliver message: ', JSON.stringify(response));
        }
      })
      .catch(err => console.error("Send Failed: ", err))
  }
