/*
 * Browser-based Web Push client for the application server piece.
 *
 * Uses the WebCrypto API.
 * Uses the fetch API.  Polyfill: https://github.com/github/fetch
 */

  'use strict';
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
  try {
      if (webCrypto === undefined) {
          webCrypto = window.crypto.subtle;
      }
  } catch (e) {
      var webCrypto = window.crypto.subtle;
  }

  // Per the WebPush API, there are known token values that are used for some
  // portions of the Nonce creations.
  var ENCRYPT_INFO = new TextEncoder('utf-8').encode(
     "Content-Encoding: aesgcm128");
  var NONCE_INFO = new TextEncoder('utf-8').encode("Content-Encoding: nonce");
  var AUTH_INFO = new TextEncoder('utf-8').encode("Content-Encoding: auth\0");

  function ensureView(data) {
    /* Coerces data into a Uint8Array */
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

  Promise.allMap = function(o) {
      // Resolve a list of promises
    var result = {};
    return Promise.all(
      Object.keys(o).map(
        k => Promise.resolve(o[k]).then(r => result[k] = r)
      )
    ).then(_ => result);
  };

  function generateNonce(base, index) {
    /* generate a 96-bit IV for use in GCM, 48-bits of which are populated */
    var nonce = base.slice(0, 12);
    for (var i = 0; i < 6; ++i) {
      nonce[nonce.length - 1 - i] ^= (index / Math.pow(256, i)) & 0xff;
    }
    return nonce;
  }

  function encodeLength(buffer) {
      /* Encode a buffer's length as a psuedo 16be value */
      return new Uint8Array([0, buffer.byteLength]);
  }



  function encrypt(senderKey, sub, data, salt) {
    /* Encrypt the data using the temporary, locally generated key,
     * the remotely shared key, and a salt value
     *
     * @param senderKey     Locally generated key
     * @param sub           Subscription information object
     * @param salt          A random "salt" value for the encrypted data
     * @param data          The data to encrypt
     * @param authSecret    Auth Secret provided by the client
     */
    console.debug("calling encrypt(", senderKey, sub, salt, data, ")");
    let headerType;
    let contentType;

    // Note: Promises can make things a bit hard to follow if you're not
    // familiar with how they work. I'm not going to try to duplicate the
    // fine work of articles like
    // http://www.html5rocks.com/en/tutorials/es6/promises/ but suffice
    // to say that the return of each .then() feeds into the next.
    //
    // Import the raw key
    // see: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey

    console.debug("receiverKey:", sub.receiverKey);
    return webCrypto.importKey('raw',
                               sub.receiverKey,
                               P256DH,
                               true,
                               ['deriveBits'])
      .then(receiverKey => {
          // Ok, we've got a representation of the remote key.
          // Now, derive a shared key from our temporary local key
          // and the remote key we just created.
          console.debug("client p256dh key:", receiverKey);
          var args = {name: P256DH.name,
                      namedCurve: P256DH.namedCurve,
                      public: receiverKey}
          console.debug("deriving new key: ", args, senderKey, 256)
          return webCrypto.deriveBits(args,
                                      senderKey.privateKey,
                                      256)
      })
      .then(function(ikm) {
          var kdf;
          var kdfPromise;
          var cEKinfo;
          var cNinfo;

          var authSecret;

          try {
             authSecret = sub.authKey;
             console.debug("Auth Secret:", new Uint8Array(authSecret));
          } catch(e) {
             console.error("No Auth Key: " + e);
             throw e;
          }

          // We now have usable AES key material
          // derived from the remote public key.
          var ikmStr = base64url.encode(new Uint8Array(ikm));
          console.debug("ikm:     ", new Uint8Array(ikm));
          output("ikm", ikmStr)

          if (authSecret) {
            // Build out the second generation encryption base.
            // this uses additional info to add entropy to the
            // hkdf routine.

            // The data that feeds the HKDF uses the following
            // complex data set.
            function makeInfo(type, te, senderKey) {
                let headStr = 'Content-Encoding: ' + type;
                let head = te.encode(headStr);
                let base = concatArray([
                    te.encode("\0P-256\0"),
                    encodeLength(sub.receiverKey),
                    sub.receiverKey,
                    encodeLength(senderKey),
                    senderKey,
                ]);
                console.debug('makeInfo head:', headStr);
                console.debug('makeInfo base:', new Uint8Array(base));
                return concatArray([head, base]);
            }

            // Seed the hkdf with the auth token and the key material
            let authKdf = new hkdf(authSecret, ikm);
            kdfPromise = authKdf.extract(AUTH_INFO, 32)
                .then(ikm2 => webCrypto.exportKey('raw', senderKey.publicKey)
                     .then (senderKey => {
                          // This is the gauntlet of values we're generating
                          // in order to encrypt the data.
                          // These should match on the reciever side.
                          console.debug("salt: ", new Uint8Array(salt));
                          console.debug("ikm2: ", new Uint8Array(ikm2));
                          console.debug("receiverKey: ",
                              new Uint8Array(sub.receiverKey));
                          console.debug("senderKey:   ",
                              new Uint8Array(senderKey));
                          let te = new TextEncoder('utf-8');
                          cEKinfo = makeInfo('aesgcm', te, senderKey);
                          console.debug("cEKinfo: ",
                              new TextDecoder('utf-8').decode(cEKinfo));
                          console.debug("cEKinfo: ", cEKinfo);
                          cNinfo = makeInfo('nonce', te, senderKey);
                          console.debug("cNinfo: ",
                              new TextDecoder('utf-8').decode(cNinfo));
                          console.debug("cNinfo: ", cNinfo);
                          return new hkdf(salt, ikm2)
                     })
                )
                .catch(err => {
                    console.error(err);
                    throw err;
                });
            headerType = "crypto-key";
            contentType = "aesgcm";
          } else {
              // Use the older, out of spec format
              kdfPromise = Promise.resolve(new hkdf(salt, ikm));
              cEKinfo = concatArray([ENCRYPT_INFO, new Uint8Array(0)]);
              cNinfo = concatArray([NONCE_INFO, new Uint8Array(0)]);
              headerType = "encryption-key";
              contentType = "aesgcm128";
          }

          // Use hkdf to generate both the encryption array and the nonce.
          // See hkdf() in base64.js
          // var kdf = new hkdf(salt, ikm);
          // Generate the encryptingData, the base object that contains the
          // key and nonce we'll use to actually encrypt the text to be
          // sent.
          return Promise.allMap({
            // The key is generated from a known pattern that's fed to
            // the hkdf that's been initialized off of the salt and the
            // ikm derived from the public half of the ECDH key
            // from the browser (the p256dh key)
            key: kdfPromise
              .then(kdf => {
                  return kdf.extract(cEKinfo, 16)
              })
              .then(gcmBits => {
                  console.debug("gcmBits: ",new Uint8Array(gcmBits));
                  output('gcmB', base64url.encode(new Uint8Array(gcmBits)));
                  //let key = mzcc.rawToJWK(gcmBits, ['encrypt']);
                  return webCrypto.importKey(
                    'raw',
                    gcmBits,           // the key data
                    'AES-GCM',      // The type of key to generate
                    true,
                    ['encrypt'])    // Use this key for encryption
              }),
              // Now, create the Nonce, from the known nonce info.
            nonce: kdfPromise
              .then(kdf => {
                  return kdf.extract(cNinfo, 12);
              })
              .then(nonceBits => {
                  console.debug("nonce: ", new Uint8Array(nonceBits));
                  output('nonce', base64url.encode(new Uint8Array(nonceBits)));
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
                   // Padding is a 16Bit Big Endian length + the number
                   // of 8 bit 0 padding characters.
                   // let padSize = 4096 - data.length;
                   let padSize = 0;
                   let padded = concatArray([
                       new Uint16Array([be16(padSize)]),
                       //new Uint8Array(padSize),
                       slice,
                  ]);
                  // Generate the Initialization Vector (iv) for this block
                  // based on the previously generated nonce and the offset
                  // of the block.
                   var iv = generateNonce(encryptingData.nonce, index);
                   output("iv", base64url.encode(iv));
                   console.debug("iv: ", new Uint8Array(iv));
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
        data = concatArray(data);
        return {data: data, header: headerType, type: contentType};
    })
    .catch(err => {
        console.error(err);
        throw err;
        });
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

    if (salt == null) {
        console.info("Making new salt");
        salt = newSalt();
        output('salt', salt);
    }
    return webCrypto.generateKey(
            P256DH,
            true,          // false for production
            ['deriveBits'])
      .then(senderKey => {
        // Display the local key parts.
        // WebCrypto only allows you to export private keys as jwk.
        webCrypto.exportKey('jwk', senderKey.publicKey)
            .then(key=>{
                //output('senderKeyPub', base64url.encode(key))
                output('senderKey', mzcc.JWKToRaw(key));
                output('senderKeyPub', JSON.stringify(key));
            })
            .catch(x => console.error(x));
        // Dump the local private key
        webCrypto.exportKey('jwk', senderKey.privateKey)
            .then(key=> {
                console.debug("Private Key:", key)
                output('senderKeyPri', JSON.stringify(key))
            })
            .catch(x => {console.error(x);
                         output('senderKeyPri', "Could not display key: " + x);
            });
        console.debug("Sender Key", senderKey);
        // encode all the data as chunks
        return Promise.allMap({
          payload: encrypt(senderKey,
                           subscription,
                           data,
                           salt),
          pubkey: webCrypto.exportKey('jwk', senderKey.publicKey)
        });
      })
      .then(results => {
          let options = {}
          let headers = new Headers();
          let rawPub = mzcc.JWKToRaw(results.pubkey);
          headers.append(results.payload.header,
                'keyid=p256dh;dh=' + rawPub);
          headers.append('encryption',
                'keyid=p256dh;salt=' + base64url.encode(salt));
          headers.append('content-encoding', results.payload.type)
          headers.append('ttl', 60)
          options.encr_header = results.payload.header;
          options.content_type = results.payload.type;
          options.salt = salt;
          options.dh = rawPub;
          options.endpoint = subscription.endpoint;
          // include the headers here because sometimes you can't extract
          // them from a used Headers object.
          options.headers = headers;
          options.payload = results.payload.data;
          options.method = 'POST';
          return options;
      })
      .catch(err =>{
            console.error("Unknown error:", err);
            throw err;
       });
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
