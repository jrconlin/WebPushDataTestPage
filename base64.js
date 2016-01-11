/* This file contains a few core utilities and polyfills.
 */
'use strict';

// Write to the various div containers.
function output(target, value) {
    var t =  document.getElementById(target).getElementsByClassName("value")[0];
    if (t.attributes.hasOwnProperty('value')) {
        t.value = value;
    } else {
        t.innerHTML = value;
    }
}

// Split a byte array into chunks of size.
function chunkArray(array, size) {
    var start = array.byteOffset || 0;
    array = array.buffer || array;
    var index = 0;
    var result = [];
    while(index + size <= array.byteLength) {
      result.push(new Uint8Array(array, start + index, size));
      index += size;
    }
    if (index <= array.byteLength) {
      result.push(new Uint8Array(array, start + index));
    }
    return result;
}

/* I can't believe that this is needed here, in this day and age ...
* Note: these are not efficient, merely expedient.
*/
var base64url = {
    _strmap: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg' +
             'hijklmnopqrstuvwxyz0123456789-_',
    encode: function(data) {
      //  console.debug('Encoding:', data);
      data = new Uint8Array(data);
      var len = Math.ceil(data.length * 4 / 3);
      return chunkArray(data, 3).map(chunk => [
        chunk[0] >>> 2,
        ((chunk[0] & 0x3) << 4) | (chunk[1] >>> 4),
        ((chunk[1] & 0xf) << 2) | (chunk[2] >>> 6),
        chunk[2] & 0x3f
      ].map(v => base64url._strmap[v]).join('')).join('').slice(0, len);
    },
    _lookup: function(s, i) {
      return base64url._strmap.indexOf(s.charAt(i));
    },
    decode: function(str) {
      var v = new Uint8Array(Math.floor(str.length * 3 / 4));
      var vi = 0;
      for (var si = 0; si < str.length;) {
        var w = base64url._lookup(str, si++);
        var x = base64url._lookup(str, si++);
        var y = base64url._lookup(str, si++);
        var z = base64url._lookup(str, si++);
        v[vi++] = w << 2 | x >>> 4;
        v[vi++] = x << 4 | y >>> 2;
        v[vi++] = y << 6 | z;
      }
      return v;
    }
  };

// Hash-Based Message Authentication Code
// This generates a secure hash based on the key.
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
};
hmac.prototype.hash = function(input) {
    var val = this.keyPromise.then(k => webCrypto.sign('HMAC', k, input));
    return val;
};


// HMAC (Hash-Based Message Authentication Code)-Based extract & expand Key
// Derivation Function. (Yeah, that's why everyone calls it "hkdf")
function hkdf(salt, ikm) {
    this.prkhPromise = new hmac(salt).hash(ikm)
      .then(prk => new hmac(prk));
};
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
        return reply;
      });
};

function bsConcat(arrays) {
    // Concatenate the byte arrays into a single Uint8Array.
    var size = arrays.reduce((total, a) => total + a.byteLength, 0);
    var index = 0;
    return arrays.reduce((result, a) => {
        result.set(new Uint8Array(a), index);
        index += a.byteLength;
        return result;
    }, new Uint8Array(size));
}


window.base64url = base64url;
