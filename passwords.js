'use strict';

function PASSWORDS() {

  let passwords = {};

  passwords.hash = async (password, iterations) => {
    let time = Date.now();
    let pass = new TextEncoder().encode(password);
    let salt = crypto.getRandomValues(new Uint8Array(32));
    let key = await crypto.subtle.importKey('raw', pass, "PBKDF2", false, ['deriveBits'])

    let result = await crypto.subtle.deriveBits({
      "name": "PBKDF2",
      "salt": salt,
      "iterations": iterations,
      "hash": "SHA-256"
    }, key, 256);

    let bitsString = btoa(Array.from(new Uint8Array(result)).map(val => {
      return String.fromCharCode(val)
    }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');

    let saltString = btoa(Array.from(new Uint8Array(salt)).map(val => {
      return String.fromCharCode(val)
    }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');

    let hash = iterations + '.' + saltString + '.' + bitsString;

    return hash;

  };

  passwords.compare = async (hash, password) => {

    let parts = hash.split('.');
    let iterations = parts[0];
    let salt = new Uint8Array(atob(parts[1].replace(/\-/g, '+').replace(/\_/g, '/')).split('').map(val => {
      return val.charCodeAt(0);
    }));

    let pass = new TextEncoder().encode(password);
    let key = await crypto.subtle.importKey('raw', pass, {
      "name": "PBKDF2"
    }, false, ['deriveBits']);

    let bitBuffer = await crypto.subtle.deriveBits({
      "name": "PBKDF2",
      "salt": salt,
      "iterations": iterations,
      "hash": "SHA-256"
    }, key, 256);

    let bitsString = btoa(Array.from(new Uint8Array(bitBuffer)).map(val => {
      return String.fromCharCode(val)
    }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');

    let result = parts[2] === bitsString;

    return result;

  };

  return passwords;

}
