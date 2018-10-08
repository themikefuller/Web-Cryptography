# Web-Cryptography
Web Cryptography Examples using the crypto.subtle API (SubtleCrypto) aka window.crypto.subtle

## Formula for encrypted communication with advanced extraterrestrial lifeforms (Aliens) familar with Elliptic Curve Diffie-Hellman and JavaScript
```javascript

  // The starship will generate an Elliptic Curve Diffie-Hellman keypair
  var starship = await crypto.subtle.generateKey({
      "name": "ECDH",
      "namedCurve": "P-256"
  }, true, ['deriveBits']);

  // The alienship will generate an Elliptic Curve Diffie-Hellman keypair
  var alienship = await crypto.subtle.generateKey({
      "name": "ECDH",
      "namedCurve": "P-256"
  }, true, ['deriveBits']);

  // alienship sends alienship.publicKey to starship
  // starship sends starship.publicKey to alienship
  // TIP: You can paint your public ECDH x and y coordinates on your vessel for all to see.

  // sharedBits - Both ships can now compute the shared bits.
  // The ship's private key is used as the "key", the other ship's public key is used as "public".
  var sharedBits = await crypto.subtle.deriveBits({
      "name": "ECDH",
      "public": alienship.publicKey
  }, starship.privateKey, 256);

  // The first half of the resulting raw bits is used as a salt.
  var sharedDS = sharedBits.slice(0, 16);

  // The second half of the resulting raw bits is imported as a shared derivation key.
  var sharedDK = await crypto.subtle.importKey('raw', sharedBits.slice(16, 32), "PBKDF2", false, ['deriveKey']);

  // A new shared AES-GCM encryption / decryption key is generated using PBKDF2
  // This is computed separately by both parties and the result is always the same.
  var key = await crypto.subtle.deriveKey({
      "name": "PBKDF2",
      "salt": sharedDS,
      "iterations": 100000,
      "hash": "SHA-256"
  }, sharedDK, {
      "name": "AES-GCM",
      "length": 256
  }, true, ['encrypt', 'decrypt']);

  // The raw bits of the actual encryption can be exported and saved in the ship's computer.
  // These bits should be stored encrypted and should reference the specfic ship you are communicating with.
  var exported = await crypto.subtle.exportKey('raw', key);

  // The alienship can construct a message and encode it.
  var message = new TextEncoder().encode('TO SERVE MAN...');

  // A random iv can be generated and used for encryption
  var iv = crypto.getRandomValues(new Uint8Array(12));

  // The iv and the message are used to create an encrypted series of bits.
  var encrypted = await crypto.subtle.encrypt({
      "name": "AES-GCM",
      "iv": iv
  }, key, message);

  // The alienship sends the bits and the iv to the starship

  // The starship decrypts the message using the shared key and publically provided iv.
  var decrypted = await crypto.subtle.decrypt({
      "name": "AES-GCM",
      "iv": iv
  }, key, encrypted);

  // The humans decode the message into human readable text...
  var decoded = new TextDecoder().decode(decrypted);

  // The humans output the message to the console and gasp!
  console.log(decoded);


```


## AES-GCM encryption / decryption with PBKDF2 key derivation

### What does this do?
This function creates a JavaScipt object containing an AES encrypt function and an AES decrypt function built using the browser's built-in Web Crypto library. For security, the encryption key is derived from the password and a random salt using the PBKDF2 algorithm.

#### Encryption

The encrypt function encodes a byteArray from a provided password and imports it as a PBKDF2 cryptoKey. Optionally, the password can be left null and a byteArray can be provided as the passwordBits. The imported cryptoKey is used with a randomly generated salt in a PBKDF2 function to derive new bits. If an iterations value is not provided, a default value of 500000 is used. The resulting bits (resulting byteArray) is imported as an AES-256 cryptoKey. The cryptoKey is used with a randomly generated initialization vector (iv) to encrypt the provided message (string data).

The value returned from this function is a string of the these concatenated values separated by periods:
 - the iterations value converted to a string and then base64 encoded
 - the salt converted from a byteArray to a base64 encoded string
 - the iv converted from a byteArray to a base64 encoded string
 - the encrypted message converted from a byteArray to a base64 encoded string

#### Decryption

The decrypt function follows essentially the same process as the encrypt function in reverse. The encrypted data, encoded as a string from the encrypt function, is provided with the password (or passwordBits) used for encryption. The encoded values are split, decoded and then used to derive the encryption key. The encryption key is then used to decrypt the data.

The value returned from this function is a string of the original message (string data).

### The Function
```javascript

function AES() {

  let aes = {};

  aes.encrypt = async (message, password, passwordBits, iterations) => {
  
    let rounds = iterations || 500000;
    let msg = new TextEncoder().encode(message);
    let pass;
    
    if (password) {
      pass = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), {
        "name": "PBKDF2"
      }, false, ['deriveBits']);
    }
    
    if (passwordBits) {
      pass = await crypto.subtle.importKey('raw',new Uint8Array(passwordBits),{
        "name": "PBKDF2"
      },false,['deriveBits'])
    }
    
    let salt = crypto.getRandomValues(new Uint8Array(32));
    let iv = crypto.getRandomValues(new Uint8Array(12));
    
    let bits = await crypto.subtle.deriveBits({
      "name": "PBKDF2",
      "salt": salt,
      "iterations": rounds,
      "hash": {
        "name": "SHA-256"
      }
    }, pass, 256);
    
    let key = await crypto.subtle.importKey('raw', bits, {
      "name": "AES-GCM"
    }, false, ['encrypt']);
    
    let enc = await crypto.subtle.encrypt({
      "name": "AES-GCM",
      "iv": iv
    }, key, msg);
    
    let iterationsHash = btoa(rounds.toString());
    
    let saltHash = btoa(Array.from(new Uint8Array(salt)).map(val => {
      return String.fromCharCode(val)
    }).join(''));
    
    let ivHash = btoa(Array.from(new Uint8Array(iv)).map(val => {
      return String.fromCharCode(val)
    }).join(''));
    
    let encHash = btoa(Array.from(new Uint8Array(enc)).map(val => {
      return String.fromCharCode(val)
    }).join(''));
    
    return iterationsHash + '.' + saltHash + '.' + ivHash + '.' + encHash;
    
  };

  aes.decrypt = async (encrypted, password, passwordBits) => {
  
    let parts = encrypted.split('.');
    let rounds = parseInt(atob(parts[0]));
    
    let salt = new Uint8Array(atob(parts[1]).split('').map(val => {
      return val.charCodeAt(0);
    }));
    
    let iv = new Uint8Array(atob(parts[2]).split('').map(val => {
      return val.charCodeAt(0);
    }));
    
    let enc = new Uint8Array(atob(parts[3]).split('').map(val => {
      return val.charCodeAt(0);
    }));
    
    let pass;
    
    if (password) {
      pass = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), {
        "name": "PBKDF2"
      }, false, ['deriveBits']);
    }
    
    if (passwordBits) {
      pass = await crypto.subtle.importKey('raw', new Uint8Array(passwordBits), {
        "name": "PBKDF2"
      }, false, ['deriveBits']);
    }
    
    let bits = await crypto.subtle.deriveBits({
      "name": "PBKDF2",
      "salt": salt,
      "iterations": rounds,
      "hash": {
        "name": "SHA-256"
      }
    }, pass, 256);
    
    let key = await crypto.subtle.importKey('raw', bits, {
      "name": "AES-GCM"
    }, false, ['decrypt']);
    
    let dec = await crypto.subtle.decrypt({
      "name": "AES-GCM",
      "iv": iv
    }, key, enc);
    
    return (new TextDecoder().decode(dec));
    
  };

  return aes;

}

```

### Examples


#### Encrypt / Decrypt with a password
```javascript

    let message = "Hello world";
    let password = "password";

    let encrypted = await AES().encrypt(message,password);
    let decrypted = await AES().decrypt(encrypted,password);
 
    console.log(encrypted);
    console.log(decrypted);
    
    // "MTAwMDAw./Q0Kbaebl4eaTB9YiQLTH64s9g6N3R84zkohvq6S3Ao=.uOA4INOHbqmlVGRi.03GJ+KxFEEYV5jSkPmCByZf5mqjr8y8SzvJC"
    // "hello world"

```


#### Encrypt / Decrypt with a byteArray derived elsewhere
```javascript

    let message = "Hello world";
    let passwordBits = crypto.getRandomValues(new Uint8Array(32));

    let encrypted = await AES().encrypt(message,null,passwordBits);
    let decrypted = await AES().decrypt(encrypted,null,passwordBits);
    
    console.log(encrypted);
    console.log(decrypted);
    
    // "NTAwMDAw.zAySc5+w1eziSEWkYehc7D/OSE/YTiI3Lvq07axvZgQ=.D3amG1ThKfxTI8ss.zKoyTs4pYgqnpE879Nus9l24foFTk0yaoOjh"
    // "hello world"
    
```

## Additional Examples
More to come...
