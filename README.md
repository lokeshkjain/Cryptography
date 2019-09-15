# How to encrypt and decrypt data in nodejs 

## Installation

This is nodejs module which is using crypto module of nodejs.

```sh
$ npm install lkj-cryptography-js
```

## Usage

```sh
const crypto = require('lkj-cryptography-js')

let password = "setyourpasswordhere"

let AES_Crypto = cryptography.AES_Crypto
let encrypted_data = AES_Crypto.encryptData(password,'aes-128-cbc',"give your text here for encrypt tha data")
console.log('encrypted data ',encrypted_data)

let decrypted_data = AES_Crypto.decryptData(password,'aes-128-cbc',encrypted_data)
console.log('decrypted data ',decrypted_data)


```

As shown in above code we have to use password to encrypt/decrypt text. We also have give block cipher to encrypt/decrypt text. currently this library supports 25 cipher and all are AES.  There are another cipher and algorithm are planned for future release. You can get supported ciphers as below code

```sh
let available_ciphers = AES_Crypto.availableAesCiphers()
console.log('available ciphers',available_ciphers)

```

