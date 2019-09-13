const crypto = require('crypto')
const util = require('./util')
class AES_Crypto{

  sha1(input) {
    return crypto.createHash('sha1').update(input).digest()
  }

  passwordDeriveBytes(password, salt, iterations, len){
    
    let key = Buffer.from(password + salt)
    for(let i = 0; i < iterations; i++) {
        key = this.sha1(key)
    }
    
    if (key.length < len) {
      let hx = this.passwordDeriveBytes(password, salt, iterations - 1, 20)
      for (let counter = 1; key.length < len; ++counter) {
          key = Buffer.concat([key, this.sha1(Buffer.concat([Buffer.from(counter.toString()), hx]))])
      }
    }
    
    return Buffer.alloc(len, key)
  }

  encryptData(password,cipher_type,text){

    let iv_length = this.getivLength(cipher_type)
    let iv = util.randomString(16)
    let salt = util.randomString(16)
    let key = this.passwordDeriveBytes(password,salt, 100, iv_length)
    let cipher = crypto.createCipheriv(cipher_type, key, Buffer.from(iv))
    let part1 = cipher.update(text, 'utf8')
    let part2 = cipher.final()
    let encrypted = Buffer.concat([part1, part2]).toString('base64')
    return iv+salt+encrypted
  }

  decryptData(password,cipher_type,encrypted_text){
    let iv_length = this.getivLength(cipher_type)
    let iv = encrypted_text.slice(0,16)
    let salt = encrypted_text.slice(16,32)
    let data_length = encrypted_text.length

    encrypted_text = encrypted_text.substr(32,data_length)
    let key = this.passwordDeriveBytes(password,salt, 100, iv_length)
    let decipher = crypto.createDecipheriv(cipher_type, key, Buffer.from(iv))
    let decrypted = decipher.update(encrypted_text, 'base64', 'utf8')
    decrypted += decipher.final()
    return decrypted
  }

  availableAesCiphers(){
    let available_ciphers = [
                              'aes128',
                              'aes-128-cbc',
                              'aes-128-cbc-hmac-sha1',
                              'aes-128-cbc-hmac-sha256',
                              'aes-128-cfb',
                              'aes-128-cfb1',
                              'aes-128-cfb8',
                              'aes-128-ctr',
                              'aes-128-ofb',
                              'aes192',
                              'aes-192-cbc',
                              'aes-192-cfb',
                              'aes-192-cfb1',
                              'aes-192-cfb8',
                              'aes-192-ctr',
                              'aes-192-ofb',
                              'aes256',
                              'aes-256-cbc',
                              'aes-256-cbc-hmac-sha1',
                              'aes-256-cbc-hmac-sha256',
                              'aes-256-cfb',
                              'aes-256-cfb1',
                              'aes-256-cfb8',
                              'aes-256-ctr',
                              'aes-256-ofb'

                            ]

    return available_ciphers
  }

  getivLength(cipher){
    let iv_length = 16
    switch(cipher){
      case 'aes128' :  iv_length = 16
                            break

      case 'aes-128-cbc' :  iv_length = 16
                            break

      case 'aes-128-cbc-hmac-sha1' :  iv_length = 16
                            break

      case 'aes-128-cbc-hmac-sha256' :  iv_length = 16
                            break

      case 'aes-128-cfb' :  iv_length = 16
                            break

      case 'aes-128-cfb1' :  iv_length = 16
                            break

      case 'aes-128-cfb8' :  iv_length = 16
                            break

      case 'aes-128-ctr' :  iv_length = 16
                            break

      case 'aes-128-ofb' :  iv_length = 16
                            break  

      case 'aes192' :  iv_length = 24
                            break

      case 'aes-192-cbc' :  iv_length = 24
                            break 

      case 'aes-192-cfb' :  iv_length = 24
                            break

      case 'aes-192-cfb1' :  iv_length = 24
                            break   

      case 'aes-192-cfb8' :  iv_length = 24
                            break   

      case 'aes-192-ctr' :  iv_length = 24
                            break

      case 'aes-192-ofb' :  iv_length = 24
                            break

      case 'aes256' :  iv_length = 32
                            break

      case 'aes-256-cbc' :  iv_length = 32
                            break  

      case 'aes-256-cbc-hmac-sha1' :  iv_length = 32
                            break 

      case 'aes-256-cbc-hmac-sha256' :  iv_length = 32
                            break 

      case 'aes-256-cfb' :  iv_length = 32
                            break

      case 'aes-256-cfb1' :  iv_length = 32
                            break  

      case 'aes-256-cfb8' :  iv_length = 32
                            break

      case 'aes-256-ctr' :  iv_length = 32
                            break

      case 'aes-256-ofb' :  iv_length = 32
                            break
                                   
    }

    return iv_length
  }

}

module.exports = new AES_Crypto()
