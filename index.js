const fs = require('fs')
const assert = require('assert')
const skrub = require('skrub')
const protobuf = require('protocol-buffers')
const path = require('path')
const mkdirp = require('mkdirp').sync
const s = require('key-backup-crypto')
const crypto = require('./crypto')

const messages = protobuf(`
message Keypair {
  required bytes publicKey = 1;
  required bytes secretKey = 2;
}
`)

module.exports = (options) => new EphemeralKeys(options)

class EphemeralKeys {
  constructor (options = {}) {
    this.dir = options.dir || '.'
    if (this.dir !== '.') mkdirp(this.dir)
    this.cipherTextSuffix = options.cipherTextSuffix || Buffer.from('ephemeral')
  }

  generateAndStore (dbKey, callback) {
    const ephKeypair = crypto.keypair()
    const ephKeypairEncoded = messages.Keypair.encode(ephKeypair)
    // TODO: check that there does not already exist a keypair with this key
    assert(dbKey, 'A database key must be given')
    fs.writeFile(this._buildFileName(dbKey), ephKeypairEncoded, (err) => {
      if (err) return callback(err)
      callback(null, ephKeypair.publicKey)
    })
  }

  boxMessage (message, publicKey, contextMessage) {
    assert(Buffer.isBuffer(message), 'Message must be a buffer')
    if (typeof publicKey === 'string') publicKey = Buffer.from(publicKey, 'hex')

    if (typeof contextMessage === 'object') contextMessage = JSON.stringify(contextMessage)
    if (typeof contextMessage === 'string') contextMessage = Buffer.from(contextMessage)

    return Buffer.concat([crypto.box(publicKey, message, contextMessage), this.cipherTextSuffix])
  }

  unBoxMessage (dbKey, cipherText, contextMessage, callback) {
    assert(Buffer.isBuffer(cipherText), 'Ciphertext must be a buffer')
    if (typeof contextMessage === 'object') contextMessage = JSON.stringify(contextMessage)
    if (typeof contextMessage === 'string') contextMessage = Buffer.from(contextMessage)

    if (cipherText.slice(-1 * this.cipherTextSuffix.length).toString('hex') !== this.cipherTextSuffix.toString('hex')) {
      return callback(new Error('Ciphertext must end in ' + this.cipherTextSuffix.toString()))
    }
    cipherText = cipherText.slice(0, -1 * this.cipherTextSuffix.length)

    assert(dbKey, 'A database key must be given')
    fs.readFile(this._buildFileName(dbKey), (err, data) => {
      if (err) return callback(err)
      let ephKeypair
      try {
        ephKeypair = messages.Keypair.decode(data)
      } catch (err) {
        return callback(err)
      }
      const plainText = crypto.unbox(cipherText, ephKeypair, contextMessage)
      if (!plainText) {
        callback(new Error('Decryption failed'))
      } else {
        callback(null, plainText)
      }
    })
  }

  deleteKeyPair (dbKey, callback) {
    assert(dbKey, 'A database key must be given')
    skrub([this._buildFileName(dbKey)], { dryRun: false }).then(
      paths => { callback() },
      err => callback(err)
    )
  }

  isBoxedMessage (buf) {
    if (buf.length < this.cipherTextSuffix.length) return false
    return (buf.slice(-1 * this.cipherTextSuffix.length) === this.cipherTextSuffix)
  }

  _buildFileName (dbKey) {
    if (typeof dbKey === 'object') {
      dbKey = JSON.stringify(dbKey)
    }
    // to obfuscate the chosen dbKey on disk, the filename is it's hash
    const fileName = s.genericHash(Buffer.from(dbKey)).toString('hex')
    return path.join(this.dir, fileName)
  }
}
