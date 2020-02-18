const { describe } = require('tape-plus')
const tmpdir = require('tmp').dirSync
const Eph = require('..')

describe('Ephemeral Keys', context => {
  let eph, message, dbKey, contextMessage

  context.beforeEach(c => {
    eph = Eph({ dir: tmpdir().name })
    message = Buffer.from('its nice to be important but its more important to be nice')
    dbKey = 'someKey'
    contextMessage = Buffer.from('test')
  })

  context('Encrypts and decrypts successfully', (assert, next) => {
    eph.generateAndStore(dbKey, (err, pk) => {
      assert.error(err, 'error from generating and storing keys is null')
      assert.true(Buffer.isBuffer(pk), 'returns public key')
      eph.boxMessage(message, pk, contextMessage, (err, boxedMsg) => {
        assert.error(err, 'No error from boxMessage')
        eph.unBoxMessage(dbKey, boxedMsg, contextMessage, (err, msg) => {
          assert.error(err, 'No error from unbox')
          assert.equal(message.toString('hex'), msg.toString('hex'), 'output is the same as input')
          eph.deleteKeyPair(dbKey, (err) => {
            assert.error(err, 'No error from delete Keypair')
            eph.unBoxMessage(dbKey, boxedMsg, contextMessage, (err, msg) => {
              assert.ok(err, 'fails to unencrypt message after deleting keys')
              assert.notOk(msg, 'returns no keys')
              next()
            })
          })
        })
      })
    })
  })

  context('Encrypts and decrypts successfully with object as dbKey', (assert, next) => {
    dbKey = { foo: 'bar', baz: 5 }
    eph.generateAndStore(dbKey, (err, pk) => {
      assert.error(err, 'error from generating and storing keys is null')
      assert.true(Buffer.isBuffer(pk), 'returns public key')
      eph.boxMessage(message, pk, contextMessage, (err, boxedMsg) => {
        assert.error(err, 'No error from boxMessage')
        eph.unBoxMessage(dbKey, boxedMsg, contextMessage, (err, msg) => {
          assert.error(err, 'No error from unbox')
          assert.equal(message.toString('hex'), msg.toString('hex'), 'output is the same as input')
          eph.deleteKeyPair(dbKey, (err) => {
            assert.error(err, 'No error from delete Keypair')
            eph.unBoxMessage(dbKey, boxedMsg, contextMessage, (err, msg) => {
              assert.ok(err, 'fails to unencrypt message after deleting keys')
              assert.notOk(msg, 'returns no keys')
              next()
            })
          })
        })
      })
    })
  })

  context('Returns an error when given the wrong message to decrypt', (assert, next) => {
    eph.generateAndStore(dbKey, (err, pk) => {
      if (err) console.error(err)
      eph.boxMessage(message, pk, contextMessage, (err, boxedMsg) => {
        assert.notOk(err, 'error from boxMessage is null')
        const change = Buffer.from('something')
        boxedMsg = Buffer.concat([change, boxedMsg.slice(change.length)])
        eph.unBoxMessage(dbKey, boxedMsg, contextMessage, (err, msg) => {
          assert.ok(err, 'throws error')
          assert.notOk(msg, 'message is null')
          next()
        })
      })
    })
  })

  context('Returns an error when ciphertext has incorrect suffix', (assert, next) => {
    eph.generateAndStore(dbKey, (err, pk) => {
      if (err) console.error(err)
      eph.boxMessage(message, pk, contextMessage, (err, boxedMsg) => {
        assert.notOk(err, 'error from boxMessage is null')
        boxedMsg = Buffer.concat([boxedMsg, Buffer.from('wrong')])
        eph.unBoxMessage(dbKey, boxedMsg, contextMessage, (err, msg) => {
          assert.ok(err, 'throws error')
          assert.notOk(msg, 'message is null')
          next()
        })
      })
    })
  })

  context('Throws an error when given an incorrect db key', (assert, next) => {
    eph.generateAndStore(dbKey, (err, pk) => {
      assert.notOk(err, 'error from generating and storing keys is null')
      eph.boxMessage(message, pk, contextMessage, (err, boxedMsg) => {
        assert.notOk(err, 'error from boxMessage is null')
        eph.unBoxMessage('something else', boxedMsg, contextMessage, (err, msg) => {
          assert.ok(err, 'throws error')
          assert.notOk(msg, 'msg is null')
          next()
        })
      })
    })
  })
  //
  // context('Throws error on encountering unsupported key type')
})
