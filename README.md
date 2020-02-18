
# ephemeral-keys

## Example - bob sends a message to alice

```js
const Ephemeral = require('.')
const contextMessage = 'alice and bob' // this is included in the shared secret

const alice = Ephemeral({ dir: './alice-keys' })
const bob = Ephemeral({ dir: './bob-keys' })

// alice does this:
const dbKey = 'message from bob'

alice.generateAndStore(dbKey, (err, pk) => {
  // she sends the public key, pk, in a request to bob

  // bob does this using the public key from alice:
  const message = 'its nice to be important but its more important to be nice'
  bob.boxMessage(message, pk, contextMessage, (err, boxedMsg) => {

    // he sends the encrypted message, boxedMsg, to alice

    // alice decrypts the message like this:
    alice.unBoxMessage(dbKey, boxedMsg, contextMessage, (err, msg) => {

      // after reading the message, msg, she deletes it's keypair and it is gone forever...    
      alice.deleteKeyPair(dbKey, (err) => {
      })
    })
  })
})
```

Note that both alice and bob must use the same context message.

## API

`const EphemeralKeys = require('.')`

`const ephemeralKeys = EphemeralKeys(options)`

Create an instance of `EphemeralKeys`. `options` is an optional object which may contain properties:

- `dir` - the base directory where keys should be stored
- `cipherTextSuffix` - a buffer which will be suffixed to encrypted messages so that they can be identified as being encrypted


### `generateAndStore(databaseKey, callback)`

This function will generate a keypair, store the secret key
on disk, indexed by the given database key and return
the public key to be included in a request in the callback.

- `databaseKey` may be a string or an object
- callback returns a buffer

### `boxMessage(message, recipientPublicKey, contextMessage, callback)` 

This function will generate a keypair, encrypt a given shard to
a given ephemeral public key, delete the generated private key, 
and return the encrypted message in the callback.
 
The context message is a string or buffer which is added to the shared
secret so that it may only be used for a specific purpose.

### `unBoxMessage(databaseKey, encryptedMessage, contextMessage, callback)`

This function will grab a stored secret key from disk using the
given database key, use it to decrypt a given message and return the
result in the callback.

The context message is a string or buffer which is added to the shared
secret so that it may only be used for a specific purpose.

`databaseKey` may be a string or an object

### `deleteKeyPair(databaseKey, callback)`

This function will delete a keyPair identified by the given database key

`databaseKey` may be a string or an object

### `isBoxedMessage(message)`