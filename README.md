# encrypted-docstore
create and mount encrypted [orbit-db](https://github.com/orbitdb/orbit-db/) docstores

**DISCLAIMER: cryptography in this repo has been implemented by an amateur and has not been auditted. <br/>Please :fire:roast:fire: me in Issues if u find a vulnerability.**

NOTE: *should* work in node but haven't tested at all 

## Usage
install with npm:
```
npm install @tabcat/encrypted-docstore
```
create orbitdb instance: https://github.com/orbitdb/orbit-db/blob/master/README.md#usage

create encrypted docstore:
```javascript
const EncryptedDocstore = require('@tabcat/encrypted-docstore')

// create the encryption key
const secret = new TextEncoder().encode('something at least kind of random here') 
const salt = await window.crypto.getRandomValues(new Uint8Array(16)) // 128bit salt
const key = EncryptedDocstore.deriveKey(secret, salt)

// create the docstore with orbit.create:
const dbConfig = { name:'asdf', type:'docstore' }
const encDbName = await EncryptedDocstore.determineEncDbName(orbit, dbConfig, key)
const docstore = await open.create(encDbname, dbConfig.type, dbConfig.options)
const encDocstore = await EncryptedDocstore.mount(docstore, key)

// OR

// create the docstore with orbit.docs:
const encDbAddress = await EncryptedDocstore.determineEncDbAddress(orbit, dbConfig, key)
const docstore = await orbit.docs(encDbAddress)
const encDocstore = await EncryptedDocstore.mount(docstore, key)

// get,put, del, query all exposed on encDocstore and returned results should be identical to docstore methods

```

## API <br/>
>EncDoc = EncryptedDocstore 

### Static Methods:
#### EncDoc.mount(docstore, key)
>mount an encrypted docstore

*docstore:* orbit docstore made with name from EncDoc.determineEncDbName or address from EncDoc.determineEncDbAddress<br/>
*key:* instance of key from src/key.js, made with EncDoc.

returns a promise that resolves to an instance of EncDoc
#### EncDoc.determineEncDbName(orbit, dbConfig, key)
>determine the EncDoc name for a docstore config and key

*orbit:* an instance of OrbitDB<br/>
*dbConfig:* an object containing name, type and options for an orbit store settings<br/>
*key:* instance of Key from src/key.js, made with EncDoc.deriveKey or EncDoc.importKey<br/>

returns a promise that resolves to a string made of:<br/> 
`<encrypted original config address root>/<original config address root>` both fields are base58 encoded
#### EncDoc.determineEncDbAddress(orbit, dbConfig, key)
>determine the EncDoc address for a docstore config and key

*orbit:* an instance of OrbitDB<br/>
*dbConfig:* an object containing name, type and options for an orbit store settings<br/>
*key:* instance of Key from src/key.js, made with EncDoc.deriveKey or EncDoc.importKey<br/>

returns a promise that resolves to an instance of orbit address
#### EncDoc.keyCheck(address, key)
>check if a key is used for this db address 

*address:* instance of orbit address<br/>
*key:* instance of Key from src/key.js, made with EncDoc.deriveKey or EncDoc.importKey<br/>

returns promise that resolves to a boolean
#### EncDoc.deriveKey(bytes, salt, [length, [purpose]])
>derive instance of Key from bytes and salt

*bytes:* bytes array made from randomness or a strong password<br/>
*salt:* bytes array to be used as salt for deriving the key, recommend using 128bit random value<br/>
*length:* number representing cipherblock size, defaults to 128<br/>
*purpose:* string that is used in generating the key somehow<br/>

returns an instance of Key
#### EncDoc.importKey(rawKey)
>import a key from raw bytes from EncDoc.exportKey

*rawKey:* bytes array from EncDoc.exportKey

returns an instance of Key
#### EncDoc.exportKey(key)
>export a key

*key:* instance of Key

returns a bytes array that can be used as rawKey in EncDoc.importKey

### Instance Propterties:
#### encDoc.encrypted
> the orbit docstore being used as the encrypted docstore
#### encDoc.key
> an instance of the Key class from src/key.js

### Instance Methods:
  - get, put, del, query all work by encapsulating the field it is indexed by (default is \_id) and should behave the same
#### encDoc.get(key)
see: https://github.com/orbitdb/orbit-db/blob/master/API.md#getkey-1

differences:
  - is async function
#### encDoc.put(doc)
>see: https://github.com/orbitdb/orbit-db/blob/master/API.md#putdoc

no visible differences
#### encDoc.del(key)
>see: https://github.com/orbitdb/orbit-db/blob/master/API.md#delkey-1

no visible differences
#### encDoc.query(mapper)
>see: https://github.com/orbitdb/orbit-db/blob/master/API.md#querymapper

differences:
  - is async function
  - when calling with option fullOp: 
    + the payload.value is the decrypted/decapsulated doc. 
    + the payload.key which would usually match the payload.value[indexBy] field (indexBy default is '\_id')
    does not.
    + anything in the fullOp entry relating to hashing the real payload.value will not match the payload.value
  - when not calling with option fullOp:
    + no visible differences
