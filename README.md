# encrypted-docstore
create and mount encrypted [orbit-db](https://github.com/orbitdb/orbit-db/) docstores

**DISCLAIMER: cryptography in this repo has been implemented by an amateur and has not been auditted. <br/>Please :fire:roast:fire: me in Issues if u find a vulnerability.**

NOTE: version 3.0.0 changes how EncryptedDocstore determines the orbitdb address, this is a breaking change. Some changes have been made to the api as well, mostly naming.

TODO: </br>
extend the docstore instead of wrap it. </br>
make every entry iv deterministic? based off anything unique besides orbit id and clock with the goal of having duplicate entries from different nodes collapse.

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
const aesKey = EncryptedDocstore.generateKey()

// create the docstore with orbitdb:
const dbConfig = { name:'asdf', type:'docstore', options: {} }
const encAddr = await EncryptedDocstore.determineAddress(orbitdb, dbConfig, aesKey)
const docstore = await orbitdb.docs(encAddr, dbConfig.options)
const encDocstore = await EncryptedDocstore.mount(docstore, key)

// get,put, del, query all exposed on encDocstore and returned results should be identical to docstore methods

```

## API <br/>
>EncDoc = EncryptedDocstore 

### Static Methods:
#### EncDoc.mount(docstore, aesKey)
>mount an encrypted docstore

*docstore:* orbit docstore made with name from EncDoc.determineEncDbName or address from EncDoc.determineEncDbAddress<br/>
*aesKey:* instance of AesKey from generateKey, deriveKey, or importKey static methods.

returns a promise that resolves to an instance of EncDoc
#### EncDoc.determineAddress(orbitdb, dbConfig, aesKey)
>determine the docstore address for the encryptedDocstore, this is adding a way to check the aesKey against the db name

*orbitdb:* an instance of OrbitDB<br/>
*dbConfig:* an object containing name, type and options for an orbit store settings<br/>
*aesKey:* instance of AesKey from generateKey, deriveKey, or importKey static methods.<br/>

returns a promise that resolves to an instance of orbit address
#### EncDoc.keyCheck(encAddr, aesKey)
>check if an orbitdb address and aesKey are a match

*encAddr:* instance of orbit address from EncDoc.determineAddress<br/>
*aesKey:* instance of AesKey from generateKey, deriveKey, or importKey static methods.<br/>

returns a promise that resolves to a boolean
#### EncDoc.generateKey([length])
>generates a new aesKey

*length:* number, aesKey length, defaults to 128. can be  128, 192, or 256<br/>

returns an instance of AesKey
#### EncDoc.deriveKey(bytes, salt[, length])
>derive an instance of AesKey from bytes and salt, uses PBKDF2 with 10k iterations

*bytes:* Uint8Array made from randomness or a strong password<br/>
*salt:* Uint8Array to be used as salt for deriving the key, optimally a 128bit random value<br/>
*length:* number, aesKey length, defaults to 128. can be  128, 192, or 256<br/>

returns an instance of AesKey
#### EncDoc.importKey(rawKey)
>import an exported aesKey

*rawKey:* Uint8Array from EncDoc.exportKey

returns an instance of AesKey
#### EncDoc.exportKey(aesKey)
>export an aesKey

*aesKey:* instance of AesKey

returns a Uint8Array rawKey

### Instance Methods:
  - get, put, del, query all work by encapsulating the whole doc and pass docstore tests for the orbitdb repo: https://github.com/orbitdb/orbit-db/blob/master/test/docstore.test.js
#### encDoc.get(key)
see: https://github.com/orbitdb/orbit-db/blob/master/API.md#getkey-1

differences:
  - is an async function
#### encDoc.put(doc)
>see: https://github.com/orbitdb/orbit-db/blob/master/API.md#putdoc

no visible differences
#### encDoc.del(key)
>see: https://github.com/orbitdb/orbit-db/blob/master/API.md#delkey-1

no visible differences
#### encDoc.query(mapper)
>see: https://github.com/orbitdb/orbit-db/blob/master/API.md#querymapper

differences:
  - is an async function
  - when calling with option fullOp: 
    + the payload.value is the decrypted/decapsulated doc.
    + anything in the fullOp entry relating to hashing the real payload.value will not match the payload.value
  - when not calling with option fullOp:
    + no visible differences
