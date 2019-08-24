
'use strict'
const bs58 = require('bs58')
const Buffer = require('safe-buffer').Buffer
const Key = require('./key')

class EncryptedDocstore {
  constructor(encryptedDocstore, key) {
    if (!isDefined(encryptedDocstore)) throw new Error('encryptedDocstore must be defined')
    if (!isDefined(key)) throw new Error('key must be defined')
    this._docstore = encryptedDocstore
    this.indexBy = this.docstore.options.indexBy
    this._key = key
  }

  // docstore: an instance of orbitdb docstore with name from determineEncDbName
  //  (get this by opening a docstore by address or creating one with a config)
  // key: aes cryptoKey (get this from this.deriveKey)
  static async mount(docstore, key) {
    if (key === undefined || docstore === undefined) {
      throw new Error('key and encryptedDocstore must be defined')
    }
    // if keyCheck fails throw
    if (!(await this.keyCheck(docstore.address, key))) {
      throw new Error('keyCheck failed while trying to mount store')
    }
    return new EncryptedDocstore(docstore, key)
  }

  // use to get name of encDocstore for creating the docstore
  static async determineEncDbName(orbitdb, dbConfig, key) {
    if (orbitdb === undefined || dbConfig === undefined || key === undefined) {
      throw new Error('orbitdb, dbConfig and key must be defined')
    }
    const { name, type, options } = dbConfig
    const root = (await orbitdb.determineAddress(name, type, options)).root
    const decodedRoot = bs58.decode(root)
    const encRoot = bs58.encode(
      Buffer.from(
        (await key.encrypt(decodedRoot, decodedRoot)).cipherbytes
      )
    )

    return `${encRoot}/${root}`
  }

  // use to determine address of encDocstore
  static async determineEncDbAddress(orbitdb, dbConfig, key) {
    if (orbitdb === undefined || dbConfig === undefined || key === undefined) {
      throw new Error('orbitdb, dbConfig and key must be defined')
    }
    if (dbConfig.type !== 'docstore') {
      throw new Error('dbConfig type must be docstore')
    }
    const encDbName = await this.determineEncDbName(orbitdb, dbConfig, key)
    return await orbitdb.determineAddress(encDbName, dbConfig.type, dbConfig.options)
  }

  static async keyCheck(address, key) {
    if (address === undefined || key === undefined) {
      throw new Error('address and key must be defined')
    }
    const [ encRoot, root ] = address.path.split('/')
    const decodedEncRoot = bs58.decode(encRoot)
    // d for deterministic
    // probably the weakest part of the encryptedDocstore to precomputed tables.
    // weakness is related to there being basically no salt so attacker needs
    //  a table with an entry of every encrypted original root from encrypting every
    //  every likely original root with every possible aes-gcm key to know your key?
    // seems like a lot but targeting specific orbitdb stores would require only
    //  finding every encrypted original root by encrypting one orignal root with
    //  every possible aes-gcm key (if the amateur cryptographer in me is correct)
    // hopefully i am correct in thinking this is adequate security for now
    //  if the bytes deriving the aes key are random enough
    const dIv = bs58.decode(root)
    try {
      const decrypted = await key.decrypt(decodedEncRoot, dIv)
      return bs58.encode(Buffer.from(decrypted)) === root
    } catch(e) {
      console.error(e)
      return false
    }
  }

// cryptographic opterations imported from ./key.js
  // creates an AES key that can be used for an encryptedDocstore
  // require bytes source to have sufficient entropy when implementing
  static async genKey(...params) {
    return await Key.genKey(...params)
  }
  static async deriveKey(...params) {
    return await Key.deriveKey(...params)
  }
  static async importKey(...params) {
    return await Key.importKey(...params)
  }
  static async exportKey(...params) {
    return await Key.exportKey(...params)
  }

// helpers
  async decryptRecords(encryptedRecords) {
    return await Promise.all(
      encryptedRecords.map(encDoc => this._key.decryptMsg(encDoc))
    )
  }

// docstore operations
  async get(indexKey, caseSensitive = false) {
    if (indexKey === undefined) {
      throw new Error('indexKey is undefined')
    }
    // code taken from orbitdb document store get method:
    // https://github.com/orbitdb/orbit-db-docstore/blob/master/src/DocumentStore.js
    indexKey = indexKey.toString()
    const terms = indexKey.split(' ')
    indexKey = terms.length > 1
      ? replaceAll(indexKey, '.', ' ').toLowerCase()
      : indexKey.toLowerCase()
    const replaceAll = (str, search, replacement) =>
      str.toString().split(search).join(replacement)
    const search = (e) => {
      if (terms.length > 1) {
        return replaceAll(e, '.', ' ').toLowerCase().indexOf(indexKey) !== -1
      }
      return e.toLowerCase().indexOf(indexKey) !== -1
    }
    const filter = caseSensitive
      ? (i) => i[this.indexBy].indexOf(indexKey) !== -1
      : (i) => search(i[this.indexBy])
    const records = await this.decryptRecords(this._docstore.query(() => true))
    return await Promise.all(records.map(res => res.internal).filter(filter))
  }

  async put(doc) {
    if (typeof doc !== 'object') {
      throw new Error('doc must have type of object')
    }
    if (!doc[this.indexBy]) {
      throw new Error(`doc requires an ${this.indexBy} field`)
    }
    // since real _id is encapsulated in cipherbytes field and external _id is
    // random, we must delete the old entry by querying for the same id
    try { await this.del(doc[this.indexBy]) } catch(e) {}
    return await this._docstore.put(await this._key.encryptMsg(doc))
  }

  async del(indexKey) {
    if (indexKey === undefined) {
      throw new Error('indexKey must be defined')
    }
    const records = await this.decryptRecords(this._docstore.query(() => true))
    const matches = records.filter(res => res.internal[this.indexBy] === indexKey)
    // if a deletion fails this will clean it up old records
    if (matches.length > 1) {
      console.error(`there was more than one entry with internal key ${indexKey}`)
    }
    if (matches.length === 0) {
      throw new Error(`No entry with key '${indexKey}' in the database`)
    }
    // only return first deletion to keep same api as docstore
    return Promise.all(
      matches.map(res => this._docstore.del(res.external[this.indexBy]))
    ).then(arr => arr[0])
  }

  async query(mapper, options = {}) {
    if (mapper === undefined) {
      throw new Error('mapper was undefined')
    }
    const fullOp = options.fullOp || false
    const decryptFullOp = async(entry) => ({
      ...entry,
      payload: {
        ...entry.payload,
        value:await this._key.decryptMsg(entry.payload.value).then(res => res.internal),
      },
    })
    const index = this._docstore._index
    const indexGet = fullOp
      ? async(_id) => decryptFullOp(index._index[_id])
      : async(_id) => index._index[_id]
        ? await this._key.decryptMsg(index._index[_id].payload.value)
          .then(res => res.internal)
        : null
    const indexKeys = Object.keys(index._index)
    return Promise.all(indexKeys.map(key => indexGet(key)))
      .then(arr => arr.filter(mapper))
  }

}

module.exports = EncryptedDocstore
