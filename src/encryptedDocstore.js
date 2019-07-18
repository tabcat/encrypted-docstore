
'use strict'
// probably do something with this emitter later
const EventEmitter = require('events').EventEmitter
const bs58 = require('bs58')
const Buffer = require('safe-buffer').Buffer
const Key = require('./key')


class EncryptedDocstore extends EventEmitter {
  constructor(encryptedDocstore, key) {
    super()
    this.encrypted = encryptedDocstore
    this.key = key
  }
  // docstore: an instance of orbit docstore with name from determineEncDbName
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
  static async determineEncDbName(orbit, dbConfig, key) {
    if (orbit === undefined || dbConfig === undefined || key === undefined) {
      throw new Error('orbit, dbConfig and key must be defined')
    }

    const { name, type, options } = dbConfig
    const root = (await orbit.determineAddress(name, type, options)).root
    const decodedRoot = bs58.decode(root)

    const encRoot = bs58.encode(
      Buffer.from(
        (await key.encrypt(decodedRoot, decodedRoot)).cipherbytes
      )
    )

    return `${encRoot}/${root}`
  }
  // use to determine address of encDocstore
  static async determineEncDbAddress(orbit, dbConfig, key) {
    if (orbit === undefined || dbConfig === undefined || key === undefined) {
      throw new Error('orbit, dbConfig and key must be defined')
    }
    if (dbConfig.type !== 'docstore') {
      throw new Error('dbConfig type must be docstore')
    }

    const encDbName = await this.determineEncDbName(orbit, dbConfig, key)

    return await orbit.determineAddress(encDbName, dbConfig.type, dbConfig.options)
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
    // seems like a lot but targeting specific orbit stores would require only
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
  static async deriveKey(...params) {
    return await Key.deriveKey(...params)
  }
  static async importKey(...params) {
    return await Key.importKey(...params)
  }
  static async exportKey(...params) {
    return await Key.exportKey(...params)
  }

// docstore operations
  async get(indexKey, caseSensitive = false) {
    if (indexKey === undefined) {
      throw new Error('indexKey is undefined')
    }

    const indexBy = this.encrypted.options.indexBy

    // code taken from orbit document store get method:
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
      ? (i) => i[indexBy].indexOf(indexKey) !== -1
      : (i) => search(i[indexBy])

    const records = this.encrypted.query(() => true)
    const matches = await Promise.all(
      records.map(encDoc => this.key.decryptMsg(encDoc).then(res => res.internal))
    ).then(arr => arr.filter(filter))

    return matches
  }

  async put(doc) {
    if (typeof doc !== 'object') {
      throw new Error('doc must have type of object')
    }
    if (!doc[this.encrypted.options.indexBy]) {
      throw new Error(`doc requires an ${this.encrypted.options.indexBy} field`)
    }

    const indexBy = this.encrypted.options.indexBy
    const records = this.encrypted.query(() => true)

    // since real _id is encapsulated in cipherbytes field and external _id is
    // random, we must delete the old entry by querying for the same id
    await this.del(doc[indexBy])

    return await this.encrypted.put(await this.key.encryptMsg(doc))
  }

  async del(indexKey) {
    if (indexKey === undefined) {
      throw new Error('')
    }

    const indexBy = this.encrypted.options.indexBy
    const records = this.encrypted.query(() => true)

    const matches = await Promise.all(
      records.map(encDoc => this.key.decryptMsg(encDoc))
    ).then(arr => arr.filter(res => res.internal[indexBy] === indexKey))

    if (matches.length > 1) {
      console.error(`there was more than one entry with internal key ${indexKey}`)
    }

    // only return first
    return Promise.all(
      matches.map(res => this.encrypted.del(res.external[indexBy]))
    ).then(arr => arr[0])
  }

  async query(mapper, options = {}) {
    if (mapper === undefined) {
      throw new Error('mapper was undefined')
    }

    // decrypts each doc before mapper recieves them
    const encMapper = async (encDoc) =>
      mapper(await this.key.decryptMsg(encDoc).then(res => res.internal))
    // calls the query with the higher order decrypting mapper
    const encQuery = this.encrypted.query(encMapper, options)

    return await Promise.all(
      encQuery.map((encDoc) => this.key.decryptMsg(encDoc))
    ).then(arr => arr.map(res => res.internal))
  }

}

module.exports = EncryptedDocstore
