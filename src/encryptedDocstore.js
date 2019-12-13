
'use strict'
const bs58 = require('bs58')
const Buffer = require('safe-buffer').Buffer
const { aes, util } = require('@tabcat/peer-account-crypto')

// deterministic iv
// used as iv when encrypting dbAddr root for encAddr
const dIv = util.str2ab('encrypted-docstore')

function encryptDoc (aesKey, indexBy) {
  return async (doc) => {
    try {
      if (doc === undefined) {
        throw new Error('doc must be defined')
      }
      const bytes = util.str2ab(JSON.stringify(doc))
      const enc = await aesKey.encrypt(bytes)
      const cipherbytes = Object.values(enc.cipherbytes)
      const iv = Object.values(enc.iv)
      return { [indexBy]: `entry-${iv.join('.')}`, cipherbytes, iv }
    } catch (e) {
      console.error(e)
      console.error('failed to encrypt doc')
      return undefined
    }
  }
}

function decryptDoc (aesKey) {
  return async (encDoc) => {
    try {
      if (encDoc === undefined) {
        throw new Error('encDoc must be defined')
      }
      const cipherbytes = new Uint8Array(encDoc.cipherbytes)
      const iv = new Uint8Array(encDoc.iv)
      const decrypted = await aesKey.decrypt(cipherbytes, iv)
      const doc = JSON.parse(util.ab2str(decrypted.buffer))
      return { internal: doc, external: encDoc }
    } catch (e) {
      console.error(e)
      console.error('failed to decrypt doc')
      return undefined
    }
  }
}

function decryptDocs (aesKey) {
  const decrypt = decryptDoc(aesKey)
  return async (encDocs) => {
    const docs = await Promise.all(encDocs.map(encDoc => decrypt(encDoc)))
    return docs.filter(t => t) // prune undefined
  }
}

class EncryptedDocstore {
  constructor (docstore, aesKey) {
    if (!docstore) throw new Error('docstore must be defined')
    if (!aesKey) throw new Error('aesKey must be defined')
    this._docstore = docstore
    this._aesKey = aesKey
    this._indexBy = this._docstore.options.indexBy
  }

  static async mount (docstore, aesKey) {
    if (!docstore || !aesKey) {
      throw new Error('docstore and aesKey must be defined')
    }
    if (!await this.keyCheck(docstore.address, aesKey)) {
      throw new Error('keyCheck failed while trying to mount store')
    }
    return new EncryptedDocstore(docstore, aesKey)
  }

  // use to determine address of the docstore to be used for encryption
  static async determineAddress (orbitdb, dbConfig, aesKey) {
    if (!orbitdb || !dbConfig || !aesKey) {
      throw new Error('orbitdb, dbConfig and aesKey must be defined')
    }
    if (dbConfig.type !== 'docstore' && dbConfig.type !== undefined) {
      throw new Error('dbConfig type must be docstore')
    }
    const { name, options } = dbConfig
    const type = 'docstore'
    const root = (await orbitdb.determineAddress(name, type, options)).root
    const decodedRoot = bs58.decode(root)
    try {
      const encRoot = bs58.encode(Buffer.from(
        (await aesKey.encrypt(decodedRoot, dIv)).cipherbytes
      ))
      const encName = `${encRoot}/${name}`
      return orbitdb.determineAddress(encName, type, options)
    } catch (e) {
      console.error(e)
      throw new Error('failed to determine address')
    }
  }

  // encAddr is whats returned from this.determineAddress
  // it is an instance of orbitdb's address
  static async keyCheck (encAddr, aesKey) {
    if (!encAddr || !aesKey) {
      throw new Error('encAddr and aesKey must be defined')
    }
    const encRoot = encAddr.path.split('/')[0]
    if (!encRoot) throw new Error('invalid encrypted docstore address')
    try {
      await aesKey.decrypt(bs58.decode(encRoot), dIv)
      return true
    } catch (e) {
      return false
    }
  }

  // creates an aesKey that can be used for an encryptedDocstore
  static async generateKey (...params) {
    return aes.generateKey(...params)
  }

  static async deriveKey (...params) {
    return aes.deriveKey(...params)
  }

  static async importKey (...params) {
    return aes.importKey(...params)
  }

  static async exportKey (...params) {
    return aes.exportKey(...params)
  }

  // docstore operations
  async get (indexKey, caseSensitive = false) {
    if (indexKey === undefined) {
      throw new Error('indexKey is undefined')
    }
    // code taken from orbitdb document store get method:
    // https://github.com/orbitdb/orbit-db-docstore/blob/master/src/DocumentStore.js
    indexKey = indexKey.toString()
    const terms = indexKey.split(' ')
    const replaceAll = (str, search, replacement) =>
      str.toString().split(search).join(replacement)
    indexKey = terms.length > 1
      ? replaceAll(indexKey, '.', ' ').toLowerCase()
      : indexKey.toLowerCase()
    const search = (e) => {
      if (terms.length > 1) {
        return replaceAll(e, '.', ' ').toLowerCase().indexOf(indexKey) !== -1
      }
      return e.toLowerCase().indexOf(indexKey) !== -1
    }
    const filter = caseSensitive
      ? (i) => i[this._indexBy].indexOf(indexKey) !== -1
      : (i) => search(i[this._indexBy])

    const docs =
      await decryptDocs(this._aesKey)(this._docstore.query(() => true))
    return Promise.all(docs.map(res => res.internal).filter(filter))
  }

  async put (doc) {
    if (typeof doc !== 'object') {
      throw new Error('doc must have type of object')
    }
    if (!doc[this._indexBy]) {
      throw new Error(`doc requires an ${this._indexBy} field`)
    }
    // since real _id is encapsulated in cipherbytes field and external _id is
    // random, we must delete the old entry by querying for the same id
    try { await this.del(doc[this._indexBy]) } catch (e) {}
    const encDoc = await encryptDoc(this._aesKey, this._indexBy)(doc)
    if (!encDoc) throw new Error('failed to encrypt doc')
    return this._docstore.put(encDoc)
  }

  async del (indexKey) {
    if (indexKey === undefined) {
      throw new Error('indexKey must be defined')
    }
    const docs =
      await decryptDocs(this._aesKey)(this._docstore.query(() => true))
    const matches = docs.filter(res => res.internal[this._indexBy] === indexKey)
    if (matches.length > 1) {
      console.error(
        `there was more than one entry with internal key: ${indexKey}`
      )
    }
    if (matches.length === 0) {
      throw new Error(`No entry with key: '${indexKey}' in the database`)
    }
    // if a deletion failed this will clean it up old docs
    // only return first deletion to keep same api as docstore
    return matches.reduce(
      async (a, c) => [
        ...await a,
        this._docstore.del(c.external[this._indexBy])
      ],
      []
    ).then(arr => arr[0])
  }

  async query (mapper, options = {}) {
    if (mapper === undefined) throw new Error('mapper was undefined')
    if (typeof mapper !== 'function') throw new Error('mapper must be function')
    const decrypt = decryptDoc(this._aesKey)
    const decryptFullOp = async (entry) => {
      const doc = await decrypt(entry.payload.value).then(res => res.internal)
      return doc
        ? {
          ...entry,
          payload: {
            ...entry.payload,
            key: doc[this._indexBy],
            value: doc
          }
        }
        : undefined
    }
    const index = this._docstore._index
    const indexGet = options.fullOp || false
      ? async (_id) => decryptFullOp(index._index[_id])
      : async (_id) => index._index[_id]
        ? decrypt(index._index[_id].payload.value)
          .then(res => res.internal)
        : null
    const indexKeys = Object.keys(index._index)
    return Promise.all(indexKeys.map(key => indexGet(key)))
      // remove undefined docs before handing to mapper
      .then(arr => arr.filter(t => t).filter(mapper))
  }
}

module.exports = EncryptedDocstore
