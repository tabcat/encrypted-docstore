
'use strict'
const webcrypto = require('./node-webcrypto-ossl')

function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint16Array(buf));
}
function str2ab(str) {
  var buf = new ArrayBuffer(str.length*2); // 2 bytes for each char
  var bufView = new Uint16Array(buf);
  for (var i=0, strLen=str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

const randomBytes = async (bytesLength) =>
  await webcrypto.get().getRandomValues(new Uint8Array(bytesLength))

const encDocFields = ['_id', 'ciphertext', 'iv']
// returns a new object with only fields that will be encrypted

const cipherSect = (doc) => Object.keys(doc)
  .reduce((accu, current) => !encDocFields.includes(current)
    ? { ...accu, [current]:doc[current] }
    : accu,
  {})


class Key {
  constructor(cryptoKey) {
    this.cryptoKey = cryptoKey
  }

  static async genKey(options = {}) {
    const { length, purpose, } = options
    const bytes = await randomBytes(16)
    const salt = await randomBytes(12)
    const key = await this.deriveKey(bytes, salt, length, purpose, )
    return key
  }

  static async deriveKey(bytes, salt, length = 128, purpose = 'encrypted-docstore') {
    if (bytes === undefined || salt === undefined) {
      throw new Error('bytes and salt must be defined')
    }
    if (typeof purpose !== 'string') throw new Error('purpose must have type string')
    const hkdf = await webcrypto.get().subtle.importKey(
      'raw',
      bytes,
      { name:"HKDF" },
      false,
      ["deriveKey"],
    )
    const cryptoKey = await webcrypto.get().subtle.deriveKey(
      {
        name: 'HKDF',
        hash: { name:'SHA-256' },
        salt,
        info: str2ab(purpose),
      },
      hkdf,
      { name:'AES-GCM', length, },
      true, // exportable
      ['encrypt', 'decrypt']
    )
    return new Key(cryptoKey)
  }

  static async exportKey(key) {
    if (key === undefined) {
      throw new Error('key must be defined')
    }
    return await webcrypto.get().subtle.exportKey('raw', key)
  }

  static async importKey(rawKey) {
    if (rawKey === undefined) {
      throw new Error('rawKey must be defined')
    }
    const cryptoKey = await webcrypto.get().subtle.importKey(
      'raw',
      rawKey,
      { name:'AES-GCM' },
      true, // exportable
      ['encrypt', 'decrypt']
    )
    return new Key(cryptoKey)
  }

  async encrypt(bytes, iv) {
    if (bytes === undefined) {
      throw new Error('bytes must be defined')
    }
    // 12bytes is recommended for GCM for computational efficiencies
    iv = iv || await randomBytes(12)
    const algo = { ...this.cryptoKey.algorithm, iv }
    const cipherbytes = new Uint8Array(
      await webcrypto.get().subtle.encrypt(algo, this.cryptoKey, bytes)
    )
    return { cipherbytes, iv }
  }
  async decrypt(bytes, iv) {
    if (bytes === undefined || iv === undefined) {
      throw new Error('bytes and iv must be defined')
    }
    const algo = { ...this.cryptoKey.algorithm, iv }
    return await webcrypto.get().subtle.decrypt(algo, this.cryptoKey, bytes)
  }

  async encryptMsg(msg) {
    return await encryptDoc.bind(this)(msg)
  }
  async decryptMsg(msg) {
    return await decryptDoc.bind(this)(msg)
  }

}

async function encryptDoc(doc) {
  if (doc === undefined) {
    throw new Error('doc must be defined')
  }
  const bytes = str2ab(JSON.stringify(doc))
  const enc = await this.encrypt(bytes)
  const prepUint = (uint) => Object.values(uint)
  const cipherbytes = prepUint(enc.cipherbytes)
  const iv = prepUint(enc.iv)
  return { _id:`entry-${iv.join('')}`, cipherbytes, iv, }
}

async function decryptDoc(encDoc) {
  if (encDoc === undefined) {
    throw new Error('encDoc must be defined')
  }
  const deserializeUint = (obj) => new Uint8Array(Object.values(obj))
  const cipherbytes = deserializeUint(encDoc.cipherbytes)
  const iv = deserializeUint(encDoc.iv)
  const decrypted = await this.decrypt(cipherbytes, iv, )
  const clearObj = JSON.parse(ab2str(decrypted))
  return { internal:clearObj, external:encDoc }
}

module.exports = Key
