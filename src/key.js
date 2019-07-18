
'use strict'

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

const randomBytes = async (bytesLength) => await crypto.getRandomValues(new Uint8Array(bytesLength))

const encDocFields = ['_id', 'ciphertext', 'iv']
// returns a new object with only fields that will be encrypted
const cipherSect = (doc) => Object.keys(doc)
  .reduce((accu, current) => !encDocFields.includes(current)
    ? { ...accu, [current]:doc[current] }
    : accu,
  {})


class Key {
  constructor(cryptoKey) {
    this.key = cryptoKey
  }
  static async deriveKey(bytes, salt, length, purpose) {
    if (bytes === undefined || salt === undefined) {
      throw new Error('bytes and salt must be defined')
    }

    const hkdf = await crypto.subtle.importKey(
      'raw',
      bytes,
      { name:"HKDF" },
      false,
      ["deriveKey"],
    )

    const cryptoKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: { name:'SHA-256' },
        salt,
        info: str2ab(
          typeof purpose === 'string'
          ? purpose
          : 'encryptedDocstore'
        ),
      },
      hkdf,
      { name:'AES-GCM', length:length || 128 },
      true,
      ['encrypt', 'decrypt']
    )

    return new Key(cryptoKey)
  }
  static async exportKey(key) {
    if (key === undefined) {
      throw new Error('key must be defined')
    }

    const rawKey = await crypto.subtle.exportKey('raw', key)

    return rawKey
  }
  static async importKey(rawKey) {
    if (cryptoKeyAb === undefined) {
      throw new Error('cryptoKeyAb must be defined')
    }

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      rawKey,
      { name:'AES-GCM' },
      true,
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
    const algo = { ...this.key.algorithm, iv }

    const cipherbytes = new Uint8Array(
      await crypto.subtle.encrypt(algo, this.key, bytes)
    )

    return { cipherbytes, iv }
  }
  async decrypt(bytes, iv) {
    if (bytes === undefined || iv === undefined) {
      throw new Error('bytes and iv must be defined')
    }

    const algo = { ...this.key.algorithm, iv }

    return await crypto.subtle.decrypt(algo, this.key, bytes)
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
  const { cipherbytes, iv } = await this.encrypt(bytes)

  return { _id:`entry-${iv.join('')}`, cipherbytes, iv }
}
async function decryptDoc(encDoc) {
  if (encDoc === undefined) {
    throw new Error('encDoc must be defined')
  }

  const decrypted = await this.decrypt(encDoc.cipherbytes, encDoc.iv)
  const clearObj = JSON.parse(ab2str(decrypted))

  return { internal:clearObj, external:encDoc }
}

module.exports = Key
