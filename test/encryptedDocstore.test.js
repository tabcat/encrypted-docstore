
'use strict'
const assert = require('assert')
const EncDocstore = require('../src/encryptedDocstore')
const Ipfs = require('@tabcat/ipfs-bundle-t')
const OrbitDB = require('orbit-db')
const crypto = require('@tabcat/peer-account-crypto')
// const wtf = require('wtfnode')

// wtf.setLogger('info', console.log)

describe('EncryptedDocstore', function () {
  this.timeout(30000)

  let ipfs, orbitdb
  const name = 'name'
  const type = 'docstore'
  const options = { replicate: false, accessController: { write: ['*'] } }
  const bytes = crypto.util.str2ab('bytes')
  const salt = crypto.util.str2ab('salt')
  const rawKey = new Uint8Array(
    [221, 189, 199, 144, 98, 65, 223, 203, 196, 23, 8, 73, 8, 112, 161, 205]
  )
  const address =
    '/orbitdb/zdpuApcptDZAGCTFUMGPV7w718rohJuXb2witrDaVC15XCpja/P9NiFPYM2P615i3NrLUYWJvohzTFG97rndcNLxUKYAgEEQABK3KkzesupoxLi47e8t7WGKF/name'

  before(async () => {
    ipfs = await new Promise((resolve, reject) => {
      const node = Ipfs({ repo: './ipfs' })
      node.on('ready', () => resolve(node))
      node.on('error', reject)
    })
    orbitdb = await OrbitDB.createInstance(
      ipfs,
      { directory: './orbitdb' }
    )
  })

  after(async () => {
    await orbitdb.disconnect()
    await ipfs.stop()
    console.log('UNFORTUNATELY TESTS DO NOT EXIT ON THEIR OWN')
    // wtf.dump()
    // setTimeout(wtf.dump, 3000)
  })

  describe('.mount', function () {
    it('mounts an encrypted docstore', async () => {
      const aesKey = await EncDocstore.deriveKey(bytes, salt)
      const encAddr = await EncDocstore.determineAddress(
        orbitdb,
        { name, type, options },
        aesKey
      )
      const docstore = await orbitdb.docs(encAddr, options)
      const encDocstore = await EncDocstore.mount(docstore, aesKey)
      await encDocstore._docstore.drop()
    })
  })

  describe('.determineAddress', function () {
    it('determines the address of an encrypted docstore', async () => {
      const aesKey = await EncDocstore.deriveKey(bytes, salt)
      const encAddr = await EncDocstore.determineAddress(
        orbitdb,
        { name, type, options },
        aesKey
      )
      assert.strictEqual(encAddr.toString(), address)
    })
  })

  describe('.keyCheck', function () {
    it('returns true when address and aesKey match', async () => {
      const encAddr = OrbitDB.parseAddress(address)
      const aesKey = await EncDocstore.deriveKey(bytes, salt)
      const keyCheck = await EncDocstore.keyCheck(encAddr, aesKey)
      assert.strictEqual(keyCheck, true)
    })

    it('returns false when address and aesKey mismatch', async () => {
      const dbAddr = OrbitDB.parseAddress(
        '/orbitdb/Qmdgwt7w4uBsw8LXduzCd18zfGXeTmBsiR8edQ1hSfzcJC/first-database'
      )
      const aesKey = await EncDocstore.deriveKey(bytes, salt)
      const keyCheck = await EncDocstore.keyCheck(dbAddr, aesKey)
      assert.strictEqual(keyCheck, false)
    })
  })

  describe('AesKey methods', function () {
    let aesKey

    afterEach(async () => {
      const encAddr = await EncDocstore.determineAddress(
        orbitdb,
        { name, type, options },
        aesKey
      )
      const encDocstore = await EncDocstore.mount(
        await orbitdb.docs(encAddr, options),
        aesKey
      )
      await encDocstore._docstore.close()
      await encDocstore._docstore.drop()
    })

    it('generate usuable key', async () => {
      aesKey = await EncDocstore.generateKey()
    })

    it('derive usuable key', async () => {
      aesKey = await EncDocstore.deriveKey(bytes, salt)
    })

    it('import usuable key', async () => {
      aesKey = await EncDocstore.importKey(rawKey)
    })

    it('export raw aes key', async () => {
      aesKey = await EncDocstore.importKey(rawKey)
      const exported = await EncDocstore.exportKey(aesKey)
      assert.deepStrictEqual(exported, rawKey)
      aesKey = await EncDocstore.importKey(rawKey)
    })
  })

  // // tests docstore methods using modified tests from the official repo!
  // // https://github.com/orbitdb/orbit-db/blob/master/test/docstore.test.js
  describe('Docstore methods', function () {
    describe('Default index \'_id\'', function () {
      let aesKey, encDocstore

      beforeEach(async () => {
        aesKey = await EncDocstore.deriveKey(bytes, salt)
        const encAddr = await EncDocstore.determineAddress(
          orbitdb,
          { name, type, options },
          aesKey
        )
        encDocstore = await EncDocstore.mount(
          await orbitdb.docs(encAddr, options),
          aesKey
        )
      })

      afterEach(async () => {
        await encDocstore._docstore.drop()
      })

      it('put', async () => {
        const doc = { _id: 'hello world', doc: 'all the things' }
        await encDocstore.put(doc)
        const value = await encDocstore.get('hello world')
        assert.deepStrictEqual(value, [doc])
      })

      it('get - partial term match', async () => {
        const doc1 = { _id: 'hello world', doc: 'some things' }
        const doc2 = { _id: 'hello universe', doc: 'all the things' }
        const doc3 = { _id: 'sup world', doc: 'other things' }
        await encDocstore.put(doc1)
        await encDocstore.put(doc2)
        await encDocstore.put(doc3)
        const value = await encDocstore.get('hello')
        assert.deepStrictEqual(value, [doc1, doc2])
      })

      it('get after delete', async () => {
        const doc1 = { _id: 'hello world', doc: 'some things' }
        const doc2 = { _id: 'hello universe', doc: 'all the things' }
        const doc3 = { _id: 'sup world', doc: 'other things' }
        await encDocstore.put(doc1)
        await encDocstore.put(doc2)
        await encDocstore.put(doc3)
        await encDocstore.del('hello universe')
        const value1 = await encDocstore.get('hello')
        const value2 = await encDocstore.get('sup')
        assert.deepStrictEqual(value1, [doc1])
        assert.deepStrictEqual(value2, [doc3])
      })

      it('put updates a value', async () => {
        const doc1 = { _id: 'hello world', doc: 'all the things' }
        const doc2 = { _id: 'hello world', doc: 'some of the things' }
        await encDocstore.put(doc1)
        await encDocstore.put(doc2)
        const value = await encDocstore.get('hello')
        assert.deepStrictEqual(value, [doc2])
      })

      it('query', async () => {
        const doc1 = { _id: 'hello world', doc: 'all the things', views: 17 }
        const doc2 = { _id: 'sup world', doc: 'some of the things', views: 10 }
        const doc3 =
          { _id: 'hello other world', doc: 'none of the things', views: 5 }
        const doc4 = { _id: 'hey universe', doc: '' }

        await encDocstore.put(doc1)
        await encDocstore.put(doc2)
        await encDocstore.put(doc3)
        await encDocstore.put(doc4)

        const value1 = await encDocstore.query((e) => e.views > 5)
        const value2 = await encDocstore.query((e) => e.views > 10)
        const value3 = await encDocstore.query((e) => e.views > 17)

        assert.deepStrictEqual(value1, [doc1, doc2])
        assert.deepStrictEqual(value2, [doc1])
        assert.deepStrictEqual(value3, [])
      })

      it('query after delete', async () => {
        const doc1 = { _id: 'hello world', doc: 'all the things', views: 17 }
        const doc2 = { _id: 'sup world', doc: 'some of the things', views: 10 }
        const doc3 =
          { _id: 'hello other world', doc: 'none of the things', views: 5 }
        const doc4 = { _id: 'hey universe', doc: '' }

        await encDocstore.put(doc1)
        await encDocstore.put(doc2)
        await encDocstore.put(doc3)
        await encDocstore.del('hello world')
        await encDocstore.put(doc4)
        const value1 = await encDocstore.query((e) => e.views >= 5)
        const value2 = await encDocstore.query((e) => e.views >= 10)
        assert.deepStrictEqual(value1, [doc2, doc3])
        assert.deepStrictEqual(value2, [doc2])
      })

      it('query returns full op', async () => {
        const doc1 = { _id: 'hello world', doc: 'all the things', views: 17 }
        const doc2 = { _id: 'sup world', doc: 'some of the things', views: 10 }

        const expectedOperation = {
          op: 'PUT',
          key: 'sup world',
          value: {
            _id: 'sup world',
            doc: 'some of the things',
            views: 10
          }
        }

        await encDocstore.put(doc1)
        await encDocstore.put(doc2)

        const res = (await encDocstore
          .query(e => e.payload.value.views < 17, { fullOp: true }))[0]
        assert.notStrictEqual(res, undefined)
        assert.notStrictEqual(res.hash, undefined)
        assert.notStrictEqual(res.id, undefined)
        assert.deepStrictEqual(res.payload, expectedOperation)
        assert.notStrictEqual(res.next, undefined)
        assert.strictEqual(res.next.length, 1)
        assert.strictEqual(res.v, 1)
        assert.notStrictEqual(res.clock, undefined)
        assert.strictEqual(res.clock.time, 2)
        assert.notStrictEqual(res.key, undefined)
        assert.notStrictEqual(res.sig, undefined)
      })
    })

    describe('Specified index', function () {
      let aesKey, encDocstore

      beforeEach(async () => {
        aesKey = await EncDocstore.deriveKey(bytes, salt)
        const encAddr = await EncDocstore.determineAddress(
          orbitdb,
          { name, type, options },
          aesKey
        )
        encDocstore = await EncDocstore.mount(
          await orbitdb.docs(encAddr, { ...options, indexBy: 'doc' }),
          aesKey
        )
      })

      afterEach(async () => {
        await encDocstore._docstore.drop()
      })

      it('put', async () => {
        const doc = { _id: 'hello world', doc: 'all the things' }
        await encDocstore.put(doc)
        const value = await encDocstore.get('all')
        assert.deepStrictEqual(value, [doc])
      })

      it('get - matches specified index', async () => {
        const doc1 = { _id: 'hello world', doc: 'all the things' }
        const doc2 = { _id: 'hello world', doc: 'some things' }

        await encDocstore.put(doc1)
        await encDocstore.put(doc2)

        const value1 = await encDocstore.get('all')
        const value2 = await encDocstore.get('some')
        assert.deepStrictEqual(value1, [doc1])
        assert.deepStrictEqual(value2, [doc2])
      })
    })
  })
})
