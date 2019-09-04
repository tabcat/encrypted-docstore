
'use strict'
const Webcrypto = require('node-webcrypto-ossl')

const webcrypto = new Webcrypto()
exports.get = () => {
  return webcrypto
}
