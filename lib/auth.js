const crypto = require('crypto')
const Promise = require('bluebird')

Promise.promisifyAll(crypto)

const OPTIONS = {
  saltlen: 32,
  iterations: 25000,
  keylen: 512,
  encoding: 'hex',
  digestAlgorithm: 'sha256' // To get a list of supported hashes use crypto.getHashes()
}

async function pbkdf2 (password, salt) {
  let { iterations, keylen, digestAlgorithm, encoding } = OPTIONS
  let raw = await crypto.pbkdf2Async(Buffer.from(password), salt, iterations, keylen, digestAlgorithm)
  return raw.toString(encoding)
}

async function hashPassword (password) {
  let { saltlen, encoding } = OPTIONS
  let buf = await crypto.randomBytesAsync(saltlen)
  let salt = buf.toString(encoding)
  let hash = await pbkdf2(password, salt)
  return `${salt}.${hash}`
}

async function verifyPassword (pass, proposed) {
  let [salt, hash] = pass.split('.')
  let calcedHash = await pbkdf2(proposed, salt)
  return hash === calcedHash
}

module.exports = {
  hashPassword,
  verifyPassword
}
