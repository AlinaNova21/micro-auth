const crypto = require('crypto')
const Promise = require('bluebird')
const JWT = require('jsonwebtoken')

const JWT_SECRET = process.env.JWT_SECRET

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

async function generateToken (username, scope = ['*'], expiresIn = '1d') {
  return JWT.sign({
    username,
    scope
  }, JWT_SECRET, {
    expiresIn
  })
}

async function decodeToken (token) {
  return JWT.verify(token, JWT_SECRET)
}

async function refreshToken (token) {
  const { username, scope } = await decodeToken(token)
  return generateToken(username, scope)
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateToken,
  decodeToken,
  refreshToken
}
