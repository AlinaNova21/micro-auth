const crypto = require('crypto')
const Promise = require('bluebird')
const JWT = require('jsonwebtoken')

const JWT_SECRET = process.env.JWT_SECRET
const JWT_PUBLIC = process.env.JWT_PUBLIC
const JWT_PRIVATE = process.env.JWT_PRIVATE
const JWT_ALGORITHM = process.env.JWT_ALGORITHM || 'HS256'

Promise.promisifyAll(crypto)
Promise.promisifyAll(JWT)

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
  return JWT.signAsync({
    username,
    scope
  }, JWT_PRIVATE || JWT_SECRET, {
    expiresIn
  })
}

async function decodeToken (token) {
  return JWT.verifyAsync(token, JWT_PUBLIC || JWT_SECRET)
}

async function refreshToken (token) {
  const { iat, exp, nbf, jti, ...data } = await decodeToken(token)
  return JWT.signAsync(data, JWT_PRIVATE || JWT_SECRET, { expiresIn: exp - iat })
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateToken,
  decodeToken,
  refreshToken
}
