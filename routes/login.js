const { json, send } = require('micro')
const { verifyPassword, generateToken } = require('../lib/auth')

module.exports.POST = async function login (req, res) {
  const { db } = req
  const { email, password } = await json(req)
  if (!email || !password) return send(res, 400, { error: 'Bad Request' })
  email = email.toLowerCase()
  const [[{ password: hash } = {}]] = await db.execute('SELECT username, password FROM auth WHERE username = ? OR email = ?', [ email, email ])
  if (!hash) return send(res, 401, { error: 'Unauthorized' })
  const valid = await verifyPassword(hash, password)
  if (!valid) return send(res, 401, { error: 'Unauthorized' })
  send(res, 200, { success: true, token: generateToken(username) })
}
