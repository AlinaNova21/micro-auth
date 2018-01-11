const { json, send } = require('micro')
const { verifyPassword } = require('../lib/auth')

module.exports.POST = async function login (req, res) {
  const { conn } = req
  const { email, password } = await json(req)
  if (!email || !password) return send(res, 400, { error: 'Bad Request' })
  const [[{ password: hash } = {}]] = await conn.execute('SELECT username, password FROM auth WHERE username = ? OR email = ?', [ email, email ])
  if (!hash) return send(res, 401, { error: 'Unauthorized' })
  const valid = await verifyPassword(hash, password)
  if (!valid) return send(res, 401, { error: 'Unauthorized' })
  send(res, 200, { success: true })
}
