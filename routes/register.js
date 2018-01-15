const { json, send } = require('micro')
const { hashPassword } = require('../lib/auth')

module.exports.POST = async function register (req, res) {
  const { db } = req
  const { username, email, password } = await json(req)
  if (!username || !email || !password) return send(res, 400, { error: 'Bad Request' })
  const hash = await hashPassword(password)
  const [rows] = await db.execute('SELECT pk FROM auth WHERE username = ? OR email = ?', [username, email])
  if (rows.length) return send(res, 409, { error: 'User already exists' })
  await db.execute('INSERT INTO auth (username, email, password) VALUES (?, ?, ?)', [username, email, hash])
  send(res, 200, { success: true })
}
