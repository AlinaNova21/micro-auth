const { json, send } = require('micro')
const { decodeToken, refreshToken } = require('../lib/auth')

const REFRESH_PERIOD = 5 * 60 * 1000

module.exports.POST = async (req, res) => {
  const { token } = await json(req)
  if (!token) return send(res, 409, { error: 'Bad Request' })
  try {
    let data = await decodeToken(token)
    if (data.exp - Date.now() < REFRESH_PERIOD) {
      const newToken = refreshToken(token)
      send(res, 200, { success: true, result: data, token: newToken })
    }
    send(res, 200, { success: true, result: data })
  } catch (e) {
    send(res, 401, { error: 'Unauthorized' })
  }
}
