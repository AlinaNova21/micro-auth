const { send } = require('micro')
const mysql = require('mysql2/promise')
const path = require('path')
const match = require('fs-router')(path.join(__dirname, '/routes'))

async function setup (fn) {
  const conn = await mysql.createConnection({
    host: process.env.MYSQL_HOST || 'localhost',
    port: process.env.MYSQL_PORT || 3306,
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASS || '',
    database: process.env.MYSQL_DB || ''
  })
  return (req, res) => {
    req.db = conn
    return fn(req, res)
  }
}

module.exports = setup(async (req, res) => {
  const matched = match(req)
  if (matched) return matched(req, res)
  send(res, 404, { error: 'Not found' })
})
