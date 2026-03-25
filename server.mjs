import http from 'node:http'
import { randomBytes } from 'node:crypto'
import { URL } from 'node:url'

const PORT = process.env.PORT ? Number(process.env.PORT) : 5000

const sessions = new Map()

function json(res, statusCode, data) {
  const body = JSON.stringify(data)
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Access-Control-Allow-Origin': 'http://localhost:5173',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
  })
  res.end(body)
}

function noContent(res) {
  res.writeHead(204, {
    'Access-Control-Allow-Origin': 'http://localhost:5173',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
  })
  res.end()
}

async function readJson(req) {
  const chunks = []
  for await (const chunk of req) chunks.push(chunk)
  const raw = Buffer.concat(chunks).toString('utf-8').trim()
  if (!raw) return {}
  return JSON.parse(raw)
}

function getBearerToken(req) {
  const auth = req.headers.authorization || ''
  const m = auth.match(/^Bearer\s+(.+)$/i)
  return m ? m[1] : null
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`)

    if (req.method === 'OPTIONS') return noContent(res)

    if (req.method === 'GET' && url.pathname === '/health') {
      return json(res, 200, { ok: true })
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/auth/login') {
      const body = await readJson(req)
      const username = String(body.username || '').trim()
      const password = String(body.password || '').trim()

      if (!username || !password) {
        return json(res, 400, { success: false, message: 'username/password required' })
      }

      if (password.length < 6) {
        return json(res, 401, { success: false, message: 'invalid credentials' })
      }

      const token = randomBytes(24).toString('hex')
      const user = {
        id: `u_${randomBytes(6).toString('hex')}`,
        username,
        email: body.email ? String(body.email) : `${username}@example.com`,
        roles: ['user']
      }

      sessions.set(token, { user, createdAt: Date.now() })

      return json(res, 200, {
        success: true,
        data: { token, user }
      })
    }

    if (req.method === 'GET' && url.pathname === '/api/v1/auth/me') {
      const token = getBearerToken(req)
      if (!token) return json(res, 401, { success: false, message: 'missing token' })

      const session = sessions.get(token)
      if (!session) return json(res, 401, { success: false, message: 'invalid token' })

      return json(res, 200, { success: true, data: { user: session.user } })
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/auth/logout') {
      const token = getBearerToken(req)
      if (token) sessions.delete(token)
      return json(res, 200, { success: true })
    }

    return json(res, 404, { success: false, message: 'not found' })
  } catch (e) {
    return json(res, 500, { success: false, message: 'server error' })
  }
})

server.listen(PORT, () => {
  console.log(`Mock auth server running: http://localhost:${PORT}`)
  console.log('Endpoints:')
  console.log('  POST /api/v1/auth/login { username, password }')
  console.log('  GET  /api/v1/auth/me    Authorization: Bearer <token>')
  console.log('  POST /api/v1/auth/logout Authorization: Bearer <token>')
})