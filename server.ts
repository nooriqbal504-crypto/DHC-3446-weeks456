/*
 * DHC-3446 | Cybersecurity Internship 2026
 * server.ts — Final Hardened Server (Weeks 4, 5 & 6)
 *
 * Builds on the Week 2 foundation and adds:
 *   Week 4: Rate limiting, CORS restriction, API key authentication
 *   Week 5: CSRF protection, SQLi prevention via prepared statements
 *   Week 6: Full audit compliance, dependency scanning, secure deployment
 */

import express from 'express'
import helmet from 'helmet'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import winston from 'winston'
import loginRouter from './routes/login'
import searchRouter from './routes/search'
import { apiLimiter, corsOptions } from './routes/rateLimiter'
import { authenticateToken } from './middleware/authenticateToken'
import { csrfProtection, handleCsrfError } from './middleware/csrfProtection'

// ── Winston Audit Trail (from Week 3 — still active) ─────────────────────────
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message }) =>
      `[${timestamp as string}] ${level.toUpperCase()}: ${message as string}`)
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/security.log' })
  ]
});
(global as any).logger = logger

const app = express()

// ── Week 4: CORS — only accept requests from our trusted frontend ─────────────
app.use(cors(corsOptions))

// ── Helmet.js (Week 2) — still protecting all headers ────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", 'data:'],
      connectSrc: ["'self'"],
      frameSrc:   ["'none'"],
      objectSrc:  ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  frameguard:      { action: 'deny' },
  noSniff:         true,
  hidePoweredBy:   true,       // Week 6: Hide "X-Powered-By: Express" header
  referrerPolicy:  { policy: 'no-referrer' }
}))

app.use(cookieParser())
app.use(express.json({ limit: '10kb' }))
app.use(express.urlencoded({ extended: true }))

// ── Week 4: Global rate limiting on all API routes ────────────────────────────
app.use('/api/', apiLimiter)

// ── Week 5: CSRF protection on all state-changing routes ─────────────────────
app.use(csrfProtection)

// ── Request Logging ───────────────────────────────────────────────────────────
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} — IP: ${req.ip}`)
  next()
})

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/rest/user/login',     loginRouter)
app.use('/rest/products/search', searchRouter)

// CSRF token endpoint — frontend fetches this first before any POST
app.get('/api/csrf-token', csrfProtection, (req: any, res) => {
  res.json({ csrfToken: req.csrfToken() })
})

// Protected admin route example
app.get('/api/Users', authenticateToken, (req, res) => {
  res.json({ message: 'Admin user list — JWT protected' })
})

app.get('/', (req, res) => {
  res.json({ project: 'DHC-3446', weeks: '4-6', status: 'Fully hardened' })
})

// ── Week 5: CSRF error handler ────────────────────────────────────────────────
app.use(handleCsrfError)

// ── Global error handler — never leak stack traces ────────────────────────────
app.use((err: Error, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error(`Error on ${req.method} ${req.path}: ${err.message}`)
  res.status(500).json({ error: 'Internal server error' })
})

const PORT = process.env.PORT ?? 3000
app.listen(PORT, () => {
  logger.info(`DHC-3446 (Weeks 4-6) running on port ${PORT}`)
})

export default app
