/*
 * DHC-3446 | Cybersecurity Internship 2026
 * middleware/apiKeyAuth.ts — API Key Authentication (Week 4)
 *
 * PROBLEM SOLVED: Unauthenticated API Access
 * Public APIs without any key validation can be scraped,
 * abused, or flooded by anyone. This middleware checks for
 * a valid X-API-Key header before allowing access to
 * sensitive endpoints — like a "secret handshake."
 */

import { Request, Response, NextFunction } from 'express'

const VALID_API_KEYS = new Set([
  process.env.API_KEY_1 ?? 'dhc3446-dev-key-replace-in-production',
  process.env.API_KEY_2 ?? 'dhc3446-test-key-replace-in-production'
])

export function apiKeyAuth (req: Request, res: Response, next: NextFunction): void {
  const apiKey = req.headers['x-api-key']

  if (!apiKey || typeof apiKey !== 'string') {
    global.logger.warn(`API access denied — no key — ${req.method} ${req.path} — IP: ${req.ip}`)
    res.status(401).json({ error: 'API key required. Include X-API-Key header.' })
    return
  }

  if (!VALID_API_KEYS.has(apiKey)) {
    global.logger.warn(`API access denied — invalid key — IP: ${req.ip}`)
    res.status(403).json({ error: 'Invalid API key.' })
    return
  }

  global.logger.info(`API key authenticated — ${req.method} ${req.path}`)
  next()
}
