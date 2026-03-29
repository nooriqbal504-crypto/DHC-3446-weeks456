/*
 * DHC-3446 | Cybersecurity Internship 2026
 * routes/rateLimiter.ts — Rate Limiting & CORS (Week 4)
 *
 * PROBLEM SOLVED: Brute Force Attacks
 * Without rate limiting, an attacker can try thousands of
 * passwords per second until they find the right one.
 * express-rate-limit acts like a "lockout policy" — after
 * 5 failed attempts the IP is blocked for 15 minutes.
 */

import rateLimit from 'express-rate-limit'
import cors from 'cors'

// ── Login Rate Limiter — 5 attempts per 15 min per IP ────────────────────────
export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, _next, options) => {
    global.logger.warn(`Rate limit triggered on /login — IP: ${req.ip}`)
    res.status(429).json(options.message)
  }
})

// ── General API Limiter — 100 requests per 15 min ────────────────────────────
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests from this IP. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false
})

// ── CORS — only allow our own trusted frontend ────────────────────────────────
export const corsOptions: cors.CorsOptions = {
  origin: process.env.ALLOWED_ORIGIN ?? 'http://localhost:3000',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  credentials: true,
  optionsSuccessStatus: 200
}
