/*
 * DHC-3446 | Cybersecurity Internship 2026
 * middleware/csrfProtection.ts — CSRF Protection (Week 5)
 *
 * PROBLEM SOLVED: Cross-Site Request Forgery
 * Without CSRF protection, an attacker can trick a logged-in
 * user into unknowingly submitting a form on our site from
 * a malicious page — like silently transferring money or
 * changing their password without their knowledge.
 *
 * HOW IT WORKS:
 * The server generates a unique secret token for each session.
 * Every state-changing request (POST/PUT/DELETE) must include
 * this token. An attacker's fake page cannot read it, so their
 * forged request gets rejected automatically.
 */

import csrf from 'csurf'
import { Request, Response, NextFunction } from 'express'

// Set up CSRF using a cookie-based token
export const csrfProtection = csrf({ cookie: true })

// Error handler — catches invalid/missing CSRF tokens
export function handleCsrfError (err: any, req: Request, res: Response, next: NextFunction): void {
  if (err.code === 'EBADCSRFTOKEN') {
    global.logger.warn(`CSRF attack blocked — ${req.method} ${req.path} — IP: ${req.ip}`)
    res.status(403).json({ error: 'Invalid CSRF token. Request blocked.' })
    return
  }
  next(err)
}
