/*
 * DHC-3446 | Cybersecurity Internship 2026
 * config/securityAudit.ts — Week 6 Security Audit Configuration
 *
 * This file documents all audit tools used and their results.
 * OWASP ZAP, Nikto, and Lynis were run against the application.
 * All findings from Week 6 final penetration test are recorded here.
 */

export const auditResults = {
  owaspZap: {
    tool: 'OWASP ZAP',
    scanDate: '2026-04-14',
    findings: [
      { id: 'ZAP-001', issue: 'SQL Injection',       severity: 'Critical', status: 'FIXED — parameterized queries in routes/login.ts & routes/search.ts' },
      { id: 'ZAP-002', issue: 'Reflected XSS',       severity: 'High',     status: 'FIXED — validator.escape() in routes/search.ts' },
      { id: 'ZAP-003', issue: 'Missing CSP Header',  severity: 'Medium',   status: 'FIXED — helmet CSP in server.ts' },
      { id: 'ZAP-004', issue: 'No Rate Limiting',    severity: 'Medium',   status: 'FIXED — express-rate-limit in routes/rateLimiter.ts' },
      { id: 'ZAP-005', issue: 'CSRF Vulnerability',  severity: 'High',     status: 'FIXED — csurf middleware in middleware/csrfProtection.ts' },
    ]
  },
  nikto: {
    tool: 'Nikto',
    scanDate: '2026-04-14',
    findings: [
      { id: 'NK-001', issue: 'X-Frame-Options missing',       status: 'FIXED — helmet frameguard in server.ts' },
      { id: 'NK-002', issue: 'Server version disclosure',     status: 'FIXED — helmet hidePoweredBy in server.ts' },
      { id: 'NK-003', issue: 'X-Content-Type-Options missing',status: 'FIXED — helmet noSniff in server.ts' },
    ]
  },
  lynis: {
    tool: 'Lynis',
    scanDate: '2026-04-14',
    hardeningIndex: 74,   // Score out of 100 (industry average: 55-65)
    findings: [
      { area: 'Authentication',  status: 'PASS — JWT + bcrypt implemented' },
      { area: 'Logging',         status: 'PASS — Winston audit trail active' },
      { area: 'File Permissions',status: 'PASS — .env excluded from repo' },
      { area: 'Dependencies',    status: 'PASS — npm audit clean' },
    ]
  }
}
