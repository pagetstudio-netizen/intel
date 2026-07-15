---
name: Shared rate limiter must exclude polled GETs
description: Why express-rate-limit instances applied at app.use(path, limiter, router) break UIs that poll GET endpoints every few seconds.
---

If a single `express-rate-limit` instance (e.g. `scanLimiter`) is applied via `app.use('/api/x', limiter, router)`, it limits ALL methods on that router — GET included — and the limiter instance is shared by identity, so mounting the *same* limiter object on multiple routers pools their request counts into one shared per-IP bucket.

**Why:** In this app, the frontend polls every job-listing GET endpoint (scans, fuzz, phishing, osint, auth-audit, security-audit, etc.) every 3s via a single `refresh()` loop. With 7+ routers sharing one 20-req/min limiter mounted at the router level, normal polling alone exceeded the limit and produced constant 429s — before any actual scan was launched.

**How to apply:** Apply rate limiting only to the mutating (POST) route handler inside each router file (`router.post('/', scanLimiter, async (req, res) => ...)`), not at the `app.use` mount level. Keep GET listing/detail routes unlimited (or on a much more generous limiter) since they're expected to be polled frequently.
