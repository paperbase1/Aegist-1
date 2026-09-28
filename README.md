# vulnscan-demo-bad

An intentionally vulnerable Express app, built as a worst-case demo target
for security scanners (e.g. static/secret/dependency/RLS scanners, active
missing-auth/IDOR probes). Every flaw here is planted on purpose:

- A hardcoded secret committed in `server.js`
- An admin route with no authentication
- An order-lookup route that checks auth but not ownership (IDOR)
- Outdated dependencies with known CVEs, plus one dependency that doesn't
  exist on npm at all (a "hallucinated dependency" test)
- Supabase migrations with Row Level Security disabled, never enabled, or
  granting access to everyone

**Do not deploy this anywhere real.** It's meant to be scanned, not run in
production -- run it only in a disposable container.

```bash
docker build -t vulnscan-demo-bad .
docker run -p 3001:3001 vulnscan-demo-bad
```
