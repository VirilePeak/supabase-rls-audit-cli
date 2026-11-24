# supabase-rls-audit-cli

Zero-dependency, read-only CLI and GitHub Action to audit deployed Supabase apps (Next.js, Lovable, Cursor, Bolt, Vite) and local SQL migrations for:

- **Unauthenticated PostgREST table reads** via the frontend `anon` key (reports table + column names only — never prints row values/PII)
- **Leaked `service_role` JWTs and `sb_secret_` keys** compiled into client JS bundles
- **Hardcoded API secrets** (`sk_live_`, `sk-proj-`, `sk-ant-api03-`, `AKIA...`, `postgres://`) in public bundles
- **Local SQL migration footguns**: `CREATE TABLE` without `ENABLE ROW LEVEL SECURITY`, `USING (true)` / `WITH CHECK (true)` policies, and `SECURITY DEFINER` functions missing `SET search_path`
- **Client-exposed env variable names** (`NEXT_PUBLIC_*` / `VITE_*` referencing `SERVICE_ROLE`, `STRIPE_SECRET`, etc.)
- **Public `.js.map` source maps** and missing baseline browser hardening headers

> Prefer a hosted, no-install browser check? Run it free at **[breachsweep.com/supabase-rls-scanner](https://breachsweep.com/supabase-rls-scanner)** (or **[breachsweep.com/lovable-security-scan](https://breachsweep.com/lovable-security-scan)** for `*.lovable.app` / AI-built apps).

---

## Quickstart (Zero Install, Node.js >= 18)

### 1. Audit a deployed app URL (read-only)

```bash
npx --yes github:VirilePeak/supabase-rls-audit-cli https://your-app.vercel.app
```

### 2. Audit local SQL migrations & frontend code

```bash
npx --yes github:VirilePeak/supabase-rls-audit-cli --dir .
```

### 3. Combine both with CI exit gate + JSON output

```bash
npx --yes github:VirilePeak/supabase-rls-audit-cli \
  --url https://your-app.vercel.app \
  --dir ./supabase/migrations \
  --fail-on high \
  --json
```

---

## GitHub Action (Post-Deploy or PR Gate)

```yaml
name: Supabase RLS Audit
on:
  pull_request:
  workflow_dispatch:

jobs:
  rls-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: VirilePeak/supabase-rls-audit-cli@v1
        with:
          dir: ./supabase/migrations
          # Optional: also audit your staging/preview URL
          # url: https://staging.your-app.com
          fail-on: high
```

---

## CLI Options

| Flag | Default | Description |
| --- | --- | --- |
| `--url <url>` | — | Deployed app URL to scan (read-only) |
| `--dir <path>` | — | Local directory with `.sql` migrations and/or frontend code |
| `--max-tables <n>` | `15` | Max PostgREST tables to probe read-only |
| `--fail-on <level>` | `high` | Exit code `1` on findings `>=` `critical`, `high`, `medium`, `low`, or `none` |
| `--json` | `false` | Emit structured JSON report |
| `--allow-private` | `false` | Allow localhost / private IPs (for local dev only) |

---

## What This Tool Does (and Does Not) Cover

This CLI catches public-surface exposures and static SQL policy patterns in seconds without credentials. It deliberately does **not** claim to prove authenticated multi-tenant isolation:

- Authenticated cross-tenant IDORs (`TO authenticated USING (true)` on live rows)
- Server-side `service_role` bypasses in Next.js API routes, Server Actions, or Edge Functions
- Business-logic flaws (quota races, subscription/plan-tier tampering, webhook replay)

For a technical breakdown of backend `service_role` bypasses, see **[Why Supabase RLS Fails When Your Backend Uses `service_role`](https://breachsweep.com/blog/supabase-rls-service-role-bypass)**. For authenticated two-tenant testing, see **[BreachSweep Tenant Isolation Testing](https://breachsweep.com/tenant-isolation-testing)**.

## Safety & Responsible Use

Only scan applications and domains you own or are explicitly authorized to test. All HTTP requests in URL mode are strictly `GET`/`HEAD` read-only checks, private IP ranges are blocked by default (SSRF guard), secrets are masked in output, and live table row values are never printed.

## License

MIT
