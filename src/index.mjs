import dns from "node:dns/promises";
import fs from "node:fs/promises";
import path from "node:path";

export const SEVERITY_RANK = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  PASS: 0,
};

const USER_AGENT = "supabase-rls-audit-cli/1.0 (+https://breachsweep.com/supabase-rls-scanner)";

const SECRET_RULES = [
  { id: "supabase-secret-key", name: "Supabase Secret Key (sb_secret_)", severity: "CRITICAL", regex: /\bsb_secret_[a-zA-Z0-9_-]{20,}\b/ },
  { id: "stripe-live-secret", name: "Stripe Live Secret Key (sk_live_/rk_live_)", severity: "CRITICAL", regex: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/ },
  { id: "openai-secret-key", name: "OpenAI API Secret Key (sk-proj-/sk-)", severity: "CRITICAL", regex: /\bsk-(?:proj-)?[a-zA-Z0-9_-]{36,}\b/ },
  { id: "anthropic-secret-key", name: "Anthropic Claude API Key (sk-ant-)", severity: "CRITICAL", regex: /\bsk-ant-api03-[a-zA-Z0-9_-]{36,}\b/ },
  { id: "aws-access-key", name: "AWS Access Key ID (AKIA...)", severity: "HIGH", regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: "postgres-uri", name: "PostgreSQL Connection URI (postgres://)", severity: "CRITICAL", regex: /postgres(?:ql)?:\/\/[^"'\s<>]{12,}/ },
];

const PUBLIC_SECRET_ENV_REGEX =
  /\b((?:NEXT_PUBLIC_|VITE_)[A-Z0-9_]*(?:SERVICE_ROLE|SB_SECRET|STRIPE_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY|PRIVATE_KEY|DATABASE_URL)[A-Z0-9_]*)\b/g;

export function isPrivateIp(ip) {
  if (!ip) return true;
  const normalized = ip.replace(/^::ffff:/i, "");
  return (
    normalized.startsWith("10.") ||
    normalized.startsWith("127.") ||
    normalized.startsWith("192.168.") ||
    normalized.startsWith("169.254.") ||
    normalized.startsWith("0.") ||
    normalized === "::1" ||
    normalized === "::" ||
    normalized.toLowerCase().startsWith("fc") ||
    normalized.toLowerCase().startsWith("fd") ||
    normalized.toLowerCase().startsWith("fe80:") ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(normalized)
  );
}

export function maskSecret(raw) {
  if (!raw) return "";
  if (raw.length <= 12) return `${raw.slice(0, 4)}...`;
  return `${raw.slice(0, 8)}...${raw.slice(-4)}`;
}

export function decodeSupabaseJwt(jwt) {
  try {
    const parts = jwt.split(".");
    if (parts.length !== 3) return null;
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    const iss = String(payload.iss || "").toLowerCase();
    const role = String(payload.role || "");
    if (iss.includes("supabase") || role === "anon" || role === "service_role") {
      return {
        role,
        ref: payload.ref ? String(payload.ref) : undefined,
        iss: payload.iss ? String(payload.iss) : undefined,
      };
    }
  } catch {
    return null;
  }
  return null;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 7000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

function normalizeTargetUrl(input) {
  const trimmed = String(input || "").trim();
  if (!trimmed) throw new Error("Target URL is empty");
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const parsed = new URL(withScheme);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http:// and https:// URLs are supported");
  }
  return parsed;
}

function extractAssetUrls(html, targetOrigin, hostname) {
  const urls = [];
  const seen = new Set();
  const patterns = [
    /<script[^>]+src=["']([^"']+\.m?js(?:\?[^"']*)?)["']/gi,
    /<link[^>]+rel=["']modulepreload["'][^>]+href=["']([^"']+\.m?js(?:\?[^"']*)?)["']/gi,
    /<link[^>]+href=["']([^"']+\.m?js(?:\?[^"']*)?)["'][^>]+rel=["']modulepreload["']/gi,
  ];
  for (const regex of patterns) {
    let match;
    while ((match = regex.exec(html)) !== null) {
      try {
        const full = new URL(match[1], targetOrigin);
        if (full.hostname === hostname && !seen.has(full.toString())) {
          seen.add(full.toString());
          urls.push(full.toString());
        }
      } catch {
        // ignore invalid asset URL
      }
    }
  }
  return urls;
}

function buildRlsSqlFix(tables) {
  return tables
    .map(
      (t) =>
        `ALTER TABLE public.${t} ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "tenant_members_read_${t}"\n  ON public.${t} FOR SELECT TO authenticated\n  USING (auth.uid() = user_id);`
    )
    .join("\n\n");
}

export async function auditUrl(rawUrl, options = {}) {
  const {
    allowPrivate = false,
    maxBundles = 10,
    maxTables = 15,
    timeoutMs = 7000,
    supabaseUrlOverride = null,
  } = options;

  const startedAt = Date.now();
  const parsed = normalizeTargetUrl(rawUrl);

  if (!allowPrivate) {
    const addresses = await dns.lookup(parsed.hostname, { all: true });
    if (!addresses.length || addresses.some((a) => isPrivateIp(a.address))) {
      throw new Error(`Refusing to scan private/non-public host: ${parsed.hostname} (pass --allow-private for local dev)`);
    }
  }

  const targetOrigin = parsed.origin;
  const res = await fetchWithTimeout(
    parsed.toString(),
    { headers: { "User-Agent": USER_AGENT, Accept: "text/html,*/*" }, redirect: "follow" },
    timeoutMs
  );
  const headers = {};
  res.headers.forEach((v, k) => {
    headers[k.toLowerCase()] = v;
  });
  const html = (await res.text()).slice(0, 400000);

  const bundleUrls = extractAssetUrls(html, targetOrigin, parsed.hostname).slice(0, maxBundles);
  const corpora = [{ source: parsed.pathname || "/", text: html }];
  const bundlesScanned = [];

  await Promise.all(
    bundleUrls.map(async (bUrl) => {
      try {
        const br = await fetchWithTimeout(bUrl, { headers: { "User-Agent": USER_AGENT } }, Math.min(timeoutMs, 6000));
        if (br.ok) {
          const text = (await br.text()).slice(0, 500000);
          const pathname = new URL(bUrl).pathname;
          bundlesScanned.push(pathname);
          corpora.push({ source: pathname, text });
        }
      } catch {
        // ignore individual bundle errors
      }
    })
  );

  const findings = [];
  const supaUrls = new Set();
  if (supabaseUrlOverride) supaUrls.add(supabaseUrlOverride.replace(/\/+$/, ""));

  const jwtCandidates = new Set();
  const supaUrlRegex = /https:\/\/[a-z0-9]{15,25}\.supabase\.co/gi;
  const jwtRegex = /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}/g;

  for (const corpus of corpora) {
    const uMatches = corpus.text.match(supaUrlRegex) || [];
    for (const u of uMatches) supaUrls.add(u.toLowerCase());
    const jMatches = corpus.text.match(jwtRegex) || [];
    for (const j of jMatches) jwtCandidates.add(j);
  }

  let anonKey = "";
  let leakedServiceRole = "";
  for (const tok of jwtCandidates) {
    const decoded = decodeSupabaseJwt(tok);
    if (!decoded) continue;
    if (decoded.role === "service_role") leakedServiceRole = tok;
    if (decoded.role === "anon" && !anonKey) anonKey = tok;
    if (decoded.ref && supaUrls.size === 0) supaUrls.add(`https://${decoded.ref}.supabase.co`);
  }

  const supabaseProject = Array.from(supaUrls)[0] || null;
  let exposedTables = [];
  let exposedRpcs = [];
  const readableTables = [];

  if (leakedServiceRole) {
    findings.push({
      id: "supabase-service-role-leak",
      severity: "CRITICAL",
      title: "Supabase service_role JWT leaked in public client bundle",
      detail: "A JWT with role='service_role' was found in public HTML/JS. This key bypasses all PostgreSQL Row Level Security policies.",
      evidence: `Decoded JWT role='service_role' (${maskSecret(leakedServiceRole)})`,
      remediation: "Rotate the service_role key immediately in Supabase Dashboard -> Project Settings -> API and remove any NEXT_PUBLIC_/VITE_ prefix.",
    });
  }

  if (supabaseProject && anonKey) {
    try {
      const specRes = await fetchWithTimeout(
        `${supabaseProject}/rest/v1/`,
        {
          headers: {
            apikey: anonKey,
            Authorization: `Bearer ${anonKey}`,
            "User-Agent": USER_AGENT,
          },
        },
        timeoutMs
      );
      if (specRes.ok) {
        const spec = await specRes.json().catch(() => null);
        const defs = Object.keys(spec?.definitions || {});
        const paths = Object.keys(spec?.paths || {});
        exposedTables = defs.filter((d) => !d.startsWith("rpc/"));
        exposedRpcs = paths.filter((p) => p.startsWith("/rpc/")).map((p) => p.replace(/^\/rpc\//, ""));

        for (const table of exposedTables.slice(0, maxTables)) {
          try {
            const tr = await fetchWithTimeout(
              `${supabaseProject}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`,
              {
                headers: {
                  apikey: anonKey,
                  Authorization: `Bearer ${anonKey}`,
                  "User-Agent": USER_AGENT,
                },
              },
              Math.min(timeoutMs, 5000)
            );
            if (tr.ok) {
              const rows = await tr.json().catch(() => null);
              if (Array.isArray(rows) && rows.length > 0) {
                const columns = rows[0] && typeof rows[0] === "object" ? Object.keys(rows[0]) : [];
                readableTables.push({ table, columns });
              }
            }
          } catch {
            // ignore individual table errors
          }
        }
      }
    } catch {
      // ignore PostgREST unreachable errors
    }

    if (readableTables.length > 0) {
      const names = readableTables.map((r) => r.table);
      findings.push({
        id: "supabase-public-readable-tables",
        severity: "CRITICAL",
        title: `${readableTables.length} Supabase table(s) publicly readable via anon key (${names.join(", ")})`,
        detail: `Unauthenticated GET requests against ${supabaseProject}/rest/v1/ returned rows using the frontend anon key. Row values are not printed; column names only.`,
        evidence: readableTables
          .map((r) => `${r.table} (columns: ${r.columns.slice(0, 8).join(", ") || "unknown"})`)
          .join("; "),
        remediation: buildRlsSqlFix(names),
      });
    } else if (exposedTables.length > 0) {
      findings.push({
        id: "supabase-schema-enumerable",
        severity: "MEDIUM",
        title: `Supabase PostgREST schema enumerable (${exposedTables.length} tables, ${exposedRpcs.length} RPCs)`,
        detail: `No unauthenticated rows returned for the first ${Math.min(exposedTables.length, maxTables)} tables, but table/RPC names are exposed via OpenAPI. Verify authenticated cross-tenant policies and SECURITY DEFINER RPCs.`,
        evidence: `Tables: ${exposedTables.slice(0, 10).join(", ")}${exposedRpcs.length ? ` | RPCs: ${exposedRpcs.slice(0, 8).join(", ")}` : ""}`,
        remediation: "Disable PostgREST OpenAPI schema exposure if unused and audit every table for tenant-scoped authenticated policies.",
      });
    }
  }

  // Client bundle secret scan
  const seenSecrets = new Set();
  for (const corpus of corpora) {
    for (const rule of SECRET_RULES) {
      const match = corpus.text.match(rule.regex);
      if (match && !seenSecrets.has(rule.id)) {
        seenSecrets.add(rule.id);
        findings.push({
          id: rule.id,
          severity: rule.severity,
          title: `Leaked ${rule.name} in public client payload`,
          detail: `High-entropy secret matched in ${corpus.source}. Move this credential to a server-only API route or Supabase Edge Function.`,
          evidence: `${corpus.source} -> ${maskSecret(match[0])}`,
          remediation: "Rotate the exposed key immediately and remove NEXT_PUBLIC_/VITE_ prefixes from server secrets.",
        });
      }
    }
  }

  // Source map check on first bundle
  if (bundleUrls.length > 0) {
    try {
      const mapUrl = `${bundleUrls[0].split("?")[0]}.map`;
      const mr = await fetchWithTimeout(mapUrl, { method: "HEAD", headers: { "User-Agent": USER_AGENT } }, 3500);
      if (mr.status === 200) {
        const mapPath = new URL(mapUrl).pathname;
        findings.push({
          id: "public-source-map",
          severity: "MEDIUM",
          title: `Public JavaScript source map exposed (${mapPath})`,
          detail: "Unminified frontend source code can be reconstructed from production .js.map files.",
          evidence: `HEAD ${mapPath} -> HTTP 200`,
          remediation: "Set productionBrowserSourceMaps: false in next.config or build.sourcemap: false in vite.config.",
        });
      }
    } catch {
      // ignore
    }
  }

  // Baseline browser hardening headers
  const missingHeaders = [];
  if (headers["access-control-allow-origin"] === "*") missingHeaders.push("Wildcard CORS (Access-Control-Allow-Origin: *)");
  if (!headers["strict-transport-security"]) missingHeaders.push("Strict-Transport-Security");
  if (!headers["content-security-policy"]) missingHeaders.push("Content-Security-Policy");
  if (!headers["x-frame-options"] && !(headers["content-security-policy"] || "").includes("frame-ancestors")) {
    missingHeaders.push("X-Frame-Options / frame-ancestors");
  }
  if (missingHeaders.length > 0) {
    findings.push({
      id: "missing-security-headers",
      severity: "LOW",
      title: `Missing baseline security headers (${missingHeaders.length})`,
      detail: `Default hosting configs often omit browser hardening headers.`,
      evidence: missingHeaders.join(", "),
      remediation: "Configure HSTS, CSP (with frame-ancestors), and X-Content-Type-Options: nosniff in next.config or vercel.json.",
    });
  }

  return {
    mode: "url",
    target: targetOrigin,
    status: res.status,
    durationMs: Date.now() - startedAt,
    bundlesScanned: bundlesScanned.length,
    supabaseProject,
    tablesEnumerated: exposedTables.length,
    rpcsEnumerated: exposedRpcs.length,
    findings,
  };
}

async function walkFiles(dirPath, results = []) {
  const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", ".vercel", "coverage"]);
  const entries = await fs.readdir(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      await walkFiles(full, results);
    } else if (entry.isFile()) {
      results.push(full);
    }
  }
  return results;
}

export async function auditLocalDir(dirPath) {
  const startedAt = Date.now();
  const absDir = path.resolve(dirPath);
  const files = await walkFiles(absDir);
  const sqlFiles = files.filter((f) => f.endsWith(".sql")).sort();
  const codeFiles = files.filter(
    (f) => /\.(?:env(?:\.[^/]+)?|ts|tsx|js|jsx|mjs|cjs)$/.test(f) && !/(?:^|[\/])(?:__tests__[\/]|[^\/]+\.(?:test|spec)\.[^\/]+$)/.test(f)
  );

  const findings = [];
  const createdTables = new Map();
  const rlsEnabledTables = new Set();

  for (const sqlFile of sqlFiles) {
    const content = await fs.readFile(sqlFile, "utf8");
    const rel = path.relative(absDir, sqlFile) || path.basename(sqlFile);

    // Track CREATE TABLE public.xxx or CREATE TABLE xxx
    const createRegex = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?"?([a-zA-Z0-9_]+)"?/gi;
    let cm;
    while ((cm = createRegex.exec(content)) !== null) {
      const tbl = cm[1].toLowerCase();
      if (!createdTables.has(tbl)) createdTables.set(tbl, rel);
    }

    // Track ALTER TABLE ... ENABLE ROW LEVEL SECURITY
    const rlsRegex = /ALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?(?:public\.)?"?([a-zA-Z0-9_]+)"?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;
    let rm;
    while ((rm = rlsRegex.exec(content)) !== null) {
      rlsEnabledTables.add(rm[1].toLowerCase());
    }

    // Check permissive USING (true) / WITH CHECK (true) policies
    const policyRegex = /CREATE\s+POLICY\s+([^;]+);/gis;
    let pm;
    while ((pm = policyRegex.exec(content)) !== null) {
      const stmt = pm[0];
      const hasOpenPredicate = /\b(?:USING|WITH\s+CHECK)\s*\(\s*true\s*\)/i.test(stmt);
      if (!hasOpenPredicate) continue;
      const targetsAnon = /\bTO\s+(?:public|anon)\b/i.test(stmt) || !/\bTO\s+authenticated\b/i.test(stmt);
      const nameMatch = stmt.match(/CREATE\s+POLICY\s+"?([^"\s]+)"?\s+ON\s+(?:public\.)?"?([a-zA-Z0-9_]+)"?/i);
      const policyLabel = nameMatch ? `${nameMatch[1]} on ${nameMatch[2]}` : "policy";
      findings.push({
        id: targetsAnon ? "sql-permissive-anon-policy" : "sql-permissive-auth-policy",
        severity: targetsAnon ? "CRITICAL" : "HIGH",
        title: `Permissive RLS policy with open true predicate (${policyLabel})`,
        detail: targetsAnon
          ? "Policy allows unauthenticated/public access via USING (true) or WITH CHECK (true)."
          : "Policy grants every authenticated user cross-tenant access via USING (true) or WITH CHECK (true).",
        evidence: `${rel}`,
        remediation: "Scope USING / WITH CHECK to auth.uid() or a tenant membership subquery.",
      });
    }

    // Check SECURITY DEFINER functions missing SET search_path (handles LANGUAGE before or after body)
    const fnStartRegex = /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([a-zA-Z0-9_."()]+)/gi;
    const fnStarts = [];
    let fm;
    while ((fm = fnStartRegex.exec(content)) !== null) {
      fnStarts.push({ name: fm[1], index: fm.index });
    }
    for (let i = 0; i < fnStarts.length; i += 1) {
      const start = fnStarts[i].index;
      const end = i + 1 < fnStarts.length ? fnStarts[i + 1].index : content.length;
      const block = content.slice(start, end);
      if (/\bSECURITY\s+DEFINER\b/i.test(block) && !/\bSET\s+search_path\s*(?:=|TO\b)/i.test(block)) {
        findings.push({
          id: "sql-security-definer-search-path",
          severity: "HIGH",
          title: `SECURITY DEFINER function without SET search_path (${fnStarts[i].name})`,
          detail: "SECURITY DEFINER functions bypass caller RLS and are vulnerable to search_path hijacking unless search_path is pinned.",
          evidence: `${rel}`,
          remediation: "Add 'SET search_path = public, pg_temp' and explicitly verify auth.uid() inside the function body.",
        });
      }
    }
  }

  const tablesWithoutRls = [];
  for (const [tbl, file] of createdTables.entries()) {
    if (!rlsEnabledTables.has(tbl)) {
      tablesWithoutRls.push({ table: tbl, file });
    }
  }
  if (tablesWithoutRls.length > 0) {
    findings.push({
      id: "sql-tables-without-rls",
      severity: "CRITICAL",
      title: `${tablesWithoutRls.length} table(s) created without ENABLE ROW LEVEL SECURITY`,
      detail: "Tables created in SQL migrations without RLS enabled can be exposed over PostgREST depending on schema grants.",
      evidence: tablesWithoutRls.map((t) => `${t.table} (${t.file})`).join(", "),
      remediation: buildRlsSqlFix(tablesWithoutRls.map((t) => t.table)),
    });
  }

  // Check frontend / env files for NEXT_PUBLIC_ / VITE_ secret variable names (never logs values)
  const seenEnvLeaks = new Set();
  for (const file of codeFiles) {
    const content = await fs.readFile(file, "utf8").catch(() => "");
    const rel = path.relative(absDir, file) || path.basename(file);
    PUBLIC_SECRET_ENV_REGEX.lastIndex = 0;
    let em;
    while ((em = PUBLIC_SECRET_ENV_REGEX.exec(content)) !== null) {
      const varName = em[1];
      const key = `${rel}:${varName}`;
      if (seenEnvLeaks.has(key)) continue;
      seenEnvLeaks.add(key);
      findings.push({
        id: "public-env-secret-prefix",
        severity: "CRITICAL",
        title: `Client-exposed secret env variable name (${varName})`,
        detail: "Variables prefixed with NEXT_PUBLIC_ or VITE_ are inlined into browser JS bundles at build time.",
        evidence: `${rel} -> ${varName}`,
        remediation: "Remove the NEXT_PUBLIC_ / VITE_ prefix and read this credential only in server-side routes or Edge Functions.",
      });
    }
  }

  return {
    mode: "dir",
    target: absDir,
    durationMs: Date.now() - startedAt,
    sqlFilesScanned: sqlFiles.length,
    codeFilesScanned: codeFiles.length,
    findings,
  };
}

export function shouldFail(findings, failOn = "high") {
  const level = String(failOn || "high").toLowerCase();
  if (level === "none") return false;
  const threshold = SEVERITY_RANK[level.toUpperCase()] ?? SEVERITY_RANK.HIGH;
  return findings.some((f) => (SEVERITY_RANK[f.severity] || 0) >= threshold);
}
