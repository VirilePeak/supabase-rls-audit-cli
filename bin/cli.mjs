#!/usr/bin/env node
import { auditUrl, auditLocalDir, shouldFail } from "../src/index.mjs";

const VERSION = "1.0.1";

function printHelp() {
  console.log(`supabase-rls-audit-cli v${VERSION}
Zero-dependency, read-only Supabase RLS & JS bundle secret auditor.

Usage:
  npx supabase-rls-audit-cli <url> [options]
  npx supabase-rls-audit-cli --dir ./supabase/migrations [options]
  npx supabase-rls-audit-cli --url https://app.example.com --dir . [options]

Options:
  --url <url>           Deployed app URL to audit (read-only)
  --dir <path>          Local directory with SQL migrations and/or frontend code
  --max-tables <n>      Max PostgREST tables to probe read-only (default: 15)
  --fail-on <level>     Exit 1 on >= severity: critical|high|medium|low|none (default: high)
  --json                Output structured JSON report
  --allow-private       Allow scanning localhost / private IPs (local dev only)
  -v, --version         Print version
  -h, --help            Show this help

Browser scanners (no install): https://breachsweep.com/supabase-rls-scanner
                               https://breachsweep.com/nextjs-security-scanner
Deep-dive guide:               https://breachsweep.com/blog/supabase-rls-service-role-bypass`);
}

function parseArgs(argv) {
  const opts = {
    url: "",
    dir: "",
    maxTables: 15,
    failOn: "high",
    json: false,
    allowPrivate: false,
    help: false,
    version: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "-h" || arg === "--help") opts.help = true;
    else if (arg === "-v" || arg === "--version") opts.version = true;
    else if (arg === "--json") opts.json = true;
    else if (arg === "--allow-private") opts.allowPrivate = true;
    else if (arg === "--url" && argv[i + 1]) opts.url = argv[++i];
    else if (arg === "--dir" && argv[i + 1]) opts.dir = argv[++i];
    else if (arg === "--fail-on" && argv[i + 1]) opts.failOn = argv[++i];
    else if (arg === "--max-tables" && argv[i + 1]) opts.maxTables = Math.max(1, Number(argv[++i]) || 15);
    else if (!arg.startsWith("-") && !opts.url) opts.url = arg;
  }
  return opts;
}

function formatReport(reports) {
  const lines = [];
  lines.push("============================================================");
  lines.push("  supabase-rls-audit (read-only) — by BreachSweep");
  lines.push("============================================================");

  let totalFindings = 0;
  for (const r of reports) {
    lines.push("");
    if (r.mode === "url") {
      lines.push(`Target URL:        ${r.target} (HTTP ${r.status}, ${r.durationMs}ms)`);
      lines.push(`JS Bundles:        ${r.bundlesScanned}`);
      lines.push(`Supabase Project:  ${r.supabaseProject || "none detected"}`);
      if (r.supabaseProject) {
        lines.push(`OpenAPI Surface:   ${r.tablesEnumerated} tables, ${r.rpcsEnumerated} RPCs`);
      }
    } else {
      lines.push(`Local Directory:   ${r.target} (${r.durationMs}ms)`);
      lines.push(`Files Scanned:     ${r.sqlFilesScanned} .sql, ${r.codeFilesScanned} code/env`);
    }

    if (r.findings.length === 0) {
      lines.push("  [PASS] No issues detected by static/unauthenticated checks.");
      continue;
    }

    totalFindings += r.findings.length;
    for (const f of r.findings) {
      lines.push("");
      lines.push(`  [${f.severity}] ${f.title}`);
      lines.push(`    Detail:   ${f.detail}`);
      lines.push(`    Evidence: ${f.evidence}`);
      if (f.remediation) {
        lines.push(`    Fix:\n${f.remediation.split("\n").map((l) => `      ${l}`).join("\n")}`);
      }
    }
  }

  lines.push("");
  lines.push("------------------------------------------------------------");
  lines.push(`Total findings: ${totalFindings}`);
  lines.push("Note: Unauthenticated checks cannot prove authenticated cross-tenant RLS isolation.");
  lines.push("Browser version: https://breachsweep.com/supabase-rls-scanner");
  return lines.join("\n");
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.version) {
    console.log(VERSION);
    return;
  }
  if (opts.help || (!opts.url && !opts.dir)) {
    printHelp();
    process.exit(opts.help ? 0 : 2);
  }

  const reports = [];
  if (opts.url) {
    reports.push(await auditUrl(opts.url, { maxTables: opts.maxTables, allowPrivate: opts.allowPrivate }));
  }
  if (opts.dir) {
    reports.push(await auditLocalDir(opts.dir));
  }

  const allFindings = reports.flatMap((r) => r.findings);
  const failed = shouldFail(allFindings, opts.failOn);

  if (opts.json) {
    console.log(JSON.stringify({ version: VERSION, failOn: opts.failOn, failed, reports }, null, 2));
  } else {
    console.log(formatReport(reports));
  }

  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(2);
});
