import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { auditUrl, auditLocalDir, decodeSupabaseJwt, isPrivateIp, maskSecret, shouldFail } from "../src/index.mjs";

function makeJwt(payload) {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${header}.${body}.dummy_signature_for_unit_test_123456`;
}

test("decodeSupabaseJwt distinguishes anon and service_role", () => {
  const anon = makeJwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon" });
  const sr = makeJwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "service_role" });
  assert.equal(decodeSupabaseJwt(anon)?.role, "anon");
  assert.equal(decodeSupabaseJwt(anon)?.ref, "abcdefghijklmnopqrst");
  assert.equal(decodeSupabaseJwt(sr)?.role, "service_role");
});

test("isPrivateIp blocks RFC1918 and loopback addresses", () => {
  assert.equal(isPrivateIp("127.0.0.1"), true);
  assert.equal(isPrivateIp("10.0.0.5"), true);
  assert.equal(isPrivateIp("192.168.1.1"), true);
  assert.equal(isPrivateIp("172.16.0.1"), true);
  assert.equal(isPrivateIp("::1"), true);
  assert.equal(isPrivateIp("93.184.216.34"), false);
});

test("maskSecret never returns full secret", () => {
  const s = "sb_secret_1234567890abcdefghijklmnop";
  const masked = maskSecret(s);
  assert.ok(!masked.includes("1234567890"));
  assert.equal(masked, "sb_secre...mnop");
});

test("auditUrl flags public readable Supabase tables, leaked bundle keys, and sourcemaps without leaking row values", async () => {
  const anonJwt = makeJwt({ iss: "supabase", ref: "mockproj1234567890", role: "anon" });
  const fakeStripe = "sk_live_" + "A".repeat(24);

  const server = http.createServer((req, res) => {
    if (req.url === "/") {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<html><head><script src='/assets/app.js'></script></head><body>ok</body></html>");
      return;
    }
    if (req.url === "/assets/app.js") {
      res.writeHead(200, { "Content-Type": "application/javascript" });
      res.end(`const key="${anonJwt}"; const stripe="${fakeStripe}";`);
      return;
    }
    if (req.url === "/assets/app.js.map") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{}");
      return;
    }
    if (req.url === "/rest/v1/") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ definitions: { users: {}, invoices: {} }, paths: { "/rpc/get_admin": {} } }));
      return;
    }
    if (req.url?.startsWith("/rest/v1/users")) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify([{ id: 1, email: "secret-pii@example.com", plan: "pro" }]));
      return;
    }
    if (req.url?.startsWith("/rest/v1/invoices")) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify([]));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;

  try {
    await assert.rejects(() => auditUrl(base), /Refusing to scan private/);

    const report = await auditUrl(base, { allowPrivate: true, supabaseUrlOverride: base });
    const ids = report.findings.map((f) => f.id);
    assert.ok(ids.includes("supabase-public-readable-tables"));
    assert.ok(ids.includes("stripe-live-secret"));
    assert.ok(ids.includes("public-source-map"));
    assert.equal(report.tablesEnumerated, 2);
    assert.equal(report.rpcsEnumerated, 1);

    const serialized = JSON.stringify(report);
    assert.ok(!serialized.includes("secret-pii@example.com"), "Must never echo live row values");
    assert.ok(!serialized.includes(fakeStripe), "Must never echo full secret");
    assert.equal(shouldFail(report.findings, "critical"), true);
  } finally {
    server.close();
  }
});

test("auditLocalDir detects tables without RLS, USING (true) policies, SECURITY DEFINER without search_path, and NEXT_PUBLIC_ secret env names", async () => {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "supa-rls-audit-"));
  try {
    await fs.writeFile(
      path.join(tmp, "001_init.sql"),
      `CREATE TABLE public.orders (id uuid primary key, user_id uuid);
CREATE TABLE public.profiles (id uuid primary key);
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "open_profiles" ON public.profiles FOR SELECT TO authenticated USING (true);
CREATE FUNCTION public.elevated_lookup() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN END; $$;
CREATE FUNCTION public.safe_lookup() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$ BEGIN END; $$;`
    );
    await fs.writeFile(
      path.join(tmp, "client.ts"),
      `export const adminKey = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;`
    );

    const report = await auditLocalDir(tmp);
    const ids = report.findings.map((f) => f.id);
    assert.ok(ids.includes("sql-tables-without-rls"));
    assert.ok(ids.includes("sql-permissive-auth-policy"));
    assert.equal(report.findings.filter((f) => f.id === "sql-security-definer-search-path").length, 1);
    assert.ok(ids.includes("public-env-secret-prefix"));
    assert.equal(shouldFail(report.findings, "high"), true);
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});
