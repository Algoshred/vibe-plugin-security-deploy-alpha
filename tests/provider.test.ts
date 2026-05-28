import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, test } from "bun:test";

import { AlphaSmokeProvider } from "../src/provider.js";
import { ALPHA_SMOKE_VERSION } from "../src/tools-manifest.js";

interface FixtureServer {
  url: string;
  stop: () => void;
}

function startServer(
  handler: (req: Request, url: URL) => Response | Promise<Response>,
): FixtureServer {
  // Bun.serve types live on globalThis.Bun — declared in bun-types.
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const u = new URL(req.url);
      return await handler(req, u);
    },
  });
  return {
    url: `http://${server.hostname}:${server.port}`,
    stop: () => server.stop(true),
  };
}

const baseInput = (config: Record<string, unknown> = {}, workdir = "/tmp") => ({
  runId: "smoke-1",
  vibeId: "v1",
  workspaceId: "w1",
  repoUrl: "x",
  repoLocalPath: "/tmp",
  commit: "c",
  stage: "deploy.alpha" as const,
  profile: { kind: "backend", languages: ["ts"], runtimes: ["bun"] },
  policyLevel: "advisory" as const,
  config,
  workdir,
});

describe("AlphaSmokeProvider", () => {
  test("provider name + stage are immutable identifiers", () => {
    const p = new AlphaSmokeProvider();
    expect(p.name).toBe("alpha-smoke");
    expect(p.stage).toBe("deploy.alpha");
  });

  test("metadata reports the pinned tool version", () => {
    const p = new AlphaSmokeProvider();
    expect(p.toolVersion).toBe(ALPHA_SMOKE_VERSION);
    expect(p.metadata().stage).toBe("deploy.alpha");
    expect(p.metadata().supportedProfiles).toContain("backend");
    expect(p.metadata().supportedProfiles).toContain("frontend");
  });

  test("ensureToolInstalled is a no-op (pure-JS)", async () => {
    const p = new AlphaSmokeProvider();
    await expect(p.ensureToolInstalled()).resolves.toBeUndefined();
  });

  test("cancel() on an unknown run is a no-op", async () => {
    const p = new AlphaSmokeProvider();
    await expect(p.cancel("nonexistent")).resolves.toBeUndefined();
  });

  describe("run() with empty config.urls", () => {
    test("emits a single info finding and no evidence", async () => {
      const p = new AlphaSmokeProvider();
      const result = await p.run(baseInput({}));
      expect(result.status).toBe("succeeded");
      expect(result.findings.length).toBe(1);
      expect(result.findings[0].severity).toBe("info");
      expect(result.findings[0].ruleId).toBe("config.urls.missing");
      expect(result.evidence).toEqual([]);
      expect(result.summary.info).toBe(1);
    });
  });

  describe("run() probing fixture servers", () => {
    let goodServer: FixtureServer;
    let badServer: FixtureServer;
    let workdir: string;

    beforeAll(async () => {
      workdir = await mkdtemp(join(tmpdir(), "alpha-smoke-test-"));

      // Server with all required headers + protected /healthz.
      goodServer = startServer((_req, u) => {
        const headers = new Headers({
          "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
          "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
          "X-Content-Type-Options": "nosniff",
          "X-Frame-Options": "DENY",
        });
        if (u.pathname === "/healthz") {
          headers.set("WWW-Authenticate", 'Bearer realm="healthz"');
          return new Response("unauthorized", { status: 401, headers });
        }
        return new Response("ok", { status: 200, headers });
      });

      // Server missing CSP + HSTS but providing X-Content-Type-Options +
      // X-Frame-Options (so we get exactly 2 findings — medium + medium).
      // /healthz returns 401 to avoid the no-auth finding.
      badServer = startServer((_req, u) => {
        const headers = new Headers({
          "X-Content-Type-Options": "nosniff",
          "X-Frame-Options": "DENY",
        });
        if (u.pathname === "/healthz") {
          return new Response("unauthorized", { status: 401, headers });
        }
        return new Response("ok", { status: 200, headers });
      });
    });

    afterAll(async () => {
      goodServer.stop();
      badServer.stop();
      await rm(workdir, { recursive: true, force: true });
    });

    test("target with all good headers yields zero findings", async () => {
      const p = new AlphaSmokeProvider();
      const result = await p.run(baseInput({ urls: [goodServer.url] }, workdir));
      expect(result.status).toBe("succeeded");
      expect(result.findings.length).toBe(0);
      expect(result.summary).toEqual({
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      });
      // findings.json evidence written
      expect(result.evidence.length).toBe(1);
      expect(result.evidence[0].localPath).toContain("findings.json");
      expect(result.evidence[0].sizeBytes).toBeGreaterThan(0);
      const raw = await readFile(result.evidence[0].localPath, "utf-8");
      const parsed = JSON.parse(raw);
      expect(parsed.probes.length).toBe(1);
      expect(parsed.probes[0].reachable).toBe(true);
    });

    test("target missing CSP + HSTS produces 2 medium findings", async () => {
      const p = new AlphaSmokeProvider();
      const result = await p.run(baseInput({ urls: [badServer.url] }, workdir));
      expect(result.status).toBe("succeeded");
      const mediums = result.findings.filter((f) => f.severity === "medium");
      expect(mediums.length).toBe(2);
      const ruleIds = mediums.map((f) => f.ruleId).sort();
      expect(ruleIds).toEqual(["headers.csp.missing", "headers.hsts.missing"]);
      // Each finding has a stable sha256 fingerprint.
      for (const f of result.findings) {
        expect(f.fingerprint).toMatch(/^[0-9a-f]{64}$/);
        expect(f.category).toBe("config");
      }
    });

    test("unreachable URL emits info finding without throwing", async () => {
      const p = new AlphaSmokeProvider();
      // Use a port that is reliably closed.
      const result = await p.run(baseInput({ urls: ["http://127.0.0.1:1"] }, workdir));
      expect(result.status).toBe("succeeded");
      const unreach = result.findings.filter((f) => f.ruleId === "url.unreachable");
      expect(unreach.length).toBe(1);
      expect(unreach[0].severity).toBe("info");
    });
  });
});
