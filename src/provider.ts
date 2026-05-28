/**
 * AlphaSmokeProvider — implements SecurityProvider for stage `deploy.alpha`.
 *
 * Pure-JS provider — no external binary, no Docker, no subprocess.
 *
 * For each URL in `input.config.urls` the provider performs a HEAD probe
 * (10s timeout) and a follow-up GET against `${url}/healthz` (5s timeout)
 * and emits one NormalizedFinding per failing check. The full result set
 * is also surfaced as a `findings.json` evidence artifact.
 *
 * Checks:
 *  - `headers.hsts.missing`        — `Strict-Transport-Security` absent          (medium)
 *  - `headers.csp.missing`         — `Content-Security-Policy` absent             (medium)
 *  - `headers.xcto.missing`        — `X-Content-Type-Options: nosniff` absent     (low)
 *  - `headers.frame-ancestors.missing` — no `X-Frame-Options` AND CSP lacks
 *                                    `frame-ancestors`                           (low)
 *  - `healthz.no-auth`             — `/healthz` returns 200 with no auth
 *                                    challenge                                   (low)
 *  - `healthz.unreachable`         — `/healthz` 5xx / refused                    (info)
 *  - `url.unreachable`             — HEAD request threw (DNS/refused/TLS)        (info)
 *  - `config.urls.missing`         — empty/missing `urls` config                 (info)
 */
import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { HostServices } from "@vibecontrols/plugin-sdk/contract";
import type {
  NormalizedFinding,
  ScanEvidenceArtifact,
  SecurityProvider,
  SecurityProviderMetadata,
  SecurityScanInput,
  SecurityScanResult,
  SecurityScanSummary,
  SecurityStage,
} from "@vibecontrols/vibe-plugin-security/types";

import { ALPHA_SMOKE_VERSION } from "./tools-manifest.js";

interface AlphaSmokeConfig {
  urls?: string[];
  healthzPath?: string;
  headTimeoutMs?: number;
  healthzTimeoutMs?: number;
  maxRedirects?: number;
}

interface ProbeResult {
  url: string;
  reachable: boolean;
  status?: number;
  headers?: Record<string, string>;
  healthz?: {
    status?: number;
    reachable: boolean;
    hasAuthChallenge: boolean;
    error?: string;
  };
  error?: string;
  durationMs: number;
}

const DEFAULT_HEAD_TIMEOUT_MS = 10_000;
const DEFAULT_HEALTHZ_TIMEOUT_MS = 5_000;
const DEFAULT_HEALTHZ_PATH = "/healthz";
const DEFAULT_MAX_REDIRECTS = 2;

export class AlphaSmokeProvider implements SecurityProvider {
  readonly name = "alpha-smoke";
  readonly stage: SecurityStage = "deploy.alpha";
  readonly toolVersion = ALPHA_SMOKE_VERSION;

  private host?: HostServices;
  private activeControllers = new Map<string, AbortController[]>();

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    // Pure-JS provider — no external binary to install. Uses native fetch.
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    const startedAt = Date.now();
    const cfg = (input.config as AlphaSmokeConfig) ?? {};
    const urls = Array.isArray(cfg.urls) ? cfg.urls.filter((u) => typeof u === "string") : [];
    const healthzPath = cfg.healthzPath ?? DEFAULT_HEALTHZ_PATH;
    const headTimeoutMs = cfg.headTimeoutMs ?? DEFAULT_HEAD_TIMEOUT_MS;
    const healthzTimeoutMs = cfg.healthzTimeoutMs ?? DEFAULT_HEALTHZ_TIMEOUT_MS;
    const maxRedirects = cfg.maxRedirects ?? DEFAULT_MAX_REDIRECTS;

    input.onProgress?.({ pct: 5, message: "deploy.alpha smoke checks starting" });

    // Empty-urls path — emit a single info finding, no evidence artifact.
    if (urls.length === 0) {
      const findings: NormalizedFinding[] = [
        {
          fingerprint: fp("config.urls.missing", "<none>"),
          ruleId: "config.urls.missing",
          title: "No URLs configured for alpha smoke",
          severity: "info",
          category: "config",
          description:
            "deploy.alpha: no `urls` configured. Provider returned successfully without probing.",
          remediation:
            "Set `config.urls` to the list of alpha-environment URLs to smoke-test (e.g. https://alphaapp.vibecontrols.com).",
        },
      ];
      input.onProgress?.({ pct: 100, message: "No URLs configured — nothing to probe" });
      return {
        runId: input.runId,
        status: "succeeded",
        findings,
        evidence: [],
        durationMs: Date.now() - startedAt,
        summary: summarize(findings),
      };
    }

    const controllers: AbortController[] = [];
    this.activeControllers.set(input.runId, controllers);

    const probeResults: ProbeResult[] = [];
    const findings: NormalizedFinding[] = [];

    try {
      const total = urls.length;
      for (let i = 0; i < urls.length; i++) {
        const url = urls[i];
        const pct = Math.floor(10 + ((i + 1) / total) * 80);
        input.onProgress?.({ pct, message: `Probing ${url}` });

        const probe = await probeUrl(url, {
          headTimeoutMs,
          healthzTimeoutMs,
          healthzPath,
          maxRedirects,
          controllers,
        });
        probeResults.push(probe);
        findings.push(...buildFindings(url, probe));
      }
    } finally {
      this.activeControllers.delete(input.runId);
    }

    // Emit findings.json evidence artifact. We tag it as "sarif" because
    // the SecurityEvidenceType union does not include a generic JSON type;
    // the artifact shape is documented in this provider's README.
    const evidence: ScanEvidenceArtifact[] = [];
    try {
      const evidencePath = join(input.workdir, "findings.json");
      const payload = JSON.stringify(
        {
          provider: this.name,
          toolVersion: this.toolVersion,
          runId: input.runId,
          stage: input.stage,
          generatedAt: new Date().toISOString(),
          probes: probeResults,
          findings,
        },
        null,
        2,
      );
      await writeFile(evidencePath, payload, "utf-8");
      const sha256 = createHash("sha256").update(payload).digest("hex");
      evidence.push({
        type: "sarif",
        localPath: evidencePath,
        sha256,
        sizeBytes: Buffer.byteLength(payload, "utf-8"),
      });
    } catch (err) {
      this.host?.logger?.warn?.(
        "alpha-smoke",
        `failed to write findings.json evidence: ${String(err)}`,
      );
    }

    input.onProgress?.({ pct: 100, message: "Smoke checks complete" });

    return {
      runId: input.runId,
      status: "succeeded",
      findings,
      evidence,
      durationMs: Date.now() - startedAt,
      summary: summarize(findings),
    };
  }

  async cancel(runId: string): Promise<void> {
    const controllers = this.activeControllers.get(runId);
    if (!controllers) return;
    for (const c of controllers) {
      try {
        c.abort();
      } catch {
        /* already aborted */
      }
    }
    this.activeControllers.delete(runId);
  }

  metadata(): SecurityProviderMetadata {
    return {
      stage: this.stage,
      supportedProfiles: ["backend", "frontend", "cli", "container"],
      toolVersion: this.toolVersion,
      description: "Pure-JS smoke checks (TLS, security headers, /healthz) for deploy.alpha.",
    };
  }
}

interface ProbeOptions {
  headTimeoutMs: number;
  healthzTimeoutMs: number;
  healthzPath: string;
  maxRedirects: number;
  controllers: AbortController[];
}

async function probeUrl(url: string, opts: ProbeOptions): Promise<ProbeResult> {
  const startedAt = Date.now();
  try {
    const headRes = await fetchWithRedirects(url, "HEAD", opts.headTimeoutMs, opts);
    const headers = headersToObject(headRes.headers);
    const healthzUrl = joinUrl(url, opts.healthzPath);
    const healthz = await probeHealthz(healthzUrl, opts);

    return {
      url,
      reachable: true,
      status: headRes.status,
      headers,
      healthz,
      durationMs: Date.now() - startedAt,
    };
  } catch (err) {
    return {
      url,
      reachable: false,
      error: errMessage(err),
      durationMs: Date.now() - startedAt,
    };
  }
}

async function probeHealthz(url: string, opts: ProbeOptions): Promise<ProbeResult["healthz"]> {
  const ctrl = new AbortController();
  opts.controllers.push(ctrl);
  const t = setTimeout(() => ctrl.abort(), opts.healthzTimeoutMs);
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: ctrl.signal,
    });
    // Drain body to free the connection — we only inspect headers + status.
    try {
      await res.body?.cancel?.();
    } catch {
      /* ignore */
    }
    const hasAuthChallenge =
      res.status === 401 || res.status === 403 || res.headers.has("www-authenticate");
    return {
      status: res.status,
      reachable: true,
      hasAuthChallenge,
    };
  } catch (err) {
    return {
      reachable: false,
      hasAuthChallenge: false,
      error: errMessage(err),
    };
  } finally {
    clearTimeout(t);
  }
}

async function fetchWithRedirects(
  url: string,
  method: "HEAD" | "GET",
  timeoutMs: number,
  opts: ProbeOptions,
): Promise<Response> {
  let current = url;
  for (let hop = 0; hop <= opts.maxRedirects; hop++) {
    const ctrl = new AbortController();
    opts.controllers.push(ctrl);
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(current, { method, redirect: "manual", signal: ctrl.signal });
      if (res.status >= 300 && res.status < 400 && res.headers.has("location")) {
        if (hop === opts.maxRedirects) {
          // Too many hops — return the last redirect response so caller can
          // still inspect status/headers; further checks degrade gracefully.
          return res;
        }
        const next = new URL(res.headers.get("location") ?? "", current).toString();
        current = next;
        continue;
      }
      return res;
    } finally {
      clearTimeout(t);
    }
  }
  // Should never reach here, but TS wants a return.
  throw new Error(`fetchWithRedirects: exceeded ${opts.maxRedirects} redirects`);
}

function buildFindings(url: string, probe: ProbeResult): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];

  // Unreachable host — emit info finding, skip header checks.
  if (!probe.reachable) {
    let host = url;
    try {
      host = new URL(url).host;
    } catch {
      /* keep original */
    }
    findings.push({
      fingerprint: fp("url.unreachable", url),
      ruleId: "url.unreachable",
      title: `Alpha URL unreachable: ${host}`,
      severity: "info",
      category: "config",
      description: `HEAD ${url} failed: ${probe.error ?? "unknown error"}`,
      remediation:
        "Verify DNS, network reachability, and TLS certificate validity for the alpha host.",
    });
    return findings;
  }

  const headers = probe.headers ?? {};

  // Strict-Transport-Security
  if (!headers["strict-transport-security"]) {
    findings.push({
      fingerprint: fp("headers.hsts.missing", url),
      ruleId: "headers.hsts.missing",
      title: `Missing Strict-Transport-Security header on ${url}`,
      severity: "medium",
      category: "config",
      description:
        "Response is missing the `Strict-Transport-Security` header. Without HSTS, browsers may downgrade to HTTP on the first visit, exposing users to SSL stripping.",
      remediation:
        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` (and `preload` once verified) on every HTTPS response.",
    });
  }

  // Content-Security-Policy
  if (!headers["content-security-policy"]) {
    findings.push({
      fingerprint: fp("headers.csp.missing", url),
      ruleId: "headers.csp.missing",
      title: `Missing Content-Security-Policy header on ${url}`,
      severity: "medium",
      category: "config",
      description:
        "Response is missing the `Content-Security-Policy` header. A strict CSP is the primary defence against XSS and data-exfiltration.",
      remediation:
        "Define a `Content-Security-Policy` covering `default-src`, `script-src`, `style-src`, `connect-src`, `img-src`, and `frame-ancestors` (start in `Content-Security-Policy-Report-Only` to gather telemetry).",
    });
  }

  // X-Content-Type-Options: nosniff
  const xcto = headers["x-content-type-options"];
  if (!xcto || xcto.trim().toLowerCase() !== "nosniff") {
    findings.push({
      fingerprint: fp("headers.xcto.missing", url),
      ruleId: "headers.xcto.missing",
      title: `Missing X-Content-Type-Options: nosniff on ${url}`,
      severity: "low",
      category: "config",
      description:
        "Response is missing `X-Content-Type-Options: nosniff`. Browsers may MIME-sniff and execute unintended content types.",
      remediation: "Send `X-Content-Type-Options: nosniff` on every response.",
    });
  }

  // Frame-ancestors / X-Frame-Options
  const csp = headers["content-security-policy"] ?? "";
  const hasFrameAncestors = /frame-ancestors\s+[^;]+/i.test(csp);
  if (!headers["x-frame-options"] && !hasFrameAncestors) {
    findings.push({
      fingerprint: fp("headers.frame-ancestors.missing", url),
      ruleId: "headers.frame-ancestors.missing",
      title: `Missing X-Frame-Options / CSP frame-ancestors on ${url}`,
      severity: "low",
      category: "config",
      description:
        "Response provides neither `X-Frame-Options` nor a `frame-ancestors` directive in CSP. The page can be framed by arbitrary origins, enabling clickjacking.",
      remediation:
        "Send `X-Frame-Options: DENY` (or `SAMEORIGIN`) and/or `Content-Security-Policy: frame-ancestors 'self'`.",
    });
  }

  // /healthz checks
  const hz = probe.healthz;
  if (hz) {
    if (!hz.reachable || (hz.status !== undefined && hz.status >= 500)) {
      findings.push({
        fingerprint: fp("healthz.unreachable", url),
        ruleId: "healthz.unreachable",
        title: `Healthz not reachable on ${url}`,
        severity: "info",
        category: "config",
        description: hz.error
          ? `GET ${url}/healthz failed: ${hz.error}`
          : `GET ${url}/healthz returned ${hz.status}`,
        remediation:
          "Informational — most services expose /healthz only on internal ingress. Confirm this is intentional.",
      });
    } else if (hz.status === 200 && !hz.hasAuthChallenge) {
      findings.push({
        fingerprint: fp("healthz.no-auth", url),
        ruleId: "healthz.no-auth",
        title: `Healthz endpoint exposed without auth challenge on ${url}`,
        severity: "low",
        category: "config",
        description:
          "GET /healthz returned 200 OK with no auth challenge. Public health endpoints can leak internal state (commit hashes, dependency versions, host names).",
        remediation:
          "Restrict /healthz to internal ingress or strip identifying details from the payload.",
      });
    }
  }

  return findings;
}

function fp(ruleId: string, url: string): string {
  return createHash("sha256").update(`${url}\x1f${ruleId}`).digest("hex");
}

function headersToObject(h: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  h.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

function joinUrl(base: string, path: string): string {
  try {
    return new URL(path, base.endsWith("/") ? base : `${base}/`).toString();
  } catch {
    const trimmed = base.endsWith("/") ? base.slice(0, -1) : base;
    return `${trimmed}${path.startsWith("/") ? path : `/${path}`}`;
  }
}

function errMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function summarize(findings: NormalizedFinding[]): SecurityScanSummary {
  const s: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}
