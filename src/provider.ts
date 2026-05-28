/**
 * AlphaSmokeProvider — implements SecurityProvider for stage `deploy.alpha`.
 *
 * Pure-JS provider — no external binary, no Docker, no subprocess.
 *
 * Wave 2 scaffold. The real implementation will:
 *  - For each URL in `input.config.alphaUrls`, perform an HTTPS GET to
 *    `/healthz` and inspect:
 *      * TLS validity (cert not expired, hostname matches, chain ok)
 *      * Presence of `Strict-Transport-Security`, `X-Content-Type-Options`,
 *        and `Content-Security-Policy` response headers
 *      * Auth-challenge presence (401 + `WWW-Authenticate` for protected
 *        endpoints; 200 OK with a known JSON shape for public /healthz)
 *  - Emit one NormalizedFinding per failing check, category "config",
 *    severity "high" for missing TLS or HSTS, "medium" for missing CSP /
 *    XCTO, "low" for missing /healthz challenge.
 *  - Emit the raw probe results as a JSON evidence artifact.
 *
 * Today this stub records that the stage ran so the dispatcher can chain
 * the next stage.
 */
import { createHash } from "node:crypto";

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
  alphaUrls?: string[];
  requireHsts?: boolean;
  requireCsp?: boolean;
  requireXcto?: boolean;
  healthzPath?: string;
  extraHeaders?: Record<string, string>;
}

export class AlphaSmokeProvider implements SecurityProvider {
  readonly name = "alpha-smoke";
  readonly stage: SecurityStage = "deploy.alpha";
  readonly toolVersion = ALPHA_SMOKE_VERSION;

  private host?: HostServices;

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    // Pure-JS provider — no external binary to install. Uses native fetch.
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    const startedAt = Date.now();
    const cfg = (input.config as AlphaSmokeConfig) ?? {};
    void this.host; // reserved for future logger use

    input.onProgress?.({ pct: 10, message: "deploy.alpha smoke checks scaffolded" });

    // TODO(wave-2): replace this stub with the real TLS + security-header +
    // /healthz auth-challenge probe loop over cfg.alphaUrls.
    const fingerprint = createHash("sha256")
      .update(`${this.name}:${input.runId}:${(cfg.alphaUrls ?? []).join(",")}`)
      .digest("hex");

    const findings: NormalizedFinding[] = [
      {
        fingerprint,
        ruleId: `${this.name}.stub`,
        title: "deploy.alpha: alpha-smoke scaffolded — real probe integration pending",
        severity: "info",
        category: "config",
        description:
          "Wave 2 scaffold for the deploy.alpha lifecycle stage. The real provider will probe each URL in input.config.alphaUrls for TLS validity, presence of HSTS / X-Content-Type-Options / CSP, and an auth-challenge on /healthz. Today this stub records that the stage ran so the dispatcher can chain the next stage.",
        remediation:
          "Wire the real native-fetch probe loop + JSON evidence artifact; severities high (TLS/HSTS) / medium (CSP/XCTO) / low (healthz).",
      },
    ];

    const evidence: ScanEvidenceArtifact[] = [];
    const summary: SecurityScanSummary = summarize(findings);

    input.onProgress?.({ pct: 100, message: "Scaffold run complete" });

    return {
      runId: input.runId,
      status: "succeeded",
      findings,
      evidence,
      durationMs: Date.now() - startedAt,
      summary,
    };
  }

  async cancel(_runId: string): Promise<void> {
    // No subprocess — nothing to cancel. Real impl may abort in-flight fetches.
  }

  metadata(): SecurityProviderMetadata {
    return {
      stage: this.stage,
      supportedProfiles: ["backend", "frontend", "cli", "container"],
      toolVersion: this.toolVersion,
      description:
        "Pure-JS smoke checks (TLS, security headers, /healthz) for deploy.alpha (Wave 2 scaffold; real integration pending).",
    };
  }
}

function summarize(findings: NormalizedFinding[]): SecurityScanSummary {
  const s: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}
