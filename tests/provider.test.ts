import { describe, expect, test } from "bun:test";

import { AlphaSmokeProvider } from "../src/provider.js";
import { ALPHA_SMOKE_VERSION } from "../src/tools-manifest.js";

const baseInput = (config: Record<string, unknown> = {}) => ({
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
  workdir: "/tmp",
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

  test("run() returns 'succeeded' with a stub info finding", async () => {
    const p = new AlphaSmokeProvider();
    const result = await p.run(
      baseInput({
        alphaUrls: ["https://alpha.example.com"],
        requireHsts: true,
      }),
    );
    expect(result.status).toBe("succeeded");
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].severity).toBe("info");
    expect(result.findings[0].category).toBe("config");
    expect(result.summary.info).toBe(1);
    expect(result.evidence).toEqual([]);
  });

  test("cancel() on an unknown run is a no-op", async () => {
    const p = new AlphaSmokeProvider();
    await expect(p.cancel("nonexistent")).resolves.toBeUndefined();
  });
});
