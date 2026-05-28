/**
 * @vibecontrols/vibe-plugin-security-deploy-alpha
 *
 * Pure-JS smoke-check provider for the `deploy.alpha` lifecycle stage.
 * Registers as a `security.release` provider (per
 * PROVIDER_TYPE_FOR_STAGE) with @vibecontrols/vibe-plugin-security on
 * the host's ServiceRegistry.
 */
import { ProviderRegistry, TelemetryEmitter, createLifecycleHooks } from "@vibecontrols/plugin-sdk";
import type {
  HostServices,
  ProfileContext,
  VibePlugin,
  VibePluginFactory,
} from "@vibecontrols/plugin-sdk/contract";

import { AlphaSmokeProvider } from "./provider.js";

const PLUGIN_NAME = "security-deploy-alpha";
const PLUGIN_VERSION = "2026.528.1";

export const createPlugin: VibePluginFactory = (_ctx: ProfileContext): VibePlugin => {
  const provider = new AlphaSmokeProvider();
  const telemetry = new TelemetryEmitter(PLUGIN_NAME, PLUGIN_VERSION);

  const lifecycle = createLifecycleHooks({
    name: PLUGIN_NAME,
    telemetryEventName: "security.deploy-alpha.ready",
    onInit: async (host: HostServices) => {
      await provider.init(host);
      const registry = new ProviderRegistry(host);
      registry.registerProvider("security.release", "alpha-smoke", provider);
      telemetry.emit("security.deploy-alpha.registered", {
        provider: "alpha-smoke",
        toolVersion: provider.toolVersion,
      });
    },
  });

  return {
    name: PLUGIN_NAME,
    version: PLUGIN_VERSION,
    description:
      "Pure-JS smoke checks (TLS, security headers, /healthz auth-challenge) for the deploy.alpha lifecycle stage. Wave 2 scaffold.",
    tags: ["backend", "provider", "integration"],
    capabilities: {
      storage: "rw",
      audit: true,
      telemetry: true,
    },
    onServerStart: lifecycle.onServerStart,
    onServerStop: lifecycle.onServerStop,
  };
};

export default createPlugin;
export { AlphaSmokeProvider } from "./provider.js";
