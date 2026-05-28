/**
 * No external tool binary for this plugin — checks are pure-JS via the
 * native `fetch` API (Node 22+ / Bun 1.3+).
 *
 * We still export a pinned `ALPHA_SMOKE_VERSION` so the provider's
 * `toolVersion` field carries a stable identifier in telemetry and audit
 * logs. Bumping is an audited operation.
 */

export const ALPHA_SMOKE_VERSION = "alpha-smoke@1.0.0";
