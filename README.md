<!-- VIBECONTROLS_OSS_HEADER_START -->

> **License**: MIT — see [LICENSE](./LICENSE).
> **Note**: This plugin is open source. The `@vibecontrols/agent` runtime that loads it is **not** open source — it is a proprietary product of Burdenoff Consultancy Services Pvt. Ltd. See [vibecontrols.com](https://vibecontrols.com) for the agent.

<!-- VIBECONTROLS_OSS_HEADER_END -->

## @vibecontrols/vibe-plugin-security-deploy-alpha

Pure-JS smoke-check provider for the `deploy.alpha` lifecycle stage in [VibeControls](https://vibecontrols.com). Provider name: `alpha-smoke`. No binary, no Docker — uses the native `fetch` API only. **Wave 2 scaffold — real probe integration pending; see `src/provider.ts` TODO.**

Registers itself with [`@vibecontrols/vibe-plugin-security`](https://www.npmjs.com/package/@vibecontrols/vibe-plugin-security) under the per-stage provider type `security.release` (per `PROVIDER_TYPE_FOR_STAGE("deploy.alpha")`). When the user picks "alpha-smoke" as their default provider for `deploy.alpha`, the security meta plugin dispatches scan runs here.

## Install

```bash
vibe plugin install @vibecontrols/vibe-plugin-security-deploy-alpha
vibe security providers set-default --stage deploy.alpha --provider alpha-smoke
```

No external dependencies. Pure-JS, no subprocess, no privileged capabilities — runs anywhere the agent runs.

## Behavior (planned)

For each URL in `input.config.alphaUrls`:

- **TLS validity**: cert not expired, hostname matches, chain valid.
- **Response headers**: `Strict-Transport-Security`, `X-Content-Type-Options`, `Content-Security-Policy` present on `GET /` (configurable per check).
- **Auth challenge**: `GET /healthz` returns 200 OK with a known JSON shape for public endpoints; protected endpoints return 401 + `WWW-Authenticate`.

Findings:

- `severity: high` — TLS invalid or HSTS missing.
- `severity: medium` — CSP or X-Content-Type-Options missing.
- `severity: low` — `/healthz` auth-challenge mismatch.

Evidence: raw probe results as a JSON artifact.

## Configuration

Per-vibe config (stored in `RepositorySecurityConfig.pluginAssignments["deploy.alpha"].config`):

```yaml
provider: alpha-smoke
config:
  alphaUrls:
    - https://alpha.example.com
    - https://api.alpha.example.com
  requireHsts: true
  requireCsp: true
  requireXcto: true
  healthzPath: /healthz
  extraHeaders:
    User-Agent: vibecontrols-alpha-smoke
```

<!-- VIBECONTROLS_OSS_FOOTER_START -->

---

## License

Released under the [MIT License](./LICENSE).

Copyright (c) 2026 Burdenoff Consultancy Services Private Limited, Algoshred Technologies Private Limited, and all its sister companies.

Maintainer: **Vignesh T.V** — <https://github.com/tvvignesh>

## About VibeControls

**VibeControls** is the agentic engineering mission control for AI-native teams. Vibe-plugins extend the VibeControls agent with new providers, tools, sessions, tunnels, storage backends, and security stages.

- Website: <https://vibecontrols.com>
- Documentation: <https://docs.vibecontrols.com>
- Plugin SDK: <https://github.com/algoshred/vibecontrols-plugin-sdk>
- All plugins: <https://github.com/algoshred?q=vibe-plugin-&type=all>

## Important: agent is not open source

The `@vibecontrols/agent` runtime that loads and orchestrates these plugins is **closed source** and proprietary to Burdenoff Consultancy Services Pvt. Ltd. Only the plugin contract and the plugins themselves are released under MIT. If you want a fully self-hostable agent, please open an issue or contact the maintainer.

<!-- VIBECONTROLS_OSS_FOOTER_END -->
