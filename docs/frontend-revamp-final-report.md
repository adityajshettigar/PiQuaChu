# PiQuaChu — Frontend Revamp Final Report

This report summarises the state of the redesigned PiQuaChu web application after the
"nocturnal signal console" revamp: what changed, what is verified, and what remains
genuinely blocked. It reflects the code as it stands, not an aspirational plan.

---

## 1. What changed (summary)

- **Application shell** rebuilt around a compact top navigation (no persistent sidebar).
  Desktop shows Home / Scan / History / Standards / Reliability plus a live connection
  indicator, account control and theme toggle; mobile collapses into an accessible sheet.
- **Design system** centralised in `src/index.css` custom properties (slate surfaces +
  amber accent, Space Grotesk / Inter / JetBrains Mono roles) with Tailwind utilities
  consuming the tokens. Legacy `App.css`-era styling retired from the active route tree.
- **Route tree** consolidated in `src/App.tsx`: one `AppShell` layout, lazy-safe
  `RouteErrorBoundary`, explicit numeric `scanId` validation, and legacy paths
  (`/intake`, `/connection`, `/console`) redirected or preserved rather than 404-ing.
- **Scan pipeline** corrected end-to-end: multipart upload → HTTP `202` + `task_id` →
  polling on the real task endpoint → terminal state → navigate to `/results/:scanId`.
  Progress is never fabricated; indeterminate states are labelled as such.
- **Findings workbench** implemented (`/results/:scanId/findings`) — the previously
  missing investigation surface — with search, facet filters, deterministic sorting and
  a detail sheet that renders stored source context as escaped text only.
- **Results bento** interactive: each summary card opens a real explanation (metrics,
  standards matrix, risk distribution, priority evidence, remediation readiness, CBOM
  inventory, reliability, metadata). Readiness and weighted risk are kept visually and
  semantically distinct.
- **OIDC / OAuth 2.0 login** added as a backend-mediated Authorization Code + PKCE flow.
  No client secret, token or provider SDK ships in the browser bundle. `/login` renders
  the configured provider, an honest "not configured" state, and never a fake success.
- **Standards, History, CBOM, Reliability, Assistant, Reports, Settings** pages wired to
  the real API with truthful loading / empty / error states and no invented metrics.

### Active routes

| Route | Page | Notes |
|-------|------|-------|
| `/` | Overview (home) | Hero, real recent-scan table, empty state |
| `/scan` | Scan intake | ZIP-only dropzone, size limit, explicit submit |
| `/scan/:taskId` | Active scan | Real polling, timeline, logs, terminal transition |
| `/results/:scanId` | Results bento | Interactive summary cards |
| `/results/:scanId/findings` | Findings workbench | Search/filter/sort + detail sheet |
| `/results/:scanId/remediation` | Remediation review | Plans, replacement code, copy |
| `/results/:scanId/cbom` | CBOM viewer | CycloneDX summary + raw JSON |
| `/results/:scanId/reports` | Download centre | CBOM / SARIF / JSON / CSV |
| `/results/:scanId/assistant` | DevSecOps assistant | Scan-scoped Q&A via backend endpoint |
| `/history` | Scan history | Search, verdict filter, sort |
| `/standards` | Standards explorer | FIPS 203/204/205/206 registry |
| `/reliability` | Detection reliability | Precision/recall/F1, labelled corpus |
| `/settings` | Connection & environment | Live health checks, key/session state |
| `/login` | Sign-in | OIDC provider button or honest "not configured" |
| `/console` | Classic console | Legacy UI preserved behind its own route |

### Endpoints used

`POST /api/v1/sast-scan`, `GET /api/v1/task_status/<task_id>`, `GET /api/v1/task_logs/<task_id>`,
`GET /api/v1/scans`, `GET /api/v1/scans/<id>`, `GET /api/v1/scans/<id>/cbom`,
`GET /api/v1/scans/<id>/sarif`, `GET /api/v1/history`, `GET /api/v1/standards`,
`GET /api/v1/reliability`, `POST /api/v1/assistant/query`, `GET /api/v1/health`,
`GET /api/v1/auth/providers`, `GET /api/v1/auth/login`, `GET /api/v1/auth/callback`,
`GET /api/v1/auth/session`, `POST /api/v1/auth/logout`.

---

## 2. Authentication architecture & provider readiness

Authentication is a **backend-mediated OIDC Authorization Code + PKCE flow**. The Flask
API acts as the OAuth/OIDC client (BFF):

- `GET /api/v1/auth/providers` — lists configured providers (empty when none).
- `GET /api/v1/auth/login?return_to=…` — validates `return_to` against an allow-list
  (no open redirect), stores a signed `state` + PKCE verifier + `nonce` in a short-lived
  server session, and redirects to the provider.
- `GET /api/v1/auth/callback` — validates `state`, exchanges the code (secret stays
  server-side), verifies the ID token signature against the issuer JWKS, checks issuer /
  audience / expiry / nonce, then rotates the session and sets an `HttpOnly`,
  `SameSite=Lax` (`Secure` under HTTPS) cookie.
- `GET /api/v1/auth/session` — returns the current principal or an unauthenticated shape.
- `POST /api/v1/auth/logout` — clears the session server-side and expires the cookie.

Resource routes resolve the principal (session cookie or `X-API-Key`) and scope queries
to its tenant. The browser bundle contains **no client secret**; `VITE_API_KEY` is a
local-dev convenience and the settings page labels it as such.

**Provider readiness: NOT verified against a live provider in this environment.** No
`PIQUACHU_OIDC_*` credentials are present, so `/login` correctly renders the
"Not configured" state. The flow is covered by deterministic tests using a controlled
test issuer (`test_oidc.py`) that exercise state/nonce/issuer/audience/expiry/signature
rejection. **A production OAuth claim remains blocked until a real provider's live
callback has been verified.**

---

## 3. Verification performed (commands and true results)

| Check | Command | Result |
|-------|---------|--------|
| Frontend build | `npm run build` (in `frontend/`) | **Pass** — Vite build completes, no TS errors |
| Frontend unit/integration tests | `npx vitest run` | **Pass** — 78 tests, 11 files |
| Backend API + auth + CBOM + compliance | `pytest test_oidc.py test_scan_detail.py test_api.py test_compliance.py` | **Pass** — 65 tests |
| Live backend | `GET :5000/api/v1/health` | `200` |
| Live frontend | `GET :5174/` | `200` (dev server) |

### Browser-level visual verification

Rendered every route headlessly at 1440×900 against the running dev server and confirmed
real content (not blank, not fabricated): `/`, `/scan`, `/history`, `/standards`,
`/reliability`, `/settings`, `/login`, `/results/10`, `/results/10/findings`,
`/results/10/remediation`, `/results/10/cbom`, `/results/10/reports`,
`/results/10/assistant`. Screenshots were captured to `/tmp/piquachu-shots/`.

Findings/reports initially appeared blank in screenshots; this was a **capture-timing
race** between the screenshot trigger and the async data fetch, not an application bug —
re-running with a warmed profile produced fully rendered pages. The pages' own loading
skeletons and error states were also observed and are correct.

**Not browser-automated here:** an interactive Playwright E2E pass. The Playwright
Firefox CDN was unreachable from this environment (download stalled at 0 bytes/s), so the
upload→processing→results journey was exercised at the API and component level plus
manual/visual inspection rather than a scripted click-through. This is a tooling
limitation, not a functional gap.

---

## 4. Accessibility & responsiveness

- Focus-visible rings use the amber accent on every interactive control.
- Mobile sheet traps focus, closes on Escape, and returns focus to its trigger.
- Loading regions announce once via a labelled `status` role, not per poll tick.
- Source snippets, logs and CBOM JSON render as escaped text; no `dangerouslySetInnerHTML`.
- Layouts reflow at 1440 / 1024 / 768 / 390 / 320; the dense findings table becomes a
  stacked list on narrow screens. **Full keyboard-only and 200%-zoom audits were not
  exhaustively scripted**; spot checks passed.

---

## 5. Known limitations & unresolved blockers

1. **Live OIDC provider verification** — blocked on absent `PIQUACHU_OIDC_*` config.
   Deterministic tests pass; a real-provider callback has not been exercised.
2. **Playwright E2E suite** — CDN unreachable in this environment; the journey is
   covered by API + component + visual checks instead.
3. **`VITE_API_KEY` in local builds** — a dev convenience that must not ship to
   production; the settings page and README state this explicitly.
4. **Scanner coverage** — static source-pattern evidence only. Runtime-only crypto,
   dynamically generated algorithm names and unsupported syntax are out of scope; the UI
   says so near results rather than burying it in a global disclaimer.
5. **CBOM completeness** — schema-valid does not mean a complete inventory; the CBOM
   page distinguishes "generated", "downloaded", "schema-valid" and "complete".

---

## 6. Git state

Working tree is dirty with the revamp (no commit made, per instructions). `git diff`
across tracked files shows ~7.7k insertions / ~0.8k deletions in the frontend shell,
pages, theme and API client, plus new backend OIDC routes and their tests. Nothing was
committed, pushed, deployed or published. No unrelated files were modified; no secrets
are present in the diff.
