# Frontend architecture audit — Phase 1

Audited: 2026-10-21 · Repo: PiQuaChu · Scope: `frontend/` (read-only audit, then
Phase 1 foundation work). Everything below was verified against the working tree,
not against earlier documentation.

## 1. Toolchain (verified)

| Item | Value |
|---|---|
| Package manager | npm 12.2.0 (lockfile: `package-lock.json`) |
| Node | 26.11.1 |
| React / ReactDOM | 19.2.0 |
| Vite | 7.3.1 (`@vitejs/plugin-react` 5.1.1) |
| TypeScript | 5.9.3, `strict`, `noUnusedLocals`, `noUnusedParameters`, `erasableSyntaxOnly` |
| Styling | Tailwind **v4** via `@tailwindcss/vite` (already installed and wired), plus Chakra UI v2.10.9 + Emotion |
| Animation | `framer-motion` 12.35.1 |
| Icons | `lucide-react` 0.577.0 (the only icon library — no second set added) |
| Upload | `react-dropzone` 15 |
| Utilities | `clsx` 2.1.1 + `tailwind-merge` 3.7.0 (already present) |
| Router | **none** before Phase 1 → `react-router-dom` added (only new runtime dep besides self-hosted fonts) |
| Tests | **none** before Phase 1 → Vitest 5 + Testing Library + jsdom added as dev deps |

Scripts (`package.json`): `dev`, `build` (`tsc -b && vite build`), `lint`,
`preview`, and new `test` / `test:watch`.

## 2. Paths and CSS entry points

- Alias `@/* → ./src/*` was already configured in **both** `tsconfig.app.json`
  (`baseUrl` + `paths`) and `vite.config.ts` (`resolve.alias`); verified by a
  production build that resolves `@/lib/utils`.
- Global stylesheet: `src/index.css` (imported once from `src/main.tsx`), already
  containing `@import "tailwindcss";`.
- Legacy component CSS: `src/App.css` (brand mark, hero dropzone, gauge needle,
  reduced-motion rules) — still used by the classic console only.
- No `tailwind.config.js` (Tailwind v4 is CSS-first).

## 3. Runtime composition before Phase 1

```
main.tsx → ChakraProvider(theme.ts) → App.tsx (1026 lines)
  App.tsx holds every piece of state (scan, findings, compliance, plans, logs,
  history, filters, baseline/gate, report modal) and renders:
    QuantumFlux (canvas hero) · dropzone · ReadinessGauge · ComplianceMatrix
    · ThreatMap · findings table · TimelineChart · remediation list
    · AssistantPanel · ScanLogs · ReportModal
```

Problems relevant to this work: a single monolith, no routes/deep links, a
hard-coded “System nominal” health pill, a global `body` invert filter used as the
light theme, and one global stylesheet mixing Chakra variables with Tailwind.

## 4. API surface (verified in `backend/app.py`, not from docs)

| Route | Auth | Response used by the UI |
|---|---|---|
| `GET /api/v1/health` | public | `status, service, version, checks{database,rate_limiter{backend,failure_mode},job_backend}, configuration{environment,tenancy_mode,warnings[]}` |
| `GET /api/v1/ready` | public | `status: ready\|not_ready`, `checks{database,rate_limiter}` (503 when not ready) |
| `POST /api/v1/sast-scan` | `scan:create` | `{status, task_id}` (202) |
| `GET /api/v1/scan/<job_id>` | `scan:read` (tenant-scoped) | `status, scan_id, engine, findings[], compliance{}, remediation_plans[], count, logs[], error?` |
| `GET /api/v1/scan/<job_id>/logs` | `scan:read` | `{logs:[{t,level,message}]}` |
| `GET /api/v1/scans` | `scan:read` | `{scans:[{id,timestamp,filename,pqc_score,verdict}]}` (newest 50, tenant-scoped) |
| `GET /api/v1/scans/<id>/cbom` | `report:read` | CycloneDX 1.7 BOM |
| `GET /api/v1/scans/<id>/sarif` | `report:read` | SARIF 2.1.0 |
| `GET /api/v1/reliability` | `reliability:read` | benchmark metrics |
| `POST /api/v1/assistant/query` | `assist:query` | `answer, code, has_context, remote_ai, privacy_note` (2 000-char question cap) |
| `POST /api/v1/compliance/check` | `telemetry:write` | telemetry intake |

There is **no** endpoint to cancel a job, apply a patch, create a PR, or expose a
standards registry. The UI must not offer those actions.

## 5. Design-system decisions for Phase 1

1. **Tailwind v4 was already the configured CSS engine**, so no migration to a new
   major version and no shadcn CLI (`npx shadcn init` would have rewritten the
   stylesheet and required Radix/CVA deps). Primitives are hand-written in the
   shadcn *convention* (`src/components/ui/*`, `cn()` from `@/lib/utils`) with the
   already-installed `clsx` + `tailwind-merge`, and no new UI dependency.
2. **One token layer** in `src/index.css`: OKLCH custom properties for
   background/surface/border/text/status colours, mapped into Tailwind with
   `@theme inline`. Dark mode is class-based (`.dark` on `<html>`); the old
   `body { filter: invert(...) }` theme hack is removed.
3. **Typography self-hosted** via `@fontsource` (Instrument Serif, IBM Plex Sans,
   IBM Plex Mono). The Google Fonts `<link>` is removed from `index.html`, so the
   app has no remote font dependency.
4. **Chakra stays for the classic console only.** Its Chakra theme (`src/theme.ts`)
   now uses the same self-hosted faces (Instrument Serif / IBM Plex Sans / IBM Plex
   Mono), so no remote font is needed anywhere in the app. Porting 1 026 lines of Chakra in
   Phase 1 would have risked the working scan workflow; the console is mounted at
   `/console` unchanged apart from removing the invert hack/theme button and
   replacing its hard-coded “System nominal” pill with the real health probe.
   Phase 2 ports the scan surfaces onto the new primitives and Chakra can then be
   removed once a repo-wide import search is empty.
5. **Routing added** (`react-router-dom`) so scan ids and filters can live in URLs
   from Phase 2 onward. Phase 1 exposes only routes that exist: `/` (Overview),
   `/console`, `/connection`.
6. **Testing added** (Vitest + Testing Library + jsdom) with `src/test/setup.ts`.

## 6. Known limitations at the end of Phase 1

- Browser-level visual/accessibility verification is **BLOCKED** in this
  environment (no Chrome/Playwright); component and page tests run in jsdom.
- The classic console still uses Chakra and keeps its own dark surface; in light
  theme it is a dark instrument panel inside a light shell (documented, ported in
  Phase 2).
- `src/components/ui/demo.tsx` (legacy QuantumFlux demo) is now unused and is
  removed in a later phase; it is not imported by any route.
- The frontend standards registry (`src/lib/standards.ts`) mirrors
  `backend/standards.py` (reviewed 2026-10-18) because no standards endpoint
  exists; it is reconciled by `backend/test_standards.py` / `test_docs.py`.
