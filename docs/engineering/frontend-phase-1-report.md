# Frontend redesign — Phase 1 report (audit, foundation, theme, primitives)

Date: 2026-10-21 · Status: **COMPLETE — awaiting explicit user approval for Phase 2**
Nothing was deployed, published, committed or pushed. The backend, CLI, scan
history and API behaviour were not modified.

## 1. What changed

| Area | Files | Behaviour |
|---|---|---|
| Token layer + typography | `frontend/src/index.css`, `frontend/index.html`, `frontend/src/main.tsx` | OKLCH light/dark tokens mapped into Tailwind v4 (`@theme inline`); self-hosted Instrument Serif / IBM Plex Sans / IBM Plex Mono via `@fontsource`; Google Fonts link and the `body { filter: invert() }` theme hack removed |
| Class utilities | `frontend/src/lib/utils.ts` (+ `.test.ts`) | `cn()` (clsx + tailwind-merge), `clamp()`, `formatTimestamp()` |
| Typed API client | `frontend/src/lib/api.ts` (+ `.test.ts`) | One fetch boundary with normalized `ApiError` kinds (network/401/403/404/413/429/500/malformed/aborted), abort support, verified response contracts |
| Standards registry | `frontend/src/lib/standards.ts` | One isolated source for FIPS 203/204/205 (final) and FIPS 206 (in development), mirroring `backend/standards.py` (reviewed 2026-10-18) |
| Primitives | `frontend/src/components/ui/{button,badge,panel,separator,skeleton,sheet}.tsx` | Token-driven, keyboard/focus accessible; `Sheet` traps focus, closes on Escape and restores focus |
| SpotlightCard | `frontend/src/components/ui/spotlight-card.tsx` (+ test) | Component-local pointer tracking via CSS vars (no global listener, no per-render `<style>`, no `touch-action` override, pointer-events-none overlay) |
| ProgressiveFluxLoader | `frontend/src/components/ui/progressive-flux-loader.tsx` (+ test) | Determinate/indeterminate modes, clamped values, `onComplete` once per transition, `progressbar` vs `status` semantics, no invented percentage |
| BentoGrid | `frontend/src/components/ui/bento-grid-showcase.tsx` (+ test) | Typed spans, DOM-order regions, mobile collapse, no demo slots or avatars |
| App shell | `frontend/src/components/app-shell/{app-shell,nav,theme-provider,theme-context,connection-status}.tsx` (+ test) | Collapsible sidebar, mobile sheet, breadcrumb, theme toggle, skip link, **real** health indicator (no hard-coded “nominal”) |
| Routing | `frontend/src/App.tsx` | `react-router-dom`: `/` Overview, `/console` classic console, `/connection`, 404 |
| Pages | `frontend/src/pages/{overview,connection,classic-console}.tsx` (+ tests) | Overview shows only API-returned history; Connection shows real health/readiness and precise privacy boundaries; console keeps the full working scan workflow |
| Test stack | `frontend/vite.config.ts`, `frontend/src/test/setup.ts`, `package.json` | Vitest + Testing Library + jsdom, `npm test` |

The classic console was moved to `src/pages/classic-console.tsx` with two changes
only: the invert-based theme toggle was removed (the shell owns the theme) and its
hard-coded “System nominal” pill now renders the real `/api/v1/health` result. No
scan, polling, history, export or assistant behaviour changed.

## 2. Architecture decisions

- **Tailwind v4 was already installed and configured**; no major-version migration
  and **no shadcn CLI**. The CLI would have rewritten the stylesheet and required
  Radix/CVA; primitives are hand-written in the shadcn convention instead, using
  the already-present `clsx` + `tailwind-merge`. No new UI/icon/animation library.
- **One token layer** is the single source for colour, radius and fonts. Components
  use `var(--token)`/Tailwind utilities generated from it — no raw hex in components.
- **Chakra is retained only for the classic console** as an explicit, documented
  migration boundary (rewriting 1 026 lines in Phase 1 would have risked the
  working workflow). Phase 2 ports the scan surfaces; Chakra is removed only after a
  repo-wide import search is empty.
- **Routing** was added because Phase 2 needs scan ids and filters in URLs. Only
  implemented routes are exposed — there are no placeholder or inert links.
- **API contracts were read from `backend/app.py`**, not from prior docs; the audit
  records the exact shapes and confirms there is no cancel/patch/PR/standards
  endpoint to build against.

## 3. Verification (commands and actual results)

Run from `frontend/`:

| Command | Result |
|---|---|
| `npm test` (`vitest run`) | **7 files, 49 tests passed** (exit 0) |
| `npm run build` (`tsc -b && vite build`) | **exit 0** — 2 819 modules, built in 3.79 s |
| `npm run lint` (`eslint .`) | **exit 0**, 0 errors, 0 warnings |
| `npm run dev -- --port 5179` + `curl /`, `/src/main.tsx`, `/src/App.tsx` | **200** each; title = “PiQuaChu — cryptography evidence workbench”; modules transform without error (dev server stopped afterwards) |
| Backend suite (`backend/test_docs.py`) after README edits | **161 checks passed** (no stale-claim regressions) |

Test coverage added: cn/clamp/date helpers; API error mapping for 401/403/404/413/
429/500/unknown, network, abort and malformed JSON; loader determinate vs
indeterminate, clamping, `NaN`, one-shot completion, phase ordering, duplicate
phases; SpotlightCard pointer tracking, touch/disabled fallbacks, class merging;
BentoGrid order/labels/spans/empty/null slots; shell navigation, breadcrumb, skip
link, theme persistence, mobile dialog focus trap + Escape + focus restore, real
connected/unreachable health states; Overview populated/empty/401 states;
Connection health/readiness values and unreachable state.

## 4. Security / privacy review

- No `dangerouslySetInnerHTML` in any new or edited file.
- No secrets, tokens or scan content are logged, persisted or put in URLs; the theme
  preference (the only stored value) holds `light`/`dark`.
- `VITE_API_KEY` is still inlined by Vite — now surfaced explicitly on the
  Connection page as “dev key in bundle”, with a warning not to publish such a build.
- The shell’s status is derived from real requests; an unreachable API renders
  “API unavailable”, never a green light.
- Unverified claims removed from the new surfaces: FIPS 206 is labelled *in
  development*, “not detected” is explained as not proof of absence, and the pages
  state that static evidence is not certification.
- Not verified here: CSP headers (backend concern), browser storage inspection, and
  any real browser-level XSS/a11y tooling — see limitations.

## 5. Known limitations

- **BLOCKED — browser-level UAT**: no Chrome/Chromium or Playwright in this
  environment, so screenshots, visual regression, zoom and real screen-reader
  passes were not run. DOM semantics and focus behaviour are covered in jsdom.
- Light theme applies to the new shell/pages; the classic console remains a dark
  Chakra surface until Phase 2 (documented in `docs/frontend-audit.md`).
- `src/components/ui/demo.tsx` (legacy QuantumFlux demo) is unused and still
  present; removal is scheduled with the console port.
- Search, findings filters, CBOM, remediation, reliability and assistant pages do
  not exist yet — they are Phase 2/3 work and are therefore **not** in navigation.
- No performance budget was measured beyond build size (~399 kB main chunk,
  122 kB gzip; Chakra chunk 381 kB / 126 kB gzip).

## 6. Manual acceptance checklist (for the user)

1. `cd frontend && npm install && npm run dev` → open the printed URL.
2. Confirm the shell: sidebar (desktop) / menu button (narrow width), breadcrumb,
   theme toggle switching warm-paper ↔ graphite, skip-link on first Tab.
3. Overview: with no history, the empty state and “Open the scan console” CTA are
   shown; with history, the latest filename, timestamp, verdict and readiness score
   match `/api/v1/scans`.
4. Header status pill: with the backend stopped it reads “API unavailable” and the
   refresh button retries; with it running it reads “API connected”.
5. Connection page: origin, version, environment, tenancy and job backend match
   `/api/v1/health`; readiness shows `ready`; warnings (if any) are listed.
6. Console: upload a small `.zip` and confirm the workflow is unchanged and the
   progress panel says the server reports no percentage (no invented number).
7. Narrow the window to ~390 px: navigation opens as a modal sheet, Escape closes
   it, and focus returns to the menu button.

## 7. User gate

Phase 1 is complete and verified as above. **Stopping here** — Phase 2 (Overview,
New Scan, Active Scan, Results, Findings workbench) will not start until you
explicitly approve this report.
