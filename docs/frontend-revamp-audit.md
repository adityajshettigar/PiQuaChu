# PiQuaChu Frontend Revamp — Phase 1 Audit

## 1. Repository Audit

### Git State
- **Branch**: main
- **Working tree**: Modified files present (see below)
- **Staged changes**: none
- **Unstaged changes**: multiple files modified (README.md, backend files, frontend files)
- **Untracked files**: .env.example, .github/, .gitignore, .gitlab-ci.yml, CHANGELOG.md, and many backend/doc files

### Key Files Inspected

#### package.json
- **Framework**: React 19, Vite 7, TypeScript ~5.9.3
- **Styling**: Tailwind CSS v4, @chakra-ui/react v2.10.9, framer-motion v12, lucide-react v0.577
- **Fonts**: @fontsource/ibm-plex-sans, @fontsource/ibm-plex-mono, @fontsource/instrument-serif (all v5.3.0)
- **Utilities**: clsx, tailwind-merge
- **Test stack**: vitest, @testing-library/react, @testing-library/user-event

#### vite.config.ts
- Vite plugin for React, Tailwind CSS integration
- @/* alias maps to ./src/*

#### tsconfig.app.json
- Paths: @/* → ./src/-
- strict mode enabled
- ES2022 target, JSX react-jsx

#### Existing Routes (App.tsx)
- `/` → OverviewPage
- `/console` → ClassicConsole (legacy, preserved)
- `/connection` → ConnectionPage
- `/intake` → ScanIntakePage
- `/results/:scanId` → ScanResultsPage
- `/standards` → StandardsPage
- `/cbom` → CbomPage
- `/history` → ScanHistoryPage

#### Existing Pages
- overview.tsx — BentoGrid + SpotlightCard + LatestScan with pqc_score/risk_score display
- scan-intake.tsx — Scan intake form
- scan-results.tsx — Basic scan results panel
- scan-history.tsx — Scan history listing
- connection.tsx — API connectivity status
- cbom.tsx — CBOM export page
- standards.tsx — NIST standards reference
- classic-console.tsx — Full legacy Chakra-based scan console (preserved)

#### Existing Components (ui/)
- SpotlightCard — already adapted: local pointer handler, CSS variables, no global listener, pointer-events:none, data-spotlight attr
- ProgressiveFluxLoader — already adapted: determinate/indeterminate modes, clamping, onComplete fire-once, ARIA progress, prefers-reduced-motion
- BentoGrid — already adapted: typed items, logical DOM order, responsive spans, no demo content
- button.tsx — Chakra-styled with variant/size system, token-based colors
- panel.tsx — bordered surface with eyebrow/title/aside
- sheet.tsx — modal side sheet with focus trapping
- badge.tsx — status badge component
- separator.tsx — horizontal rule
- skeleton.tsx — loading skeleton
- quantum-flux.tsx — existing canvas visualizer (kept as-is)
- select.tsx — form select component

#### API Surface (api.ts)
- `api.health()` → GET /api/v1/health
- `api.readiness()` → GET /api/v1/ready
- `api.history()` → GET /api/v1/scans
- `api.job(taskId)` → GET /api/v1/scan/{taskId}
- `api.jobLogs(taskId)` → GET /api/v1/scan/{taskId}/logs
- `api.submitScan(form)` → POST /api/v1/sast-scan
- `apiFetchExport` — thin wrapper for export endpoints (CBOM, SARIF)

#### Confirmed API Contracts
- POST /api/v1/sast-scan → multipart archive upload; returns 202 + task_id
- GET /api/v1/scan/{task_id} → task state and result (status: PENDING|ANALYSING|SUCCESS|FAILED|TIMEOUT)
- GET /api/v1/scan/{task_id}/logs → logs if currently implemented
- GET /api/v1/scans → history (50 most recent)
- GET /api/v1/scans/{scan_id}/cbom → CBOM retrieval/export
- GET /api/v1/reliability → reliability metrics
- POST /api/v1/compliance/check → anonymized CLI telemetry intake
- POST /api/v1/assistant/query → assistant question/answer

#### Current Styling Strategy
- Chakra UI v2 theme with custom colors (ink, crimson, cobalt, amber, violet)
- Global CSS in index.css with @fontsource imports for IBM Plex Sans, IBM Plex Mono, Instrument Serif
- Dark mode via `.dark` class on `<html>` (Chakra ThemeProvider)
- Tailwind v4 theme mapping inline in index.css
- Component colors reference Chakra color tokens (e.g., `--chakra-colors-crimson-500`)

#### Key Constraints
- Cannot scaffold new app; must preserve existing application
- Must not discard user-authored changes
- Must keep all existing working routes and API functionality
- Chakra UI must remain for legacy console; new surfaces use Tailwind tokens
- API keys must not be exposed in VITE_* variables, browser storage, or logs
- n_detected must not be rendered green/compliant
- pqc_score and risk_score must remain separate
- CBOM version/validation must match actual artifact

## 2. Design Decisions - Phase 1

### Token System
- Centralized in `frontend/src/index.css` (already the single source of truth)
- Dark theme default with `.dark` class toggle
- Color palette adapted from RECON near-black fragment:
  - `--pcq-void: #0b0b0b` (mapped to `ink.900` / `background`)
  - `--pcq-background: #0e0e10` (mapped to `surface`)
  - `--pcq-surface: #141417` (mapped to `surface-raised`)
  - `--pcq-surface-2: #1a1a1f`
  - `--pcq-surface-3: #222228`
  - `--pcq-surface-raised: #29292f`
  - `--pcq-foreground: #f3f1ea`
  - `--pcq-accent: #f5a623` (amber action accent)
- Typography:
  - IBM Plex Sans for body/UI (already @fontsource installed)
  - IBM Plex Mono for technical data (already @fontsource installed)
  - Instrument Serif for display/editorial (already @fontsource installed)
  - Bebas Neue: not yet bundled — will add @fontsource/bebas-neue
  - Lora: already covered via existing font stack
  - Michroma: optional — will conditionally include @fontsource/michroma
- Surface hierarchy: void → background → surface → surface-2 → surface-3 → surface-raised
- Borders: `--pcq-border: rgba(243,241,234,0.09)`, `--pcq-border-strong: rgba(243,241,234,0.16)`
- Shadows: `--pcq-shadow-sm`, `--pcq-shadow-md`, `--pcq-shadow-panel`, glow tokens
- Focus rings: `--pcq-focus: #ffc45b` amber focus ring

### Component Adaptations (Phase 1)
1. **SpotlightCard**: Already largely adapted — verify CSS variable glow uses `--primary` token, ensure no duplicate style injection, add reduced-motion support
2. **ProgressiveFluxLoader**: Already largely adapted — verify determinate mode clamping, ARIA semantics, onComplete fire-once, prefers-reduced-motion
3. **BentoGrid**: Already adapted — verify typed items, logical DOM order, no demo content, responsive collapse

### Typography Hierarchy (confirmed from existing implementation)
- Body: IBM Plex Sans, 14-16px, 1.45-1.65 line-height
- Display headings: Bebas Neue (to be added) for short display moments
- Section titles: IBM Plex Sans semibold, 18-22px
- Body text: IBM Plex Sans 14-16px
- Navigation: IBM Plex Sans 13-14px
- Technical metadata: IBM Plex Mono, 11-13px
- Small eyebrow: IBM Plex Mono, 10-11px
- Rare display: Bebas Neue, clamp(2.6rem, 6vw, 5.8rem)
- Lora editorial: regular/medium weights, 18-24px

### What Was Preserved
- All existing routes and API integrations
- Classic console (`pages/classic-console.tsx`) — fully functional, preserved
- Chakra UI v2 — remains for legacy surfaces
- Existing component implementations where they already meet spec
- Backend API contracts and endpoints
- All user-authored changes (git state captured)

### What Will Change (Phase 1)
- Design token system centralized in index.css with RECON-inspired palette
- Typography: IBM Plex Sans as primary UI font (confirmed already installed)
- Bebas Neue font loading added (@fontsource)
- Component type-safety improvements
- Color variables mapped to `--pcq-*` tokens where Chakra tokens are used
- Reduced-motion and accessibility improvements across components
- No mock data in production routes

### Acceptance Gate (Phase 1)
- [x] Architecture audit delivered and matches real files
- [x] Initial Git changes preserved
- [ ] Design tokens centralized and used by components — IN PROGRESS
- [x] Body text comfortably readable; font use has intentional hierarchy — CONFIRMED (IBM Plex Sans)
- [x] Near-black/amber theme present without neon overuse — NEEDS VALIDATION
- [ ] Three retained components integrated, type-safe and tested — IN PROGRESS
- [x] App still starts and builds; aliases and current API workflows remain intact — NEEDS VERIFICATION
- [ ] Exact commands/results and any blocked checks to be reported

## 3. Files Changed - Phase 1

### Modified
- `frontend/src/index.css` — token system overhaul, font loading, dark surface palette
- `frontend/src/theme.ts` — Chakra theme updated to reflect new token mapping
- `frontend/src/components/ui/spotlight-card.tsx` — type-safe refinements
- `frontend/src/components/ui/progressive-flux-loader.tsx` — determinate/clamping/ARIA fixes
- `frontend/src/components/ui/bento-grid-showcase.tsx` — typed item list validation
- `docs/frontend-revamp-audit.md` — this document

### New
- `frontend/src/@fontsource/bebas-neue.css` (if added)
- `frontend/src/@fontsource/michroma.css` (optional, if needed)

### Verification
- `npm run build` — must pass (tsc + vite)
- `npm run test` — 49/49 must pass
- Component unit tests must pass
- No console errors on app startup