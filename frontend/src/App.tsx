// frontend/src/App.tsx
//
// The single authoritative route tree. Every destination resolves to an
// implemented page; unknown addresses render inside the shell. Legacy paths
// redirect to their current equivalent instead of 404-ing a bookmark.
import { Link, Navigate, Route, Routes, useParams } from 'react-router-dom'
import { AppShell } from './components/app-shell/app-shell'
import { RouteErrorBoundary } from './components/app-shell/route-error-boundary'
import { Panel } from './components/ui/panel'
import { OverviewPage } from './pages/overview'
import { ScanIntakePage } from './pages/scan-intake'
import { ActiveScanPage } from './pages/active-scan'
import { ScanResultsPage } from './pages/scan-results'
import { FindingsPage } from './pages/findings'
import { RemediationPage } from './pages/remediation'
import { CbomPage } from './pages/cbom'
import { ReportExportPage } from './pages/report-export'
import { AssistantPage } from './pages/assistant'
import { ScanHistoryPage } from './pages/scan-history'
import { StandardsPage } from './pages/standards'
import { ReliabilityPage } from './pages/reliability'
import { SettingsPage } from './pages/connection'
import { LoginPage } from './pages/login'
import ClassicConsole from './pages/classic-console'

function MissingScanId() {
  return (
    <Panel className="mx-auto mt-10 w-full max-w-[720px] px-5 py-6">
      <h1 className="text-xl font-medium">A scan id is required</h1>
      <p className="mt-2 text-[13px] text-[var(--muted-foreground)]">
        This view belongs to one stored scan. Open a scan from history or start a new one.
      </p>
      <div className="mt-3 flex gap-4 text-[12px]">
        <Link to="/history" className="text-[var(--primary)] hover:underline">
          Scan history
        </Link>
        <Link to="/scan" className="text-[var(--primary)] hover:underline">
          Start a scan
        </Link>
      </div>
    </Panel>
  )
}

function NotFound() {
  return (
    <Panel className="mx-auto mt-10 w-full max-w-[720px] px-5 py-6">
      <p className="eyebrow">404</p>
      <h1 className="mt-1 text-xl font-medium">No page at this address</h1>
      <p className="mt-2 text-[13px] text-[var(--muted-foreground)]">
        The link may be out of date. Start from the home page, which is always available.
      </p>
      <Link
        to="/"
        className="mt-3 inline-block text-[12px] text-[var(--primary)] underline-offset-2 hover:underline"
      >
        Back to home
      </Link>
    </Panel>
  )
}

function ActiveScanRoute() {
  const { taskId } = useParams<{ taskId: string }>()
  if (!taskId) return <MissingScanId />
  return <ActiveScanPage taskId={taskId} />
}

function numericParam(value: string | undefined): number | undefined {
  return value && /^\d+$/.test(value) ? Number(value) : undefined
}

function ScanResultsRoute() {
  const { scanId } = useParams<{ scanId: string }>()
  const id = numericParam(scanId)
  if (id === undefined) return <NotFound />
  return <ScanResultsPage scanId={id} />
}

function FindingsRoute() {
  const { scanId } = useParams<{ scanId: string }>()
  const id = numericParam(scanId)
  if (id === undefined) return <NotFound />
  return <FindingsPage scanId={id} />
}

function RemediationRoute() {
  const { scanId } = useParams<{ scanId: string }>()
  const id = numericParam(scanId)
  if (id === undefined) return <NotFound />
  return <RemediationPage scanId={id} />
}

function CbomRoute() {
  const { scanId } = useParams<{ scanId: string }>()
  const id = numericParam(scanId)
  if (id === undefined) return <NotFound />
  return <CbomPage scanId={id} />
}

function ReportRoute() {
  const { scanId } = useParams<{ scanId: string }>()
  const id = numericParam(scanId)
  if (id === undefined) return <NotFound />
  return <ReportExportPage scanId={id} />
}

function AssistantRoute() {
  const { scanId } = useParams<{ scanId: string }>()
  const id = numericParam(scanId)
  if (id === undefined) return <NotFound />
  return <AssistantPage scanId={id} />
}

export default function App() {
  return (
    <RouteErrorBoundary>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<OverviewPage />} />
          <Route path="scan" element={<ScanIntakePage />} />
          <Route path="scan/:taskId" element={<ActiveScanRoute />} />

          <Route path="results/:scanId" element={<ScanResultsRoute />} />
          <Route path="results/:scanId/findings" element={<FindingsRoute />} />
          <Route path="results/:scanId/remediation" element={<RemediationRoute />} />
          <Route path="results/:scanId/cbom" element={<CbomRoute />} />
          <Route path="results/:scanId/reports" element={<ReportRoute />} />
          <Route path="results/:scanId/assistant" element={<AssistantRoute />} />

          <Route path="history" element={<ScanHistoryPage />} />
          <Route path="standards" element={<StandardsPage />} />
          <Route path="reliability" element={<ReliabilityPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="login" element={<LoginPage />} />

          {/* Legacy addresses kept working as redirects, not as dead links. */}
          <Route path="intake" element={<Navigate to="/scan" replace />} />
          <Route path="connection" element={<Navigate to="/settings" replace />} />
          <Route path="cbom" element={<Navigate to="/history" replace />} />
          <Route path="console" element={<ClassicConsole />} />

          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </RouteErrorBoundary>
  )
}
