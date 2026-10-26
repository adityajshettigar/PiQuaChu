// frontend/src/pages/scan-results.tsx
//
// Results for one stored scan, read from GET /api/v1/scans/<id>. The page is a
// bento of distinct evidence surfaces — not eight identical metric cards — and
// every card that offers an explanation actually opens one, with the exact
// methodology version the server reported.
import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowRight, Download, FileJson, FileSearch } from 'lucide-react'
import { Panel } from '@/components/ui/panel'
import { Badge, type BadgeTone } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { EmptyState } from '@/components/ui/empty-state'
import { PageHeader } from '@/components/ui/page-header'
import { Skeleton } from '@/components/ui/skeleton'
import { BentoGrid, type BentoItem } from '@/components/ui/bento-grid-showcase'
import {
  CardLink,
  ExplanationSection,
  InsightCard,
  InsightSheet,
} from '@/components/results/insight'
import {
  api,
  ApiError,
  type ComplianceSummary,
  type Finding,
  type ReliabilityResponse,
  type ScanDetail,
  type StandardAssessment,
} from '@/lib/api'
import { STANDARDS, type StandardEntry } from '@/lib/standards'
import { cn, formatTimestamp } from '@/lib/utils'

type LoadState = 'loading' | 'ready' | 'notfound' | 'error'

type Explanation =
  | null
  | { kind: 'assessment' }
  | { kind: 'standards-overview' }
  | { kind: 'standard'; id: string }
  | { kind: 'risk' }
  | { kind: 'critical' }
  | { kind: 'remediation' }
  | { kind: 'cbom' }
  | { kind: 'reliability' }
  | { kind: 'metadata' }

const TABS = [
  { segment: '', label: 'Results' },
  { segment: 'findings', label: 'Findings' },
  { segment: 'remediation', label: 'Remediation' },
  { segment: 'cbom', label: 'CBOM' },
  { segment: 'reports', label: 'Reports' },
  { segment: 'assistant', label: 'Assistant' },
] as const

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 0,
  ERROR: 0,
  HIGH: 1,
  WARNING: 2,
  MEDIUM: 2,
  INFO: 3,
  LOW: 4,
}

const RISK_BUCKETS: Array<{ key: string; label: string; why: string }> = [
  { key: 'hashing', label: 'Hashing', why: 'MD5 / SHA-1 and similar collision-broken digests.' },
  { key: 'symmetric', label: 'Symmetric', why: 'DES/3DES/RC4 and unsafe block modes such as ECB.' },
  { key: 'tls', label: 'Transport', why: 'Deprecated TLS versions and classical cipher suites.' },
  { key: 'secrets', label: 'Secrets', why: 'Hard-coded key material or credentials in source.' },
  { key: 'dependencies', label: 'Dependencies', why: 'Manifest and lockfile evidence of outdated crypto libraries.' },
  { key: 'kdf', label: 'Key derivation', why: 'Static salts and weak key-derivation parameters.' },
  { key: 'randomness', label: 'Randomness', why: 'Predictable PRNG use for keys, IVs or nonces.' },
]

function verdictTone(verdict: string | null | undefined): BadgeTone {
  switch ((verdict || '').toLowerCase()) {
    case 'compliant': return 'success'
    case 'partial': return 'warning'
    case 'transitional': return 'warning'
    case 'non_compliant': return 'danger'
    case 'at_risk': return 'danger'
    case 'incomplete': return 'warning'
    default: return 'neutral'
  }
}

function verdictLabel(verdict: string | null | undefined): string {
  return verdict ? verdict.replace(/_/g, ' ') : 'unknown'
}

function standardStatusTone(status: string | undefined): BadgeTone {
  switch ((status || '').toLowerCase()) {
    case 'compliant': return 'success'
    case 'partial': return 'warning'
    case 'transitional': return 'warning'
    case 'detected_in_development': return 'info'
    case 'non_compliant': return 'danger'
    default: return 'neutral'
  }
}

function standardStatusLabel(status: string | undefined): string {
  switch ((status || '').toLowerCase()) {
    case 'compliant': return 'PQC evidence'
    case 'partial': return 'partial'
    case 'transitional': return 'hybrid'
    case 'detected_in_development': return 'in development'
    case 'non_compliant': return 'legacy only'
    case 'not_detected': return 'not observed'
    case '': return 'not reported'
    default: return String(status).replace(/_/g, ' ')
  }
}

function severityTone(severity: string | undefined): BadgeTone {
  switch ((severity || '').toUpperCase()) {
    case 'ERROR':
    case 'CRITICAL':
    case 'HIGH':
      return 'danger'
    case 'WARNING':
    case 'MEDIUM':
      return 'warning'
    case 'INFO':
      return 'info'
    default:
      return 'neutral'
  }
}

function ruleOf(finding: Finding): string {
  return String(finding.rule_id ?? finding.vulnerability ?? 'unknown rule')
}

function locationOf(finding: Finding): string {
  const file = typeof finding.file === 'string' ? finding.file : '—'
  const line = finding.line ?? finding.line_start
  return typeof line === 'number' || typeof line === 'string' ? `${file}:${line}` : file
}

function isLegacy(finding: Finding): boolean {
  return !finding.pqc_compliant
}

function score(value: unknown): string {
  return typeof value === 'number' && Number.isFinite(value) ? String(value) : '—'
}

function pct(value: number | null | undefined): string {
  return typeof value === 'number' && Number.isFinite(value)
    ? `${(value * 100).toFixed(1)}%`
    : '—'
}

function useScan(scanId: number | undefined) {
  const [state, setState] = useState<LoadState>(scanId ? 'loading' : 'notfound')
  const [detail, setDetail] = useState<ScanDetail | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!scanId) return
    let cancelled = false
    const controller = new AbortController()

    api.scan(scanId, controller.signal).then(
      (result) => {
        if (cancelled) return
        setDetail(result)
        setError(null)
        setState('ready')
      },
      (err: unknown) => {
        if (cancelled) return
        if (err instanceof ApiError && err.kind === 'aborted') return
        if (err instanceof ApiError && err.kind === 'not_found') {
          setState('notfound')
          return
        }
        setError(err instanceof ApiError ? err.message : 'The scan could not be read.')
        setState('error')
      },
    )

    return () => {
      cancelled = true
      controller.abort()
    }
  }, [scanId])

  return { state, detail, error }
}

function useReliability(enabled: boolean) {
  const [report, setReport] = useState<ReliabilityResponse | null>(null)
  const [state, setState] = useState<'loading' | 'computing' | 'ready' | 'error'>('loading')

  useEffect(() => {
    if (!enabled) return
    let cancelled = false
    api.reliability().then(
      (result) => {
        if (cancelled) return
        if (result.status === 'computing') {
          setState('computing')
          return
        }
        setReport(result)
        setState('ready')
      },
      () => {
        if (!cancelled) setState('error')
      },
    )
    return () => {
      cancelled = true
    }
  }, [enabled])

  return { state, report }
}

function ScoreReadout({
  label,
  value,
  suffix,
  note,
  tone = 'default',
}: {
  label: string
  value: string
  suffix?: string
  note: string
  tone?: 'default' | 'primary' | 'danger' | 'warning'
}) {
  const toneClass =
    tone === 'danger'
      ? 'text-[var(--danger)]'
      : tone === 'warning'
        ? 'text-[var(--warning)]'
        : tone === 'primary'
          ? 'text-[var(--primary)]'
          : 'text-[var(--value)]'

  return (
    <div className="min-w-0">
      <p className="eyebrow">{label}</p>
      <p className={cn('tnum mt-1.5 font-mono text-[clamp(1.8rem,3vw,2.4rem)] leading-none tracking-[-0.02em]', toneClass)}>
        {value}
        {suffix && (
          <span className="ml-1 font-sans text-[12px] tracking-normal text-[var(--muted-foreground)]">
            {suffix}
          </span>
        )}
      </p>
      <p className="mt-1.5 text-[11px] leading-snug text-[var(--muted-foreground)]">{note}</p>
    </div>
  )
}

function StandardsMatrix({
  compliance,
  onSelect,
}: {
  compliance: ComplianceSummary | null
  onSelect: (standard: StandardEntry) => void
}) {
  const matrix = compliance?.standards ?? {}
  return (
    <ul className="divide-y divide-[var(--border)]">
      {STANDARDS.map((standard) => {
        const entry: StandardAssessment | undefined = matrix[standard.id]
        const status = entry?.status
        return (
          <li key={standard.id}>
            <button
              type="button"
              onClick={() => onSelect(standard)}
              className="flex w-full items-center justify-between gap-3 py-2.5 text-left transition-colors hover:text-[var(--foreground)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]"
            >
              <span className="min-w-0">
                <span className="block font-mono text-[10px] uppercase tracking-[0.1em] text-[var(--muted-foreground)]">
                  {standard.id}
                </span>
                <span className="block text-[13px] font-medium">{standard.algorithm}</span>
                <span className="mt-0.5 block text-[10.5px] text-[var(--muted-foreground)]">
                  {typeof entry?.compliant_count === 'number' || typeof entry?.legacy_count === 'number'
                    ? `${entry?.compliant_count ?? 0} PQC · ${entry?.legacy_count ?? 0} legacy`
                    : 'no related findings reported'}
                </span>
              </span>
              <Badge tone={standardStatusTone(status)}>{standardStatusLabel(status)}</Badge>
            </button>
          </li>
        )
      })}
    </ul>
  )
}

export function ScanResultsPage({ scanId }: { scanId?: number }) {
  const params = useParams<{ scanId: string }>()
  const id = scanId ?? (params.scanId && /^\d+$/.test(params.scanId) ? Number(params.scanId) : undefined)
  const { state, detail, error } = useScan(id)
  const { state: reliabilityState, report: reliability } = useReliability(state === 'ready')
  const [explanation, setExplanation] = useState<Explanation>(null)

  const findings = useMemo(() => detail?.findings ?? [], [detail])
  const compliance = detail?.compliance ?? null
  const plans = useMemo(() => detail?.remediation_plans ?? [], [detail])

  const critical = useMemo(
    () =>
      [...findings]
        .filter((finding) => isLegacy(finding))
        .sort((a, b) => {
          const rank = (SEVERITY_RANK[String(a.severity).toUpperCase()] ?? 5) -
            (SEVERITY_RANK[String(b.severity).toUpperCase()] ?? 5)
          return rank !== 0 ? rank : ruleOf(a).localeCompare(ruleOf(b))
        })
        .slice(0, 4),
    [findings],
  )

  const engines = useMemo(() => {
    const names = new Set<string>()
    for (const finding of findings) {
      if (typeof finding.engine === 'string' && finding.engine) names.add(finding.engine)
    }
    return [...names]
  }, [findings])

  const engineVersion = findings.find((finding) => typeof finding.engine_version === 'string')?.engine_version

  const advisory = compliance?.advisory ?? {}
  const bucketCounts = RISK_BUCKETS.map((bucket) => ({
    ...bucket,
    count: typeof advisory[bucket.key as keyof typeof advisory] === 'number'
      ? Number(advisory[bucket.key as keyof typeof advisory])
      : 0,
  }))
  const bucketMax = Math.max(1, ...bucketCounts.map((bucket) => bucket.count))

  const highRiskPlans = plans.filter((entry) => ['high', 'critical'].includes(String(entry.plan?.risk).toLowerCase())).length
  const manualPlans = plans.filter((entry) => !entry.plan?.replacement_code).length

  if (!id) {
    return (
      <div className="mx-auto w-full max-w-[1200px] px-4 py-8 sm:px-6">
        <Panel>
          <EmptyState
            tone="error"
            icon={<FileSearch className="size-4" aria-hidden="true" />}
            title="This scan id is not usable"
            description="Results are addressed by a numeric scan id. Open a scan from history instead."
            action={
              <Button size="sm" variant="primary" asChild>
                <Link to="/history">Scan history</Link>
              </Button>
            }
          />
        </Panel>
      </div>
    )
  }

  if (state === 'loading') {
    return (
      <div className="mx-auto w-full max-w-[1280px] px-4 py-8 sm:px-6 md:py-10">
        <Skeleton className="h-6 w-52" label="Loading scan results" />
        <div className="mt-4 grid gap-4 lg:grid-cols-3">
          <Skeleton className="h-56 lg:col-span-2" />
          <Skeleton className="h-56" />
          <Skeleton className="h-40" />
          <Skeleton className="h-40" />
          <Skeleton className="h-40" />
        </div>
      </div>
    )
  }

  if (state === 'notfound' || state === 'error') {
    return (
      <div className="mx-auto w-full max-w-[1100px] px-4 py-8 sm:px-6">
        <PageHeader eyebrow="Results" title="Scan unavailable" meta={`scan #${id}`} />
        <Panel>
          <EmptyState
            tone="error"
            icon={<FileSearch className="size-4" aria-hidden="true" />}
            title={state === 'notfound' ? 'No stored scan with this id' : 'The scan could not be read'}
            description={
              state === 'notfound'
                ? 'It may have been recorded for another tenant, or the id may not exist. Nothing is inferred in its place.'
                : (error ?? 'The API returned an error.')
            }
            action={
              <>
                <Button size="sm" variant="primary" asChild>
                  <Link to="/history">Scan history</Link>
                </Button>
                <Button size="sm" variant="ghost" asChild>
                  <Link to="/scan">Start a scan</Link>
                </Button>
              </>
            }
          />
        </Panel>
      </div>
    )
  }

  if (!detail) return null

  const verdict = detail.verdict ?? compliance?.verdict ?? null
  const readiness = typeof detail.pqc_score === 'number' ? detail.pqc_score : compliance?.pqc_score
  const riskScore = compliance?.risk_score
  const riskLevel = compliance?.risk_level
  const explanationVersion = compliance?.assessment

  const items: BentoItem[] = [
    {
      id: 'assessment',
      colSpan: 8,
      rowSpan: 2,
      label: 'Overall assessment',
      content: (
        <InsightCard
          highlighted
          eyebrow="Overall assessment"
          title={verdict ? verdictLabel(verdict) : 'No verdict reported'}
          summary="Scanner verdict with the two scores it is derived from — kept separate on purpose."
          actionLabel="How readiness and risk are calculated"
          onOpen={() => setExplanation({ kind: 'assessment' })}
        >
          <div className="grid grid-cols-2 gap-x-5 gap-y-5 sm:grid-cols-3">
            <ScoreReadout
              label="Readiness"
              value={score(readiness)}
              suffix={typeof readiness === 'number' ? '/100' : undefined}
              tone="primary"
              note="Starts at 100 and is reduced by legacy evidence (readiness-v1)."
            />
            <ScoreReadout
              label="Weighted risk"
              value={score(riskScore)}
              suffix={typeof riskScore === 'number' ? '/100' : undefined}
              tone={riskLevel === 'critical' || riskLevel === 'high' ? 'danger' : riskLevel === 'medium' ? 'warning' : 'default'}
              note={riskLevel ? `Band: ${riskLevel} (risk-v1).` : 'Not reported for this scan.'}
            />
            <ScoreReadout
              label="Findings"
              value={String(findings.length)}
              note={`${findings.filter(isLegacy).length} legacy · ${findings.filter((f) => !isLegacy(f)).length} PQC evidence`}
            />
          </div>

          {compliance?.summary && (
            <p className="mt-5 max-w-[74ch] border-t border-[var(--border)] pt-3 text-[12px] leading-relaxed text-[var(--muted-foreground)]">
              {compliance.summary}
            </p>
          )}

          <div className="mt-4 flex flex-wrap gap-2">
            <Button size="sm" variant="outline" asChild>
              <Link to={`/results/${id}/findings`}>
                Inspect findings
                <ArrowRight className="size-3.5" aria-hidden="true" />
              </Link>
            </Button>
            <Button size="sm" variant="ghost" asChild>
              <Link to={`/results/${id}/reports`}>
                <Download className="size-3.5" aria-hidden="true" />
                Export
              </Link>
            </Button>
          </div>
        </InsightCard>
      ),
    },
    {
      id: 'standards',
      colSpan: 4,
      rowSpan: 2,
      label: 'Standards matrix',
      content: (
        <InsightCard
          eyebrow="Standards matrix"
          title="NIST PQC mapping"
          summary="Evidence per standard. “Not observed” is neutral, never a pass."
          actionLabel="What these statuses mean"
          onOpen={() => setExplanation({ kind: 'standards-overview' })}
        >
          <StandardsMatrix
            compliance={compliance}
            onSelect={(standard) => setExplanation({ kind: 'standard', id: standard.id })}
          />
        </InsightCard>
      ),
    },
    {
      id: 'critical',
      colSpan: 8,
      label: 'Critical findings',
      content: (
        <InsightCard
          eyebrow="Priority evidence"
          title="Most severe findings"
          summary={
            critical.length > 0
              ? 'Ordered by reported severity, then rule id.'
              : 'No legacy findings were reported for this scan.'
          }
          actionLabel="How this list is ordered"
          onOpen={() => setExplanation({ kind: 'critical' })}
        >
          {critical.length === 0 ? (
            <p className="text-[12.5px] leading-relaxed text-[var(--muted-foreground)]">
              The scanner matched no legacy cryptographic rule in this archive. That means no
              configured rule matched — it is not proof that no cryptography exists.
            </p>
          ) : (
            <ul className="divide-y divide-[var(--border)]">
              {critical.map((finding) => (
                <li key={String(finding.fingerprint ?? ruleOf(finding) + locationOf(finding))}>
                  <Link
                    to={`/results/${id}/findings?finding=${encodeURIComponent(String(finding.fingerprint ?? ''))}`}
                    className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1 py-2.5 transition-colors hover:bg-[color-mix(in_oklch,var(--foreground)_4%,transparent)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]"
                  >
                    <span className="min-w-0 flex-1">
                      <span className="flex flex-wrap items-center gap-2">
                        <Badge tone={severityTone(finding.severity)}>{finding.severity ?? 'unrated'}</Badge>
                        <span className="font-mono text-[11px] text-[var(--foreground)]">{ruleOf(finding)}</span>
                      </span>
                      <span className="mt-1 block truncate font-mono text-[10.5px] text-[var(--muted-foreground)]" title={locationOf(finding)}>
                        {locationOf(finding)}
                      </span>
                    </span>
                    <span className="shrink-0 font-mono text-[10px] uppercase tracking-[0.08em] text-[var(--muted-foreground)]">
                      {finding.nist_standard ?? 'advisory'}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </InsightCard>
      ),
    },
    {
      id: 'risk',
      colSpan: 4,
      label: 'Risk distribution',
      content: (
        <InsightCard
          eyebrow="Risk distribution"
          title="Advisory categories"
          summary="Counts reported by the scanner for non-standard advisory layers."
          actionLabel="What each category covers"
          onOpen={() => setExplanation({ kind: 'risk' })}
        >
          {typeof advisory.total === 'number' && advisory.total > 0 ? (
            <ul className="space-y-2">
              {bucketCounts
                .filter((bucket) => bucket.count > 0)
                .map((bucket) => (
                  <li key={bucket.key}>
                    <div className="flex items-baseline justify-between gap-2 text-[11.5px]">
                      <span className="text-[var(--foreground)]">{bucket.label}</span>
                      <span className="tnum font-mono text-[11px] text-[var(--muted-foreground)]">{bucket.count}</span>
                    </div>
                    <div className="mt-1 h-1 w-full overflow-hidden rounded-full bg-[var(--surface-subtle)]" aria-hidden="true">
                      <div
                        className="h-full rounded-full bg-[color-mix(in_oklch,var(--warning)_78%,transparent)]"
                        style={{ width: `${Math.max(4, (bucket.count / bucketMax) * 100)}%` }}
                      />
                    </div>
                  </li>
                ))}
            </ul>
          ) : (
            <p className="text-[12.5px] leading-relaxed text-[var(--muted-foreground)]">
              No advisory findings were reported for this scan. Standard-mapped evidence is
              summarised in the standards matrix instead.
            </p>
          )}
        </InsightCard>
      ),
    },
    {
      id: 'remediation',
      colSpan: 4,
      label: 'Remediation readiness',
      content: (
        <InsightCard
          eyebrow="Remediation"
          title="Reviewable plans"
          summary="Generated by the local rule engine; nothing is applied from the browser."
          actionLabel="What a plan does and does not do"
          onOpen={() => setExplanation({ kind: 'remediation' })}
        >
          <div className="grid grid-cols-2 gap-3">
            <ScoreReadout label="Plans" value={String(plans.length)} note="One per remediable finding (capped)." />
            <ScoreReadout
              label="High risk"
              value={String(highRiskPlans)}
              tone={highRiskPlans > 0 ? 'danger' : 'default'}
              note="Plan risk classification."
            />
          </div>
          <p className="mt-3 text-[11.5px] leading-relaxed text-[var(--muted-foreground)]">
            {manualPlans > 0
              ? `${manualPlans} plan(s) have no generated replacement and need manual review.`
              : 'Every stored plan includes suggested code for review.'}
          </p>
          <div className="mt-3">
            <CardLink to={`/results/${id}/remediation`}>Open remediation</CardLink>
          </div>
        </InsightCard>
      ),
    },
    {
      id: 'cbom',
      colSpan: 4,
      label: 'Cryptographic inventory',
      content: (
        <InsightCard
          eyebrow="Inventory"
          title="CycloneDX CBOM"
          summary="Generated from the stored scan on demand."
          actionLabel="What the inventory covers"
          onOpen={() => setExplanation({ kind: 'cbom' })}
        >
          <div className="flex items-start gap-2.5">
            <FileJson className="mt-0.5 size-4 shrink-0 text-[var(--primary)]" aria-hidden="true" />
            <p className="text-[12.5px] leading-relaxed text-[var(--muted-foreground)]">
              A schema-valid CycloneDX 1.7 artifact is available for this scan, built from
              the same findings. Schema validity is not an inventory-completeness claim.
            </p>
          </div>
          <div className="mt-3 flex flex-col gap-1.5">
            <CardLink to={`/results/${id}/cbom`}>Inspect the CBOM</CardLink>
            <CardLink to={`/results/${id}/reports`}>Download artifacts</CardLink>
          </div>
        </InsightCard>
      ),
    },
    {
      id: 'reliability',
      colSpan: 4,
      label: 'Detection reliability',
      content: (
        <InsightCard
          eyebrow="Detection reliability"
          title="Measured on a labeled corpus"
          summary="Internal regression evidence, not a universal accuracy claim."
          actionLabel="How these metrics are produced"
          onOpen={() => setExplanation({ kind: 'reliability' })}
        >
          {reliabilityState === 'ready' && reliability ? (
            <div className="grid grid-cols-3 gap-2">
              <ScoreReadout label="Precision" value={pct(reliability.metrics?.precision)} note="" />
              <ScoreReadout label="Recall" value={pct(reliability.metrics?.recall)} note="" />
              <ScoreReadout label="F1" value={pct(reliability.metrics?.f1)} note="" />
            </div>
          ) : reliabilityState === 'computing' ? (
            <p className="text-[12.5px] text-[var(--muted-foreground)]">
              The benchmark is running in the background. No placeholder figure is shown.
            </p>
          ) : reliabilityState === 'error' ? (
            <p className="text-[12.5px] text-[var(--muted-foreground)]">
              Metrics are unavailable from this API right now.
            </p>
          ) : (
            <p className="text-[12.5px] text-[var(--muted-foreground)]">Loading metrics…</p>
          )}

          <p className="mt-3 font-mono text-[10px] uppercase tracking-[0.08em] text-[var(--muted-foreground)]">
            {typeof reliability?.corpus_size === 'number'
              ? `${reliability.corpus_size} labeled cases`
              : 'corpus size unreported'}
            {reliability?.stale ? ' · stale' : ''}
          </p>
          <div className="mt-3">
            <CardLink to="/reliability">Open reliability</CardLink>
          </div>
        </InsightCard>
      ),
    },
    {
      id: 'metadata',
      colSpan: 12,
      label: 'Scan metadata',
      content: (
        <InsightCard
          eyebrow="Provenance"
          title="What produced this result"
          actionLabel="How this result can be reproduced"
          onOpen={() => setExplanation({ kind: 'metadata' })}
        >
          <dl className="grid grid-cols-2 gap-x-5 gap-y-3 text-[11.5px] sm:grid-cols-4">
            <div>
              <dt className="text-[var(--muted-foreground)]">Scan id</dt>
              <dd className="mt-0.5 font-mono text-[11px]">#{detail.scan_id}</dd>
            </div>
            <div>
              <dt className="text-[var(--muted-foreground)]">Recorded</dt>
              <dd className="mt-0.5 font-mono text-[11px]">{formatTimestamp(detail.timestamp)}</dd>
            </div>
            <div>
              <dt className="text-[var(--muted-foreground)]">Engines</dt>
              <dd className="mt-0.5 font-mono text-[11px]">{engines.length > 0 ? engines.join(' · ') : 'not reported'}</dd>
            </div>
            <div>
              <dt className="text-[var(--muted-foreground)]">Engine version</dt>
              <dd className="mt-0.5 font-mono text-[11px]">{typeof engineVersion === 'string' ? engineVersion : 'not reported'}</dd>
            </div>
          </dl>
        </InsightCard>
      ),
    },
  ]

  return (
    <div className="rise-in mx-auto w-full max-w-[1280px] px-4 py-8 sm:px-6 md:py-10">
      <PageHeader
        eyebrow="Results"
        parent={{ to: '/history', label: 'History' }}
        title={detail.filename || `Scan #${detail.scan_id}`}
        meta={`scan #${detail.scan_id} · recorded ${formatTimestamp(detail.timestamp)}`}
        actions={
          <>
            {verdict && <Badge tone={verdictTone(verdict)}>{verdictLabel(verdict)}</Badge>}
            <Button size="sm" variant="outline" asChild>
              <Link to={`/results/${detail.scan_id}/reports`}>
                <Download className="size-3.5" aria-hidden="true" />
                Export
              </Link>
            </Button>
            <Button size="sm" variant="ghost" asChild>
              <Link to="/scan">Scan again</Link>
            </Button>
          </>
        }
      />

      <nav aria-label="Result sections" className="mb-5 -mt-1 flex flex-wrap gap-1">
        {TABS.map((tab) => {
          const to = tab.segment ? `/results/${detail.scan_id}/${tab.segment}` : `/results/${detail.scan_id}`
          const active = tab.segment === ''
          return (
            <Link
              key={tab.label}
              to={to}
              aria-current={active ? 'page' : undefined}
              className={cn(
                'rounded-[var(--radius-md)] border px-2.5 py-1.5 text-[12px] transition-colors',
                active
                  ? 'border-[color-mix(in_oklch,var(--primary)_30%,transparent)] bg-[var(--primary-subtle)] text-[var(--foreground)]'
                  : 'border-transparent text-[var(--muted-foreground)] hover:bg-[var(--surface-subtle)] hover:text-[var(--foreground)]',
              )}
            >
              {tab.label}
            </Link>
          )
        })}
      </nav>

      <BentoGrid items={items} />

      <p className="mt-5 max-w-[86ch] text-[11px] leading-relaxed text-[var(--muted-foreground)]">
        Discovery only. A finding is evidence of a matched code pattern; a clean area is
        not proof of absence, and no value here is a FIPS 140 validation or a compliance
        certificate.
      </p>

      <InsightSheet
        open={explanation !== null}
        onOpenChange={(open) => {
          if (!open) setExplanation(null)
        }}
        eyebrow={explanation ? labelFor(explanation) : ''}
        title={explanation ? titleFor(explanation) : ''}
      >
        {explanation && (
          <>
            {explanation.kind === 'assessment' && (
              <>
                <ExplanationSection title="Readiness score">
                  <p>
                    A product heuristic, <code className="font-mono text-[11px]">{explanationVersion?.score_formula_version ?? 'readiness-v1'}</code>.
                    It starts at 100, deducts 20 per legacy <span className="text-[var(--foreground)]">ERROR</span> and
                    10 per legacy <span className="text-[var(--foreground)]">WARNING</span>, adds 5 per detected
                    PQC-compliant usage, and is clamped to 0–100.
                  </p>
                  <p>
                    Reported for this scan: <span className="font-mono">{score(readiness)}</span>.
                  </p>
                </ExplanationSection>
                <ExplanationSection title="Weighted risk score">
                  <p>
                    A separate exposure estimate,{' '}
                    <code className="font-mono text-[11px]">{explanationVersion?.risk_formula_version ?? 'risk-v1'}</code>.
                    Each legacy finding contributes a category weight (for example 1.0 for key
                    establishment and signatures, 0.6 for hashing) multiplied by a severity
                    factor, normalised so five maximum-weight critical findings reach 100.
                  </p>
                  <p>
                    Reported for this scan: <span className="font-mono">{score(riskScore)}</span>
                    {riskLevel ? ` (${riskLevel})` : ''}. It is not the inverse of readiness.
                  </p>
                </ExplanationSection>
                <ExplanationSection title="What it does not prove">
                  <p>
                    {explanationVersion?.limitations ??
                      'Findings are static code-pattern evidence. They do not prove runtime behaviour, parameter correctness, FIPS 140 module validation or organisation-wide compliance.'}
                  </p>
                  <p>
                    Evidence coverage: {explanationVersion?.evidence_coverage ?? 'static pattern evidence only'}.
                    Standards registry reviewed {explanationVersion?.standards_registry_reviewed ?? 'unknown'}.
                  </p>
                </ExplanationSection>
              </>
            )}

            {explanation.kind === 'standards-overview' && (
              <>
                <ExplanationSection title="How a status is assigned">
                  <ul className="space-y-1.5">
                    <li><span className="text-[var(--foreground)]">PQC evidence</span> — PQC usage detected for a finalized standard, with no legacy evidence in that category.</li>
                    <li><span className="text-[var(--foreground)]">Partial</span> — both PQC and legacy evidence in the same category.</li>
                    <li><span className="text-[var(--foreground)]">Legacy only</span> — only classical evidence was detected for that category.</li>
                    <li><span className="text-[var(--foreground)]">In development</span> — algorithm evidence for FIPS 206 (FN-DSA), which is not finalized. It is not a pass.</li>
                    <li><span className="text-[var(--foreground)]">Not observed</span> — no qualifying evidence. Neutral: it is not proof of absence.</li>
                  </ul>
                </ExplanationSection>
                <ExplanationSection title="What a status is based on">
                  <p>
                    The scanner classifies each matched rule by category and standard, then
                    counts PQC and legacy evidence per standard. A count is pattern evidence,
                    not an implementation audit. Select a standard in the matrix for its
                    specific rationale.
                  </p>
                </ExplanationSection>
              </>
            )}

            {explanation.kind === 'standard' && (() => {
              const standard = STANDARDS.find((entry) => entry.id === explanation.id) ?? STANDARDS[0]
              const entry = compliance?.standards?.[standard.id]
              return (
                <>
                  <ExplanationSection title="What the standard covers">
                    <p>
                      {standard.id} ({standard.algorithm}, formerly {standard.former}) — {standard.role}.
                      Lifecycle: {standard.lifecycleLabel.toLowerCase()}.
                    </p>
                    <p>{standard.caveat}</p>
                  </ExplanationSection>
                  <ExplanationSection title="What this scan detected">
                    <p>
                      Status: <span className="text-[var(--foreground)]">{standardStatusLabel(entry?.status)}</span>.
                      PQC evidence: {entry?.compliant_count ?? 'not reported'} · legacy evidence:{' '}
                      {entry?.legacy_count ?? 'not reported'}.
                    </p>
                    <p>{entry?.rationale ?? 'This scan reported no assessment for this standard.'}</p>
                  </ExplanationSection>
                  <ExplanationSection title="What it does not establish">
                    <p>
                      An algorithm string in source is not an approved implementation. Parameter
                      sets, key sizes, side-channel behaviour and module validation are outside
                      static pattern detection.
                    </p>
                    {standard.lifecycle !== 'final' && (
                      <p>
                        {standard.algorithm} is not a finalized standard. Evidence of the algorithm
                        is not evidence of compliance with {standard.id}.
                      </p>
                    )}
                  </ExplanationSection>
                  <a
                    href={standard.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 text-[12px] text-[var(--primary)] hover:text-[var(--foreground)]"
                  >
                    Official reference
                    <ArrowRight className="size-3.5" aria-hidden="true" />
                  </a>
                </>
              )
            })()}

            {explanation.kind === 'risk' && (
              <>
                <ExplanationSection title="What these counts are">
                  <p>
                    These are advisory buckets the scanner reports separately from the four
                    standards: hashing, symmetric encryption, transport, secrets, dependencies,
                    key derivation and randomness. They are counts of matched findings, not
                    weighted scores.
                  </p>
                </ExplanationSection>
                <ExplanationSection title="Why each matters">
                  <ul className="space-y-2">
                    {RISK_BUCKETS.map((bucket) => (
                      <li key={bucket.key} className="flex gap-2">
                        <span className="font-mono text-[11px] text-[var(--primary)]">
                          {String(advisory[bucket.key as keyof typeof advisory] ?? 0).padStart(2, '0')}
                        </span>
                        <span>
                          <span className="text-[var(--foreground)]">{bucket.label}.</span> {bucket.why}
                        </span>
                      </li>
                    ))}
                  </ul>
                </ExplanationSection>
                <ExplanationSection title="What is excluded">
                  <p>
                    PQC-compliant usage does not appear here, and advisory findings do not carry
                    a NIST standard status. They influence the weighted risk score through their
                    category weight.
                  </p>
                </ExplanationSection>
              </>
            )}

            {explanation.kind === 'critical' && (
              <>
                <ExplanationSection title="Ordering">
                  <p>
                    Legacy findings are ordered by reported severity (ERROR/HIGH first), then by
                    rule id so the order is stable between visits. PQC-compliant evidence is not
                    a critical finding.
                  </p>
                </ExplanationSection>
                <ExplanationSection title="What to check">
                  <p>
                    Open a finding to see its file, line, the rule that matched, the evidence type
                    and the scanner's stated limitations. A high-severity match still needs a human
                    to confirm the value reaches a real cryptographic operation.
                  </p>
                </ExplanationSection>
              </>
            )}

            {explanation.kind === 'remediation' && (
              <>
                <ExplanationSection title="Where plans come from">
                  <p>
                    The local rule engine generates deterministic guidance per rule. Each plan has
                    a justification, dependencies and, where the rule allows it, illustrative
                    replacement code.
                  </p>
                </ExplanationSection>
                <ExplanationSection title="What applying means">
                  <p>
                    Nothing here modifies source. Applying a patch is a separate CLI workflow that
                    produces a diff and re-parses the file; review is required before use. A stored
                    plan is not a fix.
                  </p>
                </ExplanationSection>
              </>
            )}

            {explanation.kind === 'cbom' && (
              <>
                <ExplanationSection title="Artifact">
                  <p>
                    The CBOM is generated on request from this scan&apos;s stored findings, not
                    archived at scan time. It follows CycloneDX 1.7 with `cryptographic-asset`
                    components and evidence occurrences.
                  </p>
                </ExplanationSection>
                <ExplanationSection title="Four different claims">
                  <ul className="space-y-1.5">
                    <li>Generated: the server produced a document.</li>
                    <li>Downloaded: this browser received it.</li>
                    <li>Schema-valid: the generator validated it against the 1.7 schema.</li>
                    <li>
                      Complete inventory: an independent question — only files the scanner
                      inspected can appear.
                    </li>
                  </ul>
                </ExplanationSection>
              </>
            )}

            {explanation.kind === 'reliability' && (
              <>
                <ExplanationSection title="Source of the numbers">
                  <p>
                    Precision, recall and F1 are measured by scanning a labeled hermetic corpus
                    and comparing matches with ground truth. The page reports the corpus size,
                    the metric source and its age.
                  </p>
                </ExplanationSection>
                <ExplanationSection title="Limits">
                  <p>
                    This is internal regression evidence. External, manually reviewed repository
                    validation is reported separately and is not replaced by a synthetic score.
                    Neither figure guarantees detection in an arbitrary codebase.
                  </p>
                </ExplanationSection>
              </>
            )}

            {explanation.kind === 'metadata' && (
              <>
                <ExplanationSection title="Reproducibility">
                  <p>
                    Results are stored under scan id <span className="font-mono">#{detail.scan_id}</span> with
                    the archive name, timestamp, findings and compliance matrix. CBOM and SARIF are
                    regenerated from that stored row, so re-downloading does not re-scan the code.
                  </p>
                </ExplanationSection>
                <ExplanationSection title="Engine provenance">
                  <p>
                    Detected engines: {engines.length > 0 ? engines.join(', ') : 'not reported in the stored findings'}.
                    Rule-set version: {typeof engineVersion === 'string' ? engineVersion : 'not reported'}.
                    Missing provenance is shown as unreported rather than guessed.
                  </p>
                </ExplanationSection>
                {detail.baseline && (
                  <ExplanationSection title="Baseline comparison">
                    <p>
                      This scan was compared against a supplied baseline; the delta and gate result
                      are stored with the scan and are reflected in the SARIF output.
                    </p>
                  </ExplanationSection>
                )}
              </>
            )}
          </>
        )}
      </InsightSheet>
    </div>
  )
}

function labelFor(explanation: Exclude<Explanation, null>): string {
  switch (explanation.kind) {
    case 'assessment': return 'Methodology'
    case 'standards-overview': return 'Standards matrix'
    case 'standard': return 'Standards matrix'
    case 'risk': return 'Risk distribution'
    case 'critical': return 'Priority evidence'
    case 'remediation': return 'Remediation readiness'
    case 'cbom': return 'Cryptographic inventory'
    case 'reliability': return 'Detection reliability'
    case 'metadata': return 'Scan metadata'
  }
}

function titleFor(explanation: Exclude<Explanation, null>): string {
  switch (explanation.kind) {
    case 'assessment': return 'What the assessment means'
    case 'standards-overview': return 'How evidence is mapped to a standard'
    case 'standard': return `${explanation.id} — detection and limits`
    case 'risk': return 'Advisory risk categories'
    case 'critical': return 'How the priority list is built'
    case 'remediation': return 'Reviewable plans, not applied patches'
    case 'cbom': return 'What the inventory does and does not claim'
    case 'reliability': return 'How detection quality is measured'
    case 'metadata': return 'Provenance and reproducibility'
  }
}

export default ScanResultsPage
