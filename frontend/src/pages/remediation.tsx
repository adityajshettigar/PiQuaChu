// frontend/src/pages/remediation.tsx
//
// Remediation review for one stored scan. A plan is a suggestion produced by the
// deterministic rule engine; this page never applies a change to source, and it
// labels AI-enriched explanations separately when the stored plan says so.
import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Check, Copy, FileSearch, Wrench } from 'lucide-react'
import { Panel } from '@/components/ui/panel'
import { Badge, type BadgeTone } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { EmptyState } from '@/components/ui/empty-state'
import { PageHeader } from '@/components/ui/page-header'
import { Skeleton } from '@/components/ui/skeleton'
import { api, ApiError, type RemediationEntry, type ScanDetail } from '@/lib/api'
import { cn, formatTimestamp } from '@/lib/utils'

type LoadState = 'loading' | 'ready' | 'notfound' | 'error'

function asText(value: unknown, fallback = '—'): string {
  return typeof value === 'string' && value.trim() ? value : fallback
}

function riskTone(risk: string): BadgeTone {
  switch (risk.toLowerCase()) {
    case 'high':
    case 'critical':
      return 'danger'
    case 'medium':
      return 'warning'
    default:
      return 'neutral'
  }
}

function planKey(entry: RemediationEntry, index: number): string {
  return `${entry.rule ?? 'plan'}-${entry.file ?? ''}-${entry.line ?? ''}-${index}`
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

function CopyButton({ code }: { code: string }) {
  const [copied, setCopied] = useState(false)

  return (
    <Button
      size="sm"
      variant="outline"
      onClick={() => {
        navigator.clipboard?.writeText(code).then(
          () => {
            setCopied(true)
            window.setTimeout(() => setCopied(false), 1800)
          },
          () => setCopied(false),
        )
      }}
    >
      {copied ? (
        <>
          <Check className="size-3.5" aria-hidden="true" />
          Copied
        </>
      ) : (
        <>
          <Copy className="size-3.5" aria-hidden="true" />
          Copy suggested code
        </>
      )}
    </Button>
  )
}

export function RemediationPage({ scanId }: { scanId?: number }) {
  const params = useParams<{ scanId: string }>()
  const id =
    scanId ?? (params.scanId && /^\d+$/.test(params.scanId) ? Number(params.scanId) : undefined)
  const { state, detail, error } = useScan(id)
  const [expanded, setExpanded] = useState<string | null>(null)

  const plans = useMemo(() => detail?.remediation_plans ?? [], [detail])

  const counts = useMemo(() => {
    const high = plans.filter((entry) => ['high', 'critical'].includes(asText(entry.plan?.risk, '').toLowerCase()))
    const withCode = plans.filter((entry) => typeof entry.plan?.replacement_code === 'string' && entry.plan.replacement_code)
    const aiEnriched = plans.filter((entry) => /groq|llm|remote/i.test(asText(entry.plan?.source, '')))
    return {
      total: plans.length,
      high: high.length,
      manual: plans.length - withCode.length,
      aiEnriched: aiEnriched.length,
    }
  }, [plans])

  if (!id) {
    return (
      <div className="mx-auto w-full max-w-[1100px] px-4 py-8 sm:px-6">
        <Panel>
          <EmptyState
            tone="error"
            title="A scan id is required"
            description="Remediation plans belong to one stored scan."
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
      <div className="mx-auto w-full max-w-[1100px] px-4 py-8 sm:px-6">
        <Skeleton className="h-6 w-56" label="Loading remediation plans" />
        <Skeleton className="mt-4 h-24 w-full" />
        <Skeleton className="mt-3 h-32 w-full" />
      </div>
    )
  }

  if (state === 'notfound' || state === 'error' || !detail) {
    return (
      <div className="mx-auto w-full max-w-[1100px] px-4 py-8 sm:px-6">
        <PageHeader eyebrow="Remediation" title="Scan unavailable" meta={`scan #${id}`} />
        <Panel>
          <EmptyState
            tone="error"
            icon={<Wrench className="size-4" aria-hidden="true" />}
            title={state === 'notfound' ? 'No stored scan with this id' : 'The scan could not be read'}
            description={state === 'notfound' ? 'It may belong to another tenant or may not exist.' : (error ?? 'The API returned an error.')}
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

  return (
    <div className="rise-in mx-auto w-full max-w-[1100px] px-4 py-8 sm:px-6 md:py-10">
      <PageHeader
        eyebrow="Remediation"
        parent={{ to: `/results/${detail.scan_id}`, label: 'Results' }}
        title="Migration plan"
        meta={`scan #${detail.scan_id} · ${detail.filename ?? 'unnamed archive'} · ${formatTimestamp(detail.timestamp)}`}
        description="Deterministic recommendations produced by the local rule engine. Review the finding, the call site and the suggested target before changing source. Applying a patch is a separate CLI workflow that emits a diff."
        actions={
          <Button size="sm" variant="ghost" asChild>
            <Link to={`/results/${detail.scan_id}/findings`}>
              <FileSearch className="size-3.5" aria-hidden="true" />
              Findings
            </Link>
          </Button>
        }
      />

      <Panel className="mb-4 grid grid-cols-2 gap-5 sm:grid-cols-4">
        <div>
          <p className="eyebrow">Plans</p>
          <p className="tnum mt-1 font-mono text-[1.8rem] leading-none text-[var(--value)]">{counts.total}</p>
        </div>
        <div>
          <p className="eyebrow">High risk</p>
          <p className={cn('tnum mt-1 font-mono text-[1.8rem] leading-none text-[var(--value)]', counts.high > 0 && 'text-[var(--danger)]')}>
            {counts.high}
          </p>
        </div>
        <div>
          <p className="eyebrow">Manual review</p>
          <p className="tnum mt-1 font-mono text-[1.8rem] leading-none text-[var(--value)]">{counts.manual}</p>
          <p className="mt-1 text-[10.5px] leading-snug text-[var(--muted-foreground)]">
            No generated replacement code.
          </p>
        </div>
        <div>
          <p className="eyebrow">AI-enriched</p>
          <p className="tnum mt-1 font-mono text-[1.8rem] leading-none text-[var(--value)]">{counts.aiEnriched}</p>
          <p className="mt-1 text-[10.5px] leading-snug text-[var(--muted-foreground)]">
            Optional provider text; rule output is the baseline.
          </p>
        </div>
      </Panel>

      {plans.length === 0 ? (
        <Panel>
          <EmptyState
            icon={<Wrench className="size-4" aria-hidden="true" />}
            title="No remediation plans stored"
            description="The engine produced no plan for this scan. Findings may still exist, and a plan is not required for manual migration."
            action={
              <Button size="sm" variant="secondary" asChild>
                <Link to={`/results/${detail.scan_id}/findings`}>Open findings</Link>
              </Button>
            }
          />
        </Panel>
      ) : (
        <ul className="space-y-3">
          {plans.map((entry, index) => {
            const key = planKey(entry, index)
            const isOpen = expanded === key
            const code = typeof entry.plan?.replacement_code === 'string' ? entry.plan.replacement_code : ''
            const source = asText(entry.plan?.source, 'rule engine')
            const enriched = /groq|llm|remote/i.test(source)
            return (
              <li key={key}>
                <Panel>
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="font-mono text-[12px] text-[var(--foreground)]">{asText(entry.rule)}</p>
                      <p className="mt-1 break-all font-mono text-[11px] text-[var(--muted-foreground)]">
                        {asText(entry.file)}
                        {entry.line !== undefined && entry.line !== null ? `:${entry.line}` : ''}
                      </p>
                    </div>
                    <div className="flex shrink-0 flex-wrap items-center gap-2">
                      <Badge tone="neutral">{asText(entry.standard)}</Badge>
                      <Badge tone={riskTone(asText(entry.plan?.risk, 'unknown'))}>
                        {asText(entry.plan?.risk, 'unrated')} risk
                      </Badge>
                      {enriched && <Badge tone="info">AI-enriched</Badge>}
                    </div>
                  </div>

                  <p className="mt-3 text-[12.5px] leading-relaxed text-[var(--muted-foreground)]">
                    {asText(entry.plan?.justification, 'No justification was stored for this plan.')}
                  </p>

                  <dl className="mt-3 grid gap-2 text-[11px] sm:grid-cols-2">
                    <div>
                      <dt className="text-[var(--muted-foreground)]">Dependencies</dt>
                      <dd className="mt-0.5 font-mono">{asText(entry.plan?.dependencies, 'not reported')}</dd>
                    </div>
                    <div>
                      <dt className="text-[var(--muted-foreground)]">Plan source</dt>
                      <dd className="mt-0.5 font-mono">{source}</dd>
                    </div>
                  </dl>

                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      aria-expanded={isOpen}
                      aria-controls={`plan-code-${index}`}
                      onClick={() => setExpanded(isOpen ? null : key)}
                    >
                      {isOpen ? 'Hide suggested code' : 'Review suggested code'}
                    </Button>
                    {code && <CopyButton code={code} />}
                  </div>

                  <div id={`plan-code-${index}`} hidden={!isOpen}>
                    {isOpen && (
                      <div className="mt-3">
                        {code ? (
                          <pre className="max-h-80 overflow-auto rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--background)] p-4 font-mono text-[11px] leading-relaxed text-[var(--foreground)]">
                            {code}
                          </pre>
                        ) : (
                          <p className="text-[12px] leading-relaxed text-[var(--muted-foreground)]">
                            No replacement code was generated for this rule. Migrate manually
                            using the justification above.
                          </p>
                        )}
                        <p className="mt-2 text-[11px] leading-relaxed text-[var(--muted-foreground)]">
                          Suggested code is illustrative and may not match the surrounding call
                          site. This page cannot apply it; the CLI patch flow re-parses the file
                          and emits a diff for review.
                        </p>
                      </div>
                    )}
                  </div>
                </Panel>
              </li>
            )
          })}
        </ul>
      )}

      <div className="mt-5 flex flex-wrap gap-2">
        <Button size="sm" variant="secondary" asChild>
          <Link to={`/results/${detail.scan_id}`}>Back to results</Link>
        </Button>
        <Button size="sm" variant="ghost" asChild>
          <Link to="/history">Scan history</Link>
        </Button>
      </div>
    </div>
  )
}

export default RemediationPage
