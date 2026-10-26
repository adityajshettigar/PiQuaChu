// frontend/src/pages/reliability.tsx
//
// Detection reliability: the hermetic-corpus metrics reported by
// /api/v1/reliability. The endpoint is allowed to answer "computing" — that is
// shown as such, never replaced with placeholder numbers.

import { useCallback, useEffect, useRef, useState } from 'react'
import { Activity, RefreshCw } from 'lucide-react'
import { Panel } from '@/components/ui/panel'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Stat } from '@/components/ui/stat'
import { EmptyState } from '@/components/ui/empty-state'
import { PageHeader } from '@/components/ui/page-header'
import { api, ApiError, type ReliabilityResponse } from '@/lib/api'

type LoadState = 'loading' | 'ready' | 'computing' | 'error'

function pct(value: number | null | undefined): string {
  if (typeof value !== 'number' || Number.isNaN(value)) return '—'
  return `${(value * 100).toFixed(1)}%`
}

function formatExternalDate(iso: string): string {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString()
}

export function ReliabilityPage() {
  const [state, setState] = useState<LoadState>('loading')
  const [report, setReport] = useState<ReliabilityResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const controllerRef = useRef<AbortController | null>(null)

  // Fires the request only; state is set from the callbacks so the effect never
  // writes state synchronously.
  const request = useCallback(() => {
    controllerRef.current?.abort()
    const controller = new AbortController()
    controllerRef.current = controller

    api.reliability(controller.signal).then(
      (res) => {
        if (res.status === 'computing') {
          setReport(null)
          setError(null)
          setState('computing')
          return
        }
        setReport(res)
        setError(null)
        setState('ready')
      },
      (err: unknown) => {
        if (err instanceof ApiError && err.kind === 'aborted') return
        setError(err instanceof ApiError ? err.message : 'Could not load reliability metrics.')
        setState('error')
      },
    )
  }, [])

  useEffect(() => {
    request()
    return () => controllerRef.current?.abort()
  }, [request])

  const reload = useCallback(() => {
    setState('loading')
    setError(null)
    request()
  }, [request])

  const metrics = report?.metrics ?? {}
  const confusion = report?.confusion

  return (
    <div className="rise-in mx-auto w-full max-w-[1200px] px-3 py-6 sm:px-6 lg:py-9">
      <PageHeader
        eyebrow="Reliability"
        parent={{ to: '/', label: 'PiQuaChu' }}
        title="Detection reliability"
        meta="hermetic labeled corpus · not an external ground-truth benchmark"
        actions={
          <>
            {report?.stale && <Badge tone="warning">stale</Badge>}
            <Button size="sm" variant="ghost" onClick={reload} disabled={state === 'loading'}>
              <RefreshCw className="size-3.5" aria-hidden="true" />
              Refresh
            </Button>
          </>
        }
        description="These figures measure the scanner against its own labeled corpus. They are evidence about the engine, not a claim of complete cryptographic discovery."
      />

      {state === 'loading' && (
        <Panel>
          <p className="text-[13px] text-[var(--muted-foreground)]">
            Loading reliability metrics…
          </p>
        </Panel>
      )}

      {state === 'error' && (
        <Panel eyebrow="Error" title="Metrics unavailable">
          <EmptyState
            tone="error"
            icon={<Activity className="size-4" aria-hidden="true" />}
            title="The benchmark could not be read"
            description={error ?? 'The API returned an error.'}
            action={
              <Button size="sm" onClick={reload}>
                Retry
              </Button>
            }
          />
        </Panel>
      )}

      {state === 'computing' && (
        <Panel eyebrow="Benchmark" title="Running the corpus" highlighted>
          <div className="flex items-start gap-3">
            <span
              className="spin mt-1 size-4 shrink-0 rounded-full border-2 border-[var(--border-strong)] border-t-[var(--primary)]"
              aria-hidden="true"
            />
            <p className="text-[13px] leading-relaxed text-[var(--muted-foreground)]">
              The labeled corpus is being scanned in the background. Metrics appear once the
              run finishes — no placeholder values are shown in the meantime.
            </p>
          </div>
        </Panel>
      )}

      {state === 'ready' && report && (
        <div className="space-y-4">
          <Panel highlighted>
            <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
              <Stat label="Accuracy" value={pct(metrics.accuracy)} size="lg" />
              <Stat
                label="Precision"
                value={pct(metrics.precision)}
                size="lg"
                note={`false positives: ${confusion?.fp ?? '—'}`}
              />
              <Stat
                label="Recall"
                value={pct(metrics.recall)}
                size="lg"
                note={`false negatives: ${confusion?.fn ?? '—'}`}
              />
              <Stat
                label="F1"
                value={pct(metrics.f1)}
                size="lg"
                tone="primary"
              />
            </div>
          </Panel>

          <div className="grid gap-4 sm:grid-cols-3">
            <Panel eyebrow="Corpus" title="Sample base">
              <Stat
                label="Labeled cases"
                value={report.corpus_size ?? '—'}
                note="Hermetic synthetic corpus."
              />
            </Panel>
            <Panel eyebrow="Provenance" title="Metric source">
              <p className="font-mono text-[12px] text-[var(--foreground)]">
                {String(report.metric_source ?? 'unknown')}
              </p>
              <p className="mt-2 text-[11px] leading-snug text-[var(--muted-foreground)]">
                Internal regression evidence. External validation is reported separately.
              </p>
            </Panel>
            <Panel eyebrow="Freshness" title="Generated">
              <p className="font-mono text-[12px] text-[var(--foreground)]">
                {report.generated_at
                  ? new Date(report.generated_at).toLocaleString()
                  : '—'}
              </p>
              <p className="mt-2 text-[11px] text-[var(--muted-foreground)]">
                {typeof report.age_seconds === 'number'
                  ? `${report.age_seconds}s old${report.stale ? ' · flagged stale' : ''}`
                  : 'Age not reported.'}
              </p>
            </Panel>
          </div>

          <Panel eyebrow="External validation" title="Manually reviewed repositories">
            {(() => {
              const external = report.external_validation
              const measured =
                external &&
                external.metric_source === 'external-ground-truth' &&
                external.status === 'ready'
              if (!measured) {
                return (
                  <div className="space-y-2">
                    <Badge tone="neutral">not yet measured</Badge>
                    <p className="text-[12.5px] leading-relaxed text-[var(--muted-foreground)]">
                      {external?.note ??
                        'No external ground-truth run has been published for this deployment.'}
                    </p>
                    <p className="text-[11px] leading-relaxed text-[var(--muted-foreground)]">
                      This is different from a measured zero. The internal corpus figures above
                      do not stand in for external repository validation.
                    </p>
                  </div>
                )
              }
              const micro = external.micro ?? {}
              return (
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone="success">measured</Badge>
                    {external.generated_at && (
                      <span className="font-mono text-[10.5px] text-[var(--muted-foreground)]">
                        {formatExternalDate(external.generated_at)}
                      </span>
                    )}
                  </div>
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                    {(['precision', 'recall', 'f1', 'accuracy'] as const).map((metric) => (
                      <div key={metric}>
                        <p className="eyebrow capitalize">{metric}</p>
                        <p className="tnum mt-1 font-mono text-[13px]">
                          {typeof micro[metric] === 'number'
                            ? `${(Number(micro[metric]) * 100).toFixed(1)}%`
                            : '—'}
                        </p>
                      </div>
                    ))}
                  </div>
                  <p className="text-[11px] leading-relaxed text-[var(--muted-foreground)]">
                    Scores come from the published external report for this deployment. Per-target
                    detail is available in the raw API response.
                  </p>
                </div>
              )
            })()}
          </Panel>

          {confusion && (
            <Panel eyebrow="Confusion matrix" title="How the cases resolved">
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                {[
                  { label: 'True positive', value: confusion.tp, tone: 'success' as const },
                  { label: 'False positive', value: confusion.fp, tone: 'warning' as const },
                  { label: 'False negative', value: confusion.fn, tone: 'danger' as const },
                  { label: 'True negative', value: confusion.tn, tone: 'default' as const },
                ].map((cell) => (
                  <Stat key={cell.label} label={cell.label} value={cell.value} tone={cell.tone} />
                ))}
              </div>
            </Panel>
          )}

          <Separator />

          <p className="max-w-[76ch] text-[11px] leading-relaxed text-[var(--muted-foreground)]">
            A high internal score does not substitute for external ground-truth validation,
            and no score here proves that a given repository was comprehensively analysed.
          </p>
        </div>
      )}
    </div>
  )
}

export default ReliabilityPage
