// frontend/src/pages/active-scan.tsx
//
// Task progress. The backend exposes states (PENDING / ANALYSING / SUCCESS /
// FAILED / TIMEOUT), not percentages, so progress is indeterminate and the
// timeline only shows milestones the server actually reported. No elapsed time
// is converted into a fake completion figure.
import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ArrowRight, Check, CircleAlert, FileArchive, RotateCw } from 'lucide-react'
import { Panel } from '@/components/ui/panel'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { PageHeader } from '@/components/ui/page-header'
import { EmptyState } from '@/components/ui/empty-state'
import { ProgressiveFluxLoader } from '@/components/ui/progressive-flux-loader'
import { api, type ScanJobResponse } from '@/lib/api'
import { cn } from '@/lib/utils'

type ScanState = 'pending' | 'analysing' | 'success' | 'failed' | 'timeout' | 'error'

function taskStatusLabel(status: string | undefined): string {
  switch (String(status ?? '').toUpperCase()) {
    case 'PENDING': return 'Queued'
    case 'ANALYSING': return 'Analysis in progress'
    case 'SUCCESS': return 'Complete'
    case 'FAILED': return 'Scan failed'
    case 'TIMEOUT': return 'Scan timed out'
    case '': return 'Starting'
    default: return String(status)
  }
}

function toScanState(status: string | undefined): ScanState {
  switch (String(status ?? '').toUpperCase()) {
    case 'SUCCESS': return 'success'
    case 'FAILED': return 'failed'
    case 'TIMEOUT': return 'timeout'
    case 'ANALYSING': return 'analysing'
    case 'PENDING': return 'pending'
    default: return 'pending'
  }
}

export function ActiveScanPage({ taskId }: { taskId?: string }) {
  const [state, setState] = useState<ScanState>('pending')
  const [job, setJob] = useState<ScanJobResponse | null>(null)
  const [pollError, setPollError] = useState<string | null>(null)
  const navigate = useNavigate()
  const controllerRef = useRef<AbortController | null>(null)

  useEffect(() => {
    if (!taskId) return

    let mounted = true
    let timer: ReturnType<typeof setInterval> | null = null
    const controller = new AbortController()
    controllerRef.current = controller

    const stop = () => {
      if (timer) clearInterval(timer)
      timer = null
    }

    const apply = (res: ScanJobResponse) => {
      if (!mounted) return
      setJob(res)
      setPollError(null)
      const next = toScanState(res.status)
      setState(next)

      if (next === 'success') {
        stop()
        // The stored scan is addressed by its numeric scan_id, not the task id.
        if (typeof res.scan_id === 'number') navigate(`/results/${res.scan_id}`)
      } else if (next === 'failed' || next === 'timeout') {
        stop()
      }
    }

    const fail = (error: unknown) => {
      if (!mounted) return
      // A transient polling failure keeps the last known state; only the very
      // first request turns the page into an error.
      setJob((previous) => {
        if (previous === null) setState('error')
        return previous
      })
      setPollError('The last status request failed. Retrying…')
      void error
    }

    api.job(taskId, controller.signal).then(apply, fail)

    timer = setInterval(() => {
      if (!mounted) return
      api.job(taskId, controller.signal).then(apply, fail)
    }, 3000)

    return () => {
      mounted = false
      stop()
      controller.abort()
    }
  }, [taskId, navigate])

  if (!taskId) {
    return (
      <div className="mx-auto w-full max-w-[1100px] px-4 py-8 sm:px-6">
        <Panel>
          <EmptyState
            tone="error"
            title="No task selected"
            description="This view is bound to a scan task. Start one from the scan page."
            action={
              <Button size="sm" variant="primary" asChild>
                <Link to="/scan">Start a scan</Link>
              </Button>
            }
          />
        </Panel>
      </div>
    )
  }

  if (state === 'error') {
    return (
      <div className="mx-auto w-full max-w-[1100px] px-4 py-8 sm:px-6">
        <PageHeader eyebrow="Scan" title="Task unavailable" meta={`task ${taskId}`} />
        <Panel>
          <EmptyState
            tone="error"
            icon={<CircleAlert className="size-4" aria-hidden="true" />}
            title="This task could not be read"
            description="The API did not return this job. It may have expired, it may belong to another tenant, or this build's key is not accepted."
            action={
              <>
                <Button size="sm" onClick={() => window.location.reload()}>
                  <RotateCw className="size-3.5" aria-hidden="true" />
                  Retry
                </Button>
                <Button size="sm" variant="ghost" asChild>
                  <Link to="/history">Scan history</Link>
                </Button>
              </>
            }
          />
        </Panel>
      </div>
    )
  }

  if (state === 'failed' || state === 'timeout') {
    return (
      <div className="rise-in mx-auto w-full max-w-[1100px] px-4 py-8 sm:px-6">
        <PageHeader
          eyebrow="Scan"
          title={state === 'failed' ? 'Scan failed' : 'Scan timed out'}
          meta={`task ${taskId}`}
          actions={<Badge tone="danger">{taskStatusLabel(job?.status)}</Badge>}
        />
        <Panel eyebrow="Terminal state" title="The job did not produce results">
          <p role="alert" className="text-[13px] text-[var(--danger)]">
            {job?.error ?? 'The server reported a terminal failure for this task.'}
          </p>
          <p className="mt-2 text-[12px] leading-relaxed text-[var(--muted-foreground)]">
            The archive was not stored as a result. Upload it again to retry; if it fails
            the same way, give an operator this task id and the server log will show the
            reason.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            <Button size="sm" variant="primary" asChild>
              <Link to="/scan">Start another scan</Link>
            </Button>
            <Button size="sm" variant="ghost" asChild>
              <Link to="/history">Scan history</Link>
            </Button>
          </div>
        </Panel>
      </div>
    )
  }

  const reported = String(job?.status ?? '').toUpperCase()
  const milestones = [
    {
      id: 'queued',
      label: 'Accepted and queued',
      done: Boolean(job),
      detail: 'The API returned 202 with a task id.',
    },
    {
      id: 'analysing',
      label: 'Analysis in progress',
      done: reported === 'ANALYSING' || reported === 'SUCCESS',
      detail: 'The worker is extracting and scanning the archive.',
    },
    {
      id: 'complete',
      label: 'Result stored',
      done: reported === 'SUCCESS',
      detail: 'A numeric scan id was written and the results are ready.',
    },
  ]

  return (
    <div className="rise-in mx-auto w-full max-w-[1100px] px-4 py-8 sm:px-6 md:py-12">
      <PageHeader
        eyebrow="Scan"
        parent={{ to: '/history', label: 'History' }}
        title="Analysis"
        meta={`task ${taskId}`}
        actions={<Badge tone="info">{taskStatusLabel(job?.status ?? 'PENDING')}</Badge>}
        description="This view polls the task itself. When the server reports success it moves to the stored results automatically, so a refresh here never loses the scan."
      />

      <div className="space-y-4">
        <Panel highlighted>
          <ProgressiveFluxLoader
            mode="indeterminate"
            label="Scan analysis"
            statusText={
              reported === 'ANALYSING'
                ? 'Analysis in progress — the server has not reported a percentage.'
                : reported === 'PENDING'
                  ? 'Queued — waiting for a worker to start.'
                  : 'Waiting for the first status response…'
            }
          />
        </Panel>

        <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <Panel eyebrow="Timeline" title="Reported milestones">
            <ol className="space-y-3">
              {milestones.map((milestone, index) => (
                <li key={milestone.id} className="flex gap-3">
                  <span
                    aria-hidden="true"
                    className={cn(
                      'mt-0.5 grid size-5 shrink-0 place-items-center rounded-full border',
                      milestone.done
                        ? 'border-[color-mix(in_oklch,var(--success)_40%,transparent)] bg-[var(--success-subtle)] text-[var(--success)]'
                        : 'border-[var(--border)] text-[var(--muted-foreground)]',
                    )}
                  >
                    {milestone.done ? (
                      <Check className="size-3" strokeWidth={2} />
                    ) : (
                      <span className="font-mono text-[9px]">{index + 1}</span>
                    )}
                  </span>
                  <div className="min-w-0">
                    <p
                      className={cn(
                        'text-[12.5px]',
                        milestone.done ? 'text-[var(--foreground)]' : 'text-[var(--muted-foreground)]',
                      )}
                    >
                      {milestone.label}
                      {milestone.done && <span className="sr-only"> (reported complete)</span>}
                    </p>
                    <p className="mt-0.5 text-[11px] leading-snug text-[var(--muted-foreground)]">
                      {milestone.detail}
                    </p>
                  </div>
                </li>
              ))}
            </ol>
            <p className="mt-4 border-t border-[var(--border)] pt-3 text-[11px] leading-relaxed text-[var(--muted-foreground)]">
              The scanner does not report sub-stage progress to this client, so no
              intermediate phases are shown.
            </p>
          </Panel>

          <Panel eyebrow="Job" title="Reported state">
            <dl className="space-y-2 text-[12px]">
              <div className="flex items-baseline justify-between gap-3">
                <dt className="text-[var(--muted-foreground)]">Status</dt>
                <dd className="font-mono text-[11px]">{job?.status ?? '—'}</dd>
              </div>
              <div className="flex items-baseline justify-between gap-3">
                <dt className="text-[var(--muted-foreground)]">Scan id</dt>
                <dd className="font-mono text-[11px]">
                  {typeof job?.scan_id === 'number' ? `#${job.scan_id}` : 'pending'}
                </dd>
              </div>
              <div className="flex items-baseline justify-between gap-3">
                <dt className="text-[var(--muted-foreground)]">Log lines</dt>
                <dd className="font-mono text-[11px]">{job?.logs?.length ?? 0}</dd>
              </div>
            </dl>

            {pollError && (
              <p role="status" className="mt-3 text-[11px] text-[var(--danger)]">
                {pollError}
              </p>
            )}

            <div className="mt-4 flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="secondary"
                disabled={typeof job?.scan_id !== 'number'}
                onClick={() => {
                  if (typeof job?.scan_id === 'number') navigate(`/results/${job.scan_id}`)
                }}
              >
                View results
                <ArrowRight className="size-3.5" aria-hidden="true" />
              </Button>
              <Button size="sm" variant="ghost" asChild>
                <Link to="/history">Scan history</Link>
              </Button>
            </div>
          </Panel>
        </div>

        {job?.logs && job.logs.length > 0 && (
          <Panel
            eyebrow="Log"
            title="Server-reported progress"
            aside={<Badge tone="neutral">{job.logs.length} lines</Badge>}
          >
            <p className="mb-3 flex items-center gap-1.5 text-[11px] text-[var(--muted-foreground)]">
              <FileArchive className="size-3.5" aria-hidden="true" />
              Latest entries from this task. Paths are shown relative to the archive.
            </p>
            <ol className="max-h-64 space-y-1.5 overflow-y-auto rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--background)] p-3">
              {job.logs.slice(-40).map((entry, index) => (
                <li key={`${entry.t}-${index}`} className="flex gap-3 font-mono text-[11px] leading-relaxed">
                  <span className="shrink-0 text-[var(--muted-foreground)]">{entry.level}</span>
                  <span className="min-w-0 break-words text-[var(--foreground)]">{entry.message}</span>
                </li>
              ))}
            </ol>
          </Panel>
        )}
      </div>
    </div>
  )
}

export default ActiveScanPage
