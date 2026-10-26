// frontend/src/pages/scan-history.tsx
//
// Scan history. Reads the stored scans for this tenant and links each row to its
// results. Filtering and sorting apply to the returned rows only — the API has
// no server-side pagination yet, and the page says so.
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { FileArchive, RefreshCw, Search } from 'lucide-react'
import { Panel } from '@/components/ui/panel'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState } from '@/components/ui/empty-state'
import { PageHeader } from '@/components/ui/page-header'
import { api, ApiError, type ScanHistoryItem } from '@/lib/api'
import { formatTimestamp } from '@/lib/utils'

type LoadState = 'loading' | 'ready' | 'error'

function verdictTone(verdict: string | undefined): 'neutral' | 'success' | 'warning' | 'danger' {
  switch ((verdict || '').toLowerCase()) {
    case 'compliant': return 'success'
    case 'partial': return 'warning'
    case 'transitional': return 'warning'
    case 'non_compliant': return 'danger'
    case 'at_risk': return 'danger'
    default: return 'neutral'
  }
}

function verdictLabel(verdict: string | undefined): string {
  if (!verdict) return 'unknown'
  return verdict.replace(/_/g, ' ')
}

export function ScanHistoryPage() {
  const [scans, setScans] = useState<ScanHistoryItem[]>([])
  const [state, setState] = useState<LoadState>('loading')
  const [error, setError] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [verdict, setVerdict] = useState('All verdicts')
  const [sort, setSort] = useState<'newest' | 'oldest' | 'readiness'>('newest')

  const request = useCallback(() => {
    api.history().then(
      (res) => {
        setScans(Array.isArray(res.scans) ? res.scans : [])
        setError(null)
        setState('ready')
      },
      (err: unknown) => {
        if (err instanceof ApiError && err.kind === 'aborted') return
        setError(err instanceof ApiError ? err.message : 'History could not be loaded.')
        setState('error')
      },
    )
  }, [])

  useEffect(() => {
    request()
  }, [request])

  const reload = useCallback(() => {
    setState('loading')
    setError(null)
    request()
  }, [request])

  const verdicts = useMemo(
    () => ['All verdicts', ...new Set(scans.map((scan) => verdictLabel(scan.verdict)))],
    [scans],
  )

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase()
    const filtered = scans.filter((scan) => {
      if (verdict !== 'All verdicts' && verdictLabel(scan.verdict) !== verdict) return false
      if (!needle) return true
      return (
        (scan.filename || '').toLowerCase().includes(needle) ||
        String(scan.id).includes(needle) ||
        verdictLabel(scan.verdict).includes(needle)
      )
    })
    return [...filtered].sort((a, b) => {
      if (sort === 'readiness') return b.pqc_score - a.pqc_score
      if (sort === 'oldest') return a.id - b.id
      return b.id - a.id
    })
  }, [scans, query, verdict, sort])

  return (
    <div className="rise-in mx-auto w-full max-w-[1200px] px-4 py-8 sm:px-6 md:py-10">
      <PageHeader
        eyebrow="History"
        title="Recorded scans"
        meta={`${scans.length} returned · newest first · up to 50 per tenant`}
        actions={
          <Button size="sm" variant="ghost" onClick={reload} disabled={state === 'loading'}>
            <RefreshCw className="size-3.5" aria-hidden="true" />
            Refresh
          </Button>
        }
        description="Only scans the server stored appear here. Readiness is the scanner's pqc_score for that archive at the time it ran."
      />

      <div className="mb-4 flex flex-wrap items-end gap-2">
        <div className="min-w-[220px] flex-1">
          <label htmlFor="history-search" className="eyebrow mb-1.5 block">
            Search
          </label>
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-[var(--muted-foreground)]"
              aria-hidden="true"
            />
            <input
              id="history-search"
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Archive or scan id…"
              className="h-9 w-full rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--surface)] pl-8 pr-3 text-[12.5px] text-[var(--foreground)] placeholder:text-[var(--muted-foreground)] focus:border-[color-mix(in_oklch,var(--primary)_50%,transparent)] focus:outline-none focus:ring-2 focus:ring-[color-mix(in_oklch,var(--primary)_20%,transparent)]"
            />
          </div>
        </div>

        <div>
          <label htmlFor="history-verdict" className="eyebrow mb-1.5 block">
            Verdict
          </label>
          <select
            id="history-verdict"
            value={verdict}
            onChange={(event) => setVerdict(event.target.value)}
            className="h-9 rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--surface)] px-2 text-[12px] text-[var(--foreground)] focus:border-[color-mix(in_oklch,var(--primary)_50%,transparent)] focus:outline-none focus:ring-2 focus:ring-[color-mix(in_oklch,var(--primary)_20%,transparent)]"
          >
            {verdicts.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor="history-sort" className="eyebrow mb-1.5 block">
            Sort
          </label>
          <select
            id="history-sort"
            value={sort}
            onChange={(event) => setSort(event.target.value as typeof sort)}
            className="h-9 rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--surface)] px-2 text-[12px] text-[var(--foreground)] focus:border-[color-mix(in_oklch,var(--primary)_50%,transparent)] focus:outline-none focus:ring-2 focus:ring-[color-mix(in_oklch,var(--primary)_20%,transparent)]"
          >
            <option value="newest">Newest first</option>
            <option value="oldest">Oldest first</option>
            <option value="readiness">Highest readiness</option>
          </select>
        </div>
      </div>

      {state === 'error' && (
        <Panel className="mb-4" eyebrow="Error" title="History unavailable">
          <p role="alert" className="text-[13px] text-[var(--danger)]">
            {error}
          </p>
          {scans.length > 0 && (
            <p className="mt-2 text-[11px] text-[var(--muted-foreground)]">
              Showing the {scans.length} row(s) from the last successful load.
            </p>
          )}
          <Button size="sm" className="mt-3" onClick={reload}>
            Retry
          </Button>
        </Panel>
      )}

      {state === 'loading' ? (
        <Panel>
          <div className="space-y-3">
            {[0, 1, 2, 3].map((row) => (
              <Skeleton key={row} className="h-9 w-full" label={row === 0 ? 'Loading scan history' : undefined} />
            ))}
          </div>
        </Panel>
      ) : scans.length === 0 ? (
        <Panel>
          <EmptyState
            icon={<FileArchive className="size-4" aria-hidden="true" />}
            title="No scans recorded yet"
            description="Run a scan and its results appear here, addressable by scan id."
            action={
              <Button size="sm" variant="primary" asChild>
                <Link to="/scan">Start a scan</Link>
              </Button>
            }
          />
        </Panel>
      ) : visible.length === 0 ? (
        <Panel>
          <EmptyState
            icon={<Search className="size-4" aria-hidden="true" />}
            title="No scans match these filters"
            description={`${scans.length} scan(s) are available. Clear the search or choose a different verdict.`}
            action={
              <Button
                size="sm"
                onClick={() => {
                  setQuery('')
                  setVerdict('All verdicts')
                }}
              >
                Clear filters
              </Button>
            }
          />
        </Panel>
      ) : (
        <Panel flush>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left">
              <thead>
                <tr className="border-b border-[var(--border)]">
                  {['Scan', 'Archive', 'Recorded', 'Readiness', 'Verdict', ''].map((heading, i) => (
                    <th
                      key={heading || `col-${i}`}
                      scope="col"
                      className="whitespace-nowrap px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]"
                    >
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {visible.map((scan) => (
                  <tr
                    key={scan.id}
                    className="border-b border-[var(--border)] transition-colors last:border-0 hover:bg-[var(--surface-subtle)]"
                  >
                    <td className="whitespace-nowrap px-4 py-2.5 font-mono text-[11px] text-[var(--muted-foreground)]">
                      #{scan.id}
                    </td>
                    <td className="max-w-[36ch] px-4 py-2.5">
                      <Link
                        to={`/results/${scan.id}`}
                        className="block truncate font-mono text-[12px] transition-colors hover:text-[var(--primary)]"
                        title={scan.filename}
                      >
                        {scan.filename || 'unnamed archive'}
                      </Link>
                    </td>
                    <td className="whitespace-nowrap px-4 py-2.5 text-[11px] text-[var(--muted-foreground)]">
                      {formatTimestamp(scan.timestamp)}
                    </td>
                    <td className="tnum whitespace-nowrap px-4 py-2.5 font-mono text-[12px]">
                      {typeof scan.pqc_score === 'number' ? `${scan.pqc_score}/100` : '—'}
                    </td>
                    <td className="px-4 py-2.5">
                      <Badge tone={verdictTone(scan.verdict)}>{verdictLabel(scan.verdict)}</Badge>
                    </td>
                    <td className="whitespace-nowrap px-4 py-2.5 text-right">
                      <Link
                        to={`/results/${scan.id}`}
                        className="text-[11px] text-[var(--muted-foreground)] transition-colors hover:text-[var(--foreground)]"
                      >
                        Open
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      <p className="mt-3 text-[11px] leading-relaxed text-[var(--muted-foreground)]">
        Showing {visible.length} of {scans.length} returned row(s). Trend comparison across
        scans is not offered: scores produced by different engine versions are not directly
        comparable.
      </p>
    </div>
  )
}

export default ScanHistoryPage
