// frontend/src/pages/findings.tsx
//
// The findings workbench: the investigation surface behind the results bento.
// Everything is read from the stored scan; filters and sorting operate on that
// real collection, and a filtered-empty result is never presented as a clean
// scan.
import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { FileSearch, FilterX, Search } from 'lucide-react'
import { Panel } from '@/components/ui/panel'
import { Badge, type BadgeTone } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { EmptyState } from '@/components/ui/empty-state'
import { PageHeader } from '@/components/ui/page-header'
import { Skeleton } from '@/components/ui/skeleton'
import { Sheet } from '@/components/ui/sheet'
import { api, ApiError, type Finding, type ScanDetail } from '@/lib/api'
import { cn, formatTimestamp } from '@/lib/utils'

const PAGE_SIZE = 60

const SEVERITY_OPTIONS = ['All severities', 'ERROR', 'WARNING', 'INFO'] as const
const SORT_OPTIONS = [
  { id: 'severity', label: 'Severity, then rule' },
  { id: 'rule', label: 'Rule id' },
  { id: 'location', label: 'File path' },
  { id: 'standard', label: 'Standard' },
] as const

type SortId = (typeof SORT_OPTIONS)[number]['id']

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 0,
  ERROR: 0,
  HIGH: 1,
  WARNING: 2,
  MEDIUM: 2,
  INFO: 3,
  LOW: 4,
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

function standardOf(finding: Finding): string {
  return typeof finding.nist_standard === 'string' && finding.nist_standard
    ? finding.nist_standard
    : 'Advisory'
}

function categoryOf(finding: Finding): string {
  return typeof finding.category === 'string' && finding.category ? finding.category : 'unknown'
}

function algorithmOf(finding: Finding): string {
  const value = finding.algorithm ?? finding.target_algorithm ?? finding.observed_value
  return typeof value === 'string' && value ? value : '—'
}

function fileOf(finding: Finding): string {
  return typeof finding.file === 'string' && finding.file ? finding.file : '—'
}

function lineOf(finding: Finding): string {
  const value = finding.line ?? finding.line_start
  return typeof value === 'number' || typeof value === 'string' ? String(value) : '—'
}

function findingKey(finding: Finding, index: number): string {
  if (typeof finding.fingerprint === 'string' && finding.fingerprint) return finding.fingerprint
  return `${ruleOf(finding)}-${fileOf(finding)}-${lineOf(finding)}-${index}`
}

function useScan(scanId: number | undefined) {
  const [state, setState] = useState<'loading' | 'ready' | 'notfound' | 'error'>(
    scanId ? 'loading' : 'notfound',
  )
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

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="font-mono text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
        {label}
      </dt>
      <dd className="mt-1 text-[12.5px] leading-relaxed text-[var(--foreground)]">{children}</dd>
    </div>
  )
}

function FindingDetail({ finding, scanId }: { finding: Finding; scanId: number }) {
  const snippet = Array.isArray(finding.snippet) ? finding.snippet : []
  const highlight = Number(finding.line ?? finding.line_start ?? -1)

  return (
    <div className="space-y-5 pb-8">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={severityTone(finding.severity)}>{finding.severity ?? 'unrated'}</Badge>
        <Badge tone="neutral">{standardOf(finding)}</Badge>
        <Badge tone={finding.pqc_compliant ? 'success' : 'neutral'}>
          {finding.pqc_compliant ? 'PQC evidence' : 'legacy evidence'}
        </Badge>
      </div>

      <div>
        <p className="font-mono text-[12px] text-[var(--foreground)]">{ruleOf(finding)}</p>
        <p className="mt-1 break-all font-mono text-[11px] text-[var(--muted-foreground)]">
          {fileOf(finding)}
          {lineOf(finding) !== '—' ? `:${lineOf(finding)}` : ''}
        </p>
      </div>

      <dl className="grid grid-cols-2 gap-4">
        <Field label="Category">{categoryOf(finding)}</Field>
        <Field label="Algorithm">{algorithmOf(finding)}</Field>
        <Field label="Engine">{finding.engine ?? 'not reported'}</Field>
        <Field label="Evidence type">{finding.evidence_type ?? 'not reported'}</Field>
        <Field label="Confidence">
          {finding.confidence ?? finding.confidence_tier ?? 'not reported'}
        </Field>
        <Field label="Verdict">{finding.verdict ?? 'not reported'}</Field>
      </dl>

      {finding.rationale && (
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
            Why the rule matched
          </p>
          <p className="mt-1.5 text-[12.5px] leading-relaxed text-[var(--foreground)]">
            {finding.rationale}
          </p>
        </div>
      )}

      {snippet.length > 0 && (
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
            Stored source context
          </p>
          <pre className="mt-2 max-h-64 overflow-auto rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--background)] p-3 font-mono text-[11px] leading-relaxed">
            {snippet.map((row) => (
              <span
                key={row.line}
                className={cn(
                  'block whitespace-pre',
                  row.line === highlight && 'bg-[var(--primary-subtle)] text-[var(--foreground)]',
                )}
              >
                <span className="mr-3 inline-block w-8 select-none text-right text-[var(--muted-foreground)]">
                  {row.line}
                </span>
                {row.text}
              </span>
            ))}
          </pre>
          <p className="mt-1.5 text-[10.5px] leading-snug text-[var(--muted-foreground)]">
            Rendered as escaped text. No source is executed or interpreted as HTML.
          </p>
        </div>
      )}

      <div>
        <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
          Recommendation
        </p>
        <p className="mt-1.5 text-[12.5px] leading-relaxed text-[var(--foreground)]">
          {finding.recommendation || 'No recommendation was stored for this finding.'}
        </p>
        {finding.target_algorithm && (
          <p className="mt-1.5 text-[12px] text-[var(--muted-foreground)]">
            Migration target: <span className="font-mono text-[var(--foreground)]">{finding.target_algorithm}</span>
          </p>
        )}
      </div>

      <div>
        <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
          Limitations
        </p>
        <p className="mt-1.5 text-[12px] leading-relaxed text-[var(--muted-foreground)]">
          {finding.limitations ??
            'Static pattern evidence only. It does not prove runtime behaviour, parameter correctness or module validation.'}
        </p>
      </div>

      <div className="flex flex-wrap gap-2 border-t border-[var(--border)] pt-4">
        <Button size="sm" variant="outline" asChild>
          <Link to={`/results/${scanId}/remediation`}>Open remediation plan</Link>
        </Button>
        <Button size="sm" variant="ghost" asChild>
          <Link to={`/results/${scanId}/findings`}>All findings</Link>
        </Button>
      </div>
    </div>
  )
}

export function FindingsPage({ scanId }: { scanId?: number }) {
  const params = useParams<{ scanId: string }>()
  const id =
    scanId ?? (params.scanId && /^\d+$/.test(params.scanId) ? Number(params.scanId) : undefined)
  const { state, detail, error } = useScan(id)

  const [searchParams, setSearchParams] = useSearchParams()
  const selected = searchParams.get('finding')

  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState<(typeof SEVERITY_OPTIONS)[number]>('All severities')
  const [sort, setSort] = useState<SortId>('severity')
  const [standard, setStandard] = useState('All standards')
  const [category, setCategory] = useState('All categories')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const findings = useMemo(() => detail?.findings ?? [], [detail])

  const standards = useMemo(
    () => ['All standards', ...new Set(findings.map(standardOf))].sort((a, b) =>
      a === 'All standards' ? -1 : b === 'All standards' ? 1 : a.localeCompare(b),
    ),
    [findings],
  )

  const categories = useMemo(
    () => ['All categories', ...new Set(findings.map(categoryOf))].sort((a, b) =>
      a === 'All categories' ? -1 : b === 'All categories' ? 1 : a.localeCompare(b),
    ),
    [findings],
  )

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase()
    const filtered = findings.filter((finding) => {
      if (severity !== 'All severities' && String(finding.severity).toUpperCase() !== severity) return false
      if (standard !== 'All standards' && standardOf(finding) !== standard) return false
      if (category !== 'All categories' && categoryOf(finding) !== category) return false
      if (!needle) return true
      return [
        ruleOf(finding),
        standardOf(finding),
        categoryOf(finding),
        algorithmOf(finding),
        fileOf(finding),
        lineOf(finding),
        String(finding.recommendation ?? ''),
        String(finding.rationale ?? ''),
      ]
        .join(' ')
        .toLowerCase()
        .includes(needle)
    })

    const sorted = [...filtered].sort((a, b) => {
      if (sort === 'rule') return ruleOf(a).localeCompare(ruleOf(b))
      if (sort === 'location') return fileOf(a).localeCompare(fileOf(b)) || Number(lineOf(a)) - Number(lineOf(b))
      if (sort === 'standard') return standardOf(a).localeCompare(standardOf(b)) || ruleOf(a).localeCompare(ruleOf(b))
      const rank =
        (SEVERITY_RANK[String(a.severity).toUpperCase()] ?? 5) -
        (SEVERITY_RANK[String(b.severity).toUpperCase()] ?? 5)
      return rank !== 0 ? rank : ruleOf(a).localeCompare(ruleOf(b))
    })
    return sorted
  }, [findings, query, severity, standard, category, sort])

  const selectedFinding = useMemo(() => {
    if (!selected) return null
    return findings.find((finding, index) => findingKey(finding, index) === selected) ?? null
  }, [findings, selected])

  const filtersActive =
    query.trim() !== '' ||
    severity !== 'All severities' ||
    standard !== 'All standards' ||
    category !== 'All categories'

  const clearFilters = () => {
    setQuery('')
    setSeverity('All severities')
    setStandard('All standards')
    setCategory('All categories')
    setLimit(PAGE_SIZE)
  }

  const openFinding = (finding: Finding, index: number) => {
    const next = new URLSearchParams(searchParams)
    next.set('finding', findingKey(finding, index))
    setSearchParams(next, { replace: true })
  }

  const closeFinding = () => {
    const next = new URLSearchParams(searchParams)
    next.delete('finding')
    setSearchParams(next, { replace: true })
  }

  if (!id) {
    return (
      <div className="mx-auto w-full max-w-[1100px] px-4 py-8 sm:px-6">
        <Panel>
          <EmptyState
            tone="error"
            title="A scan id is required"
            description="The findings workbench is scoped to one stored scan."
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
      <div className="mx-auto w-full max-w-[1280px] px-4 py-8 sm:px-6">
        <Skeleton className="h-6 w-56" label="Loading findings" />
        <Skeleton className="mt-5 h-10 w-full" />
        <div className="mt-4 space-y-2">
          {[0, 1, 2, 3, 4].map((row) => (
            <Skeleton key={row} className="h-11 w-full" />
          ))}
        </div>
      </div>
    )
  }

  if (state === 'notfound' || state === 'error' || !detail) {
    return (
      <div className="mx-auto w-full max-w-[1100px] px-4 py-8 sm:px-6">
        <PageHeader eyebrow="Findings" title="Scan unavailable" meta={`scan #${id}`} />
        <Panel>
          <EmptyState
            tone="error"
            icon={<FileSearch className="size-4" aria-hidden="true" />}
            title={state === 'notfound' ? 'No stored scan with this id' : 'The scan could not be read'}
            description={
              state === 'notfound'
                ? 'It may belong to another tenant or may not exist.'
                : (error ?? 'The API returned an error.')
            }
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
    <div className="rise-in mx-auto w-full max-w-[1320px] px-4 py-8 sm:px-6 md:py-10">
      <PageHeader
        eyebrow="Findings"
        parent={{ to: `/results/${detail.scan_id}`, label: 'Results' }}
        title="Findings workbench"
        meta={`scan #${detail.scan_id} · ${findingMeta(detail)}`}
        description="Every stored match, with its rule, location, evidence type and stated limitations. Filters apply to this scan only."
      />

      <div className="mb-4 flex flex-wrap items-end gap-2">
        <div className="min-w-[220px] flex-1">
          <label htmlFor="finding-search" className="eyebrow mb-1.5 block">
            Search
          </label>
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-[var(--muted-foreground)]"
              aria-hidden="true"
            />
            <input
              id="finding-search"
              type="search"
              value={query}
              onChange={(event) => {
                setQuery(event.target.value)
                setLimit(PAGE_SIZE)
              }}
              placeholder="Rule, file, algorithm, recommendation…"
              className="h-9 w-full rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--surface)] pl-8 pr-3 text-[12.5px] text-[var(--foreground)] placeholder:text-[var(--muted-foreground)] focus:border-[color-mix(in_oklch,var(--primary)_50%,transparent)] focus:outline-none focus:ring-2 focus:ring-[color-mix(in_oklch,var(--primary)_20%,transparent)]"
            />
          </div>
        </div>

        <FilterSelect label="Severity" value={severity} onChange={(value) => setSeverity(value as (typeof SEVERITY_OPTIONS)[number])} options={[...SEVERITY_OPTIONS]} />
        <FilterSelect label="Standard" value={standard} onChange={setStandard} options={standards} />
        <FilterSelect label="Category" value={category} onChange={setCategory} options={categories} />
        <FilterSelect
          label="Sort"
          value={sort}
          onChange={(value) => setSort(value as SortId)}
          options={SORT_OPTIONS.map((option) => option.id)}
          labels={Object.fromEntries(SORT_OPTIONS.map((option) => [option.id, option.label]))}
        />

        <Button size="sm" variant="ghost" onClick={clearFilters} disabled={!filtersActive}>
          <FilterX className="size-3.5" aria-hidden="true" />
          Clear
        </Button>
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-[var(--muted-foreground)]">
        <span>
          Showing <span className="font-mono text-[var(--foreground)]">{Math.min(visible.length, limit)}</span> of{' '}
          <span className="font-mono text-[var(--foreground)]">{visible.length}</span> matching
          {' '}({findings.length} stored)
        </span>
        {filtersActive && <Badge tone="info">filters active</Badge>}
      </div>

      {findings.length === 0 ? (
        <Panel>
          <EmptyState
            icon={<FileSearch className="size-4" aria-hidden="true" />}
            title="No findings recorded"
            description="The scanner matched no configured rule in this archive. That is not proof the code contains no cryptography — only that no rule fired."
            action={
              <Button size="sm" variant="secondary" asChild>
                <Link to={`/results/${detail.scan_id}`}>Back to results</Link>
              </Button>
            }
          />
        </Panel>
      ) : visible.length === 0 ? (
        <Panel>
          <EmptyState
            icon={<Search className="size-4" aria-hidden="true" />}
            title="No findings match these filters"
            description={`The scan still contains ${findings.length} finding(s). Clear the filters to see them.`}
            action={
              <Button size="sm" onClick={clearFilters}>
                Clear filters
              </Button>
            }
          />
        </Panel>
      ) : (
        <>
          {/* Desktop table */}
          <Panel flush className="hidden md:block">
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left">
                <thead>
                  <tr className="border-b border-[var(--border)]">
                    {['Severity', 'Rule', 'Standard', 'Category', 'Algorithm', 'Location', 'Engine'].map((heading) => (
                      <th
                        key={heading}
                        scope="col"
                        className="whitespace-nowrap px-3 py-2.5 font-mono text-[10px] uppercase tracking-[0.1em] text-[var(--muted-foreground)]"
                      >
                        {heading}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {visible.slice(0, limit).map((finding, index) => (
                    <tr
                      key={findingKey(finding, index)}
                      tabIndex={0}
                      onClick={() => openFinding(finding, index)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault()
                          openFinding(finding, index)
                        }
                      }}
                      aria-label={`${ruleOf(finding)}, ${severityOf(finding)}, ${fileOf(finding)}`}
                      className={cn(
                        'cursor-pointer border-b border-[var(--border)] transition-colors last:border-0 hover:bg-[var(--surface-subtle)]',
                        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--focus-ring)]',
                      )}
                    >
                      <td className="px-3 py-2 align-top">
                        <Badge tone={severityTone(finding.severity)}>{finding.severity ?? 'unrated'}</Badge>
                      </td>
                      <td className="max-w-[26ch] px-3 py-2 align-top">
                        <span className="block truncate font-mono text-[11px]" title={ruleOf(finding)}>
                          {ruleOf(finding)}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 align-top font-mono text-[10.5px] text-[var(--muted-foreground)]">
                        {standardOf(finding)}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 align-top text-[11px] text-[var(--muted-foreground)]">
                        {categoryOf(finding)}
                      </td>
                      <td className="max-w-[16ch] px-3 py-2 align-top">
                        <span className="block truncate font-mono text-[10.5px]" title={algorithmOf(finding)}>
                          {algorithmOf(finding)}
                        </span>
                      </td>
                      <td className="max-w-[28ch] px-3 py-2 align-top">
                        <span className="block truncate font-mono text-[10.5px]" title={fileOf(finding)}>
                          {fileOf(finding)}
                        </span>
                        <span className="text-[10px] text-[var(--muted-foreground)]">line {lineOf(finding)}</span>
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 align-top font-mono text-[10.5px] text-[var(--muted-foreground)]">
                        {finding.engine ?? '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          {/* Mobile list */}
          <ul className="space-y-2 md:hidden">
            {visible.slice(0, limit).map((finding, index) => (
              <li key={findingKey(finding, index)}>
                <button
                  type="button"
                  onClick={() => openFinding(finding, index)}
                  className="w-full rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--surface)] px-3 py-2.5 text-left"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone={severityTone(finding.severity)}>{finding.severity ?? 'unrated'}</Badge>
                    <span className="font-mono text-[11px]">{ruleOf(finding)}</span>
                  </div>
                  <p className="mt-1.5 break-all font-mono text-[10.5px] text-[var(--muted-foreground)]">
                    {fileOf(finding)}:{lineOf(finding)}
                  </p>
                  <p className="mt-1 text-[10.5px] text-[var(--muted-foreground)]">
                    {standardOf(finding)} · {categoryOf(finding)}
                  </p>
                </button>
              </li>
            ))}
          </ul>

          {visible.length > limit && (
            <div className="mt-4 flex justify-center">
              <Button size="sm" variant="outline" onClick={() => setLimit((value) => value + PAGE_SIZE)}>
                Show {Math.min(PAGE_SIZE, visible.length - limit)} more
              </Button>
            </div>
          )}
        </>
      )}

      <Sheet
        open={selectedFinding !== null}
        onOpenChange={(open) => {
          if (!open) closeFinding()
        }}
        title={selectedFinding ? ruleOf(selectedFinding) : 'Finding'}
        description={`scan #${detail.scan_id}`}
        side="right"
        widthClassName="w-[min(34rem,94vw)]"
      >
        {selectedFinding && <FindingDetail finding={selectedFinding} scanId={detail.scan_id} />}
      </Sheet>
    </div>
  )
}

function findingMeta(detail: ScanDetail): string {
  const timestamp = detail.timestamp ? `recorded ${formatTimestamp(detail.timestamp)}` : 'timestamp not reported'
  return `${detail.findings.length} stored · ${timestamp}`
}

function severityOf(finding: Finding): string {
  return finding.severity ? String(finding.severity).toLowerCase() : 'unrated'
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
  labels,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  options: string[]
  labels?: Record<string, string>
}) {
  const id = `filter-${label.toLowerCase()}`
  return (
    <div>
      <label htmlFor={id} className="eyebrow mb-1.5 block">
        {label}
      </label>
      <select
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-9 rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--surface)] px-2 text-[12px] text-[var(--foreground)] focus:border-[color-mix(in_oklch,var(--primary)_50%,transparent)] focus:outline-none focus:ring-2 focus:ring-[color-mix(in_oklch,var(--primary)_20%,transparent)]"
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {labels?.[option] ?? option}
          </option>
        ))}
      </select>
    </div>
  )
}

export default FindingsPage
