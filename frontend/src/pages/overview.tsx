// frontend/src/pages/overview.tsx
// Financial: the homepage. A broad promise on the left, a framed, real record on
// the right, then a ruled strip of supporting facts, a three-column capability
// matrix, the stored scan table, and a closing tinted field.
//
// Every number here is real: the readiness value comes from the latest stored
// scan, the standard counts come from the maintained registry. Nothing is
// invented to fill the frame.

import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight,
  ArrowUpRight,
  Boxes,
  FileSearch,
  Fingerprint,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react'
import { Panel } from '@/components/ui/panel'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { api, ApiError, type ScanHistoryItem } from '@/lib/api'
import { formatTimestamp } from '@/lib/utils'
import { STANDARDS } from '@/lib/standards'

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

function useScanHistory() {
  const [state, setState] = useState<LoadState>('loading')
  const [scans, setScans] = useState<ScanHistoryItem[]>([])
  const [error, setError] = useState<string | null>(null)
  const controllerRef = useRef<AbortController | null>(null)

  const applyHistory = useCallback((data: { scans?: ScanHistoryItem[] }) => {
    setScans(Array.isArray(data.scans) ? data.scans : [])
    setError(null)
    setState('ready')
  }, [])

  const applyError = useCallback((err: unknown) => {
    if (err instanceof ApiError && err.kind === 'aborted') return
    setError(err instanceof ApiError ? err.message : 'History could not be loaded.')
    setState('error')
  }, [])

  const request = useCallback(() => {
    controllerRef.current?.abort()
    const controller = new AbortController()
    controllerRef.current = controller
    api.history(controller.signal).then(applyHistory, applyError)
  }, [applyHistory, applyError])

  const reload = useCallback(() => {
    setState('loading')
    setError(null)
    request()
  }, [request])

  useEffect(() => {
    request()
    return () => controllerRef.current?.abort()
  }, [request])

  return { state, scans, error, reload }
}

const CAPABILITIES = [
  {
    id: 'discovery',
    icon: Fingerprint,
    label: '01 / Discovery',
    title: 'Every cryptographic call, with the rule that matched it',
    body: 'Static source, dependency, configuration and key-material analysis. Each finding keeps its file, line, engine and the evidence behind it, so a match can be checked rather than counted.',
  },
  {
    id: 'standards',
    icon: ShieldCheck,
    label: '02 / Standards',
    title: 'Findings mapped to the standard they actually relate to',
    body: 'Evidence is classified against FIPS 203, 204 and 205, and against FIPS 206 while it is still in development. Detection is evidence of a code pattern; it is never a claim of certification.',
  },
  {
    id: 'migration',
    icon: Boxes,
    label: '03 / Migration',
    title: 'A plan, a reviewable patch, and an inventory you can ship',
    body: 'Deterministic guidance per rule, a CycloneDX CBOM for the scan and SARIF output for CI. Suggestions stay labelled as suggestions; nothing is applied to your source from the browser.',
  },
] as const

const FINAL_STANDARDS = STANDARDS.filter((standard) => standard.lifecycle === 'final').length

const FACTS = [
  {
    value: String(STANDARDS.length),
    label: `${FINAL_STANDARDS} final NIST standards and one still in development`,
  },
  {
    value: '50 MB',
    label: 'Largest archive accepted for a single scan',
  },
  {
    value: '04',
    label: 'Evidence surfaces: source, dependencies, configuration, key material',
  },
  {
    value: '.zip',
    label: 'Archive format; every result is stored against a reopenable scan id',
  },
]

/** The framed value: the newest stored record, or its honest absence. */
function LatestEvidence({
  state,
  scans,
  error,
}: {
  state: LoadState
  scans: ScanHistoryItem[]
  error: string | null
}) {
  const latest = scans[0]

  if (state === 'loading') {
    return (
      <div className="space-y-4" aria-busy="true">
        <Skeleton className="h-3 w-32" label="Loading the latest scan" />
        <Skeleton className="h-12 w-40" />
        <Skeleton className="h-3 w-2/3" />
        <Skeleton className="h-9 w-44" />
      </div>
    )
  }

  if (state === 'error') {
    return (
      <div>
        <p role="alert" className="text-[13px] leading-[var(--leading-reading)] text-[var(--danger)]">
          {error}
        </p>
        <p className="mt-2 text-[13px] leading-[var(--leading-reading)] text-[var(--muted-foreground)]">
          The record could not be read. No placeholder result is shown in its place.
        </p>
      </div>
    )
  }

  if (!latest) {
    return (
      <div>
        <p className="font-mono text-[2.25rem] leading-none text-[var(--muted-foreground)]">—</p>
        <p className="mt-3 text-[14px] leading-[var(--leading-reading)] text-[var(--muted-foreground)]">
          Nothing recorded yet. Your first result appears here as soon as the server stores it.
        </p>
        <Button variant="primary" size="md" className="mt-5" asChild>
          <Link to="/scan">
            Start the first scan
            <ArrowRight className="size-4" aria-hidden="true" />
          </Link>
        </Button>
      </div>
    )
  }

  return (
    <div>
      <p className="eyebrow">Readiness</p>
      <p className="tnum mt-2 font-mono text-[clamp(2.75rem,4vw,3.5rem)] leading-none tracking-[-0.03em] text-[var(--value)]">
        {typeof latest.pqc_score === 'number' ? latest.pqc_score : '—'}
        <span className="ml-2 font-sans text-[14px] tracking-normal text-[var(--muted-foreground)]">
          / 100
        </span>
      </p>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Badge tone={verdictTone(latest.verdict)}>{verdictLabel(latest.verdict)}</Badge>
        <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
          scan #{latest.id}
        </span>
      </div>

      <p className="mt-4 truncate font-mono text-[13px] text-[var(--foreground)]" title={latest.filename}>
        {latest.filename || 'unnamed archive'}
      </p>
      <p className="mt-1 font-mono text-[13px] text-[var(--muted-foreground)]">
        {formatTimestamp(latest.timestamp)}
      </p>

      <Link
        to={`/results/${latest.id}`}
        className="mt-5 inline-flex items-center gap-2 rounded-[var(--radius-control)] border border-[var(--primary)] px-4 py-2 text-[13px] font-medium text-[var(--primary)] transition-colors duration-[var(--dp-motion-interaction)] hover:bg-[var(--primary)] hover:text-[var(--primary-foreground)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]"
      >
        Open the evidence
        <ArrowRight className="size-3.5" aria-hidden="true" />
      </Link>
    </div>
  )
}

function RecentTable({ scans }: { scans: ScanHistoryItem[] }) {
  const cell = 'px-4 py-3 align-middle'
  const head =
    'whitespace-nowrap px-4 py-2.5 font-mono text-[11px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]'

  return (
    <div className="overflow-x-auto border border-[var(--border)]">
      <table className="w-full min-w-[760px] border-collapse text-left">
        <thead>
          <tr className="border-b border-[var(--border)]">
            <th scope="col" className={head}>Scan</th>
            <th scope="col" className={head}>Archive</th>
            <th scope="col" className={head}>Recorded</th>
            <th scope="col" className={head}>Readiness</th>
            <th scope="col" className={head}>Verdict</th>
            <th scope="col" className={`${head} text-right`}>Result</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr
              key={scan.id}
              className="border-b border-[var(--border)] transition-colors duration-[var(--dp-motion-interaction)] last:border-0 hover:bg-[var(--surface-subtle)]"
            >
              <td className={`${cell} whitespace-nowrap font-mono text-[13px] text-[var(--muted-foreground)]`}>
                #{scan.id}
              </td>
              <td className={`${cell} max-w-[34ch]`}>
                <Link
                  to={`/results/${scan.id}`}
                  className="block truncate font-mono text-[13px] text-[var(--foreground)] hover:text-[var(--primary)]"
                  title={scan.filename}
                >
                  {scan.filename || 'unnamed archive'}
                </Link>
              </td>
              <td className={`${cell} whitespace-nowrap font-mono text-[13px] text-[var(--muted-foreground)]`}>
                {formatTimestamp(scan.timestamp)}
              </td>
              <td className={`${cell} tnum whitespace-nowrap font-mono text-[13px] text-[var(--value)]`}>
                {typeof scan.pqc_score === 'number' ? `${scan.pqc_score}/100` : '—'}
              </td>
              <td className={cell}>
                <Badge tone={verdictTone(scan.verdict)}>{verdictLabel(scan.verdict)}</Badge>
              </td>
              <td className={`${cell} whitespace-nowrap text-right`}>
                <Link
                  to={`/results/${scan.id}`}
                  className="inline-flex items-center gap-1 text-[13px] text-[var(--muted-foreground)] hover:text-[var(--primary)]"
                >
                  Open
                  <ArrowUpRight className="size-3.5" aria-hidden="true" />
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function OverviewPage() {
  const { state, scans, error, reload } = useScanHistory()
  const recent = scans.slice(0, 5)
  const latest = scans[0]

  return (
    <div className="mx-auto w-full max-w-[1280px] px-4 pb-0 pt-10 sm:px-6 md:pt-16 lg:px-10">
      {/* Hero ---------------------------------------------------------------- */}
      <section className="rise-in grid items-start gap-12 lg:grid-cols-[minmax(0,1.05fr)_minmax(0,0.8fr)] lg:gap-16">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-[var(--primary)]">
            Post-quantum discovery
          </p>

          <h1 className="mt-5 max-w-[18ch] text-[clamp(1.9rem,3.9vw,3.6rem)] font-medium leading-[1.06] tracking-[-0.03em] text-[var(--foreground)]">
            Understand your <span className="hero-mark">cryptographic exposure</span>.
          </h1>

          <p className="mt-6 max-w-[54ch] text-[16px] leading-[var(--leading-reading)] text-[var(--muted-foreground)]">
            PiQuaChu inspects a source archive and shows which cryptography it actually
            contains: the algorithms, the files and lines, the evidence its rules matched,
            how that evidence maps to the NIST post-quantum standards, and what to migrate
            first.
          </p>

          <div className="mt-8 flex flex-wrap items-center gap-3">
            <Button variant="primary" size="lg" asChild>
              <Link to="/scan">
                Start a scan
                <ArrowRight className="size-4" aria-hidden="true" />
              </Link>
            </Button>
            <Button variant="outline" size="lg" asChild>
              <Link to="/standards">Explore standards</Link>
            </Button>
            <span className="font-mono text-[13px] text-[var(--muted-foreground)]">
              .zip · up to 50 MB
            </span>
          </div>
        </div>

        {/* Framed value object: real record, thin offset outlines behind it. */}
        <div className="warm-light">
          <div className="offset-frame">
            <div className="rounded-[var(--radius-lg)] border border-[var(--border)] bg-[var(--surface)] p-5 sm:p-6">
              <div className="flex items-center justify-between gap-3 border-b border-[var(--border)] pb-3">
                <p className="eyebrow">Latest recorded evidence</p>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => void reload()}
                  aria-label="Reload scan history"
                >
                  <RefreshCw className="size-3.5" aria-hidden="true" />
                </Button>
              </div>

              <div className="pt-5">
                <LatestEvidence state={state} scans={scans} error={error} />
              </div>

              <dl className="mt-6 grid grid-cols-2 gap-x-4 gap-y-3 border-t border-[var(--border)] pt-4">
                {['Source', 'Dependencies', 'Configuration', 'Key material'].map((surface) => (
                  <div key={surface} className="flex items-center gap-2">
                    <span
                      aria-hidden="true"
                      className="size-1.5 rounded-full bg-[var(--value)]"
                    />
                    <dt className="font-mono text-[11px] uppercase tracking-[0.1em] text-[var(--muted-foreground)]">
                      {surface}
                    </dt>
                  </div>
                ))}
              </dl>
            </div>
          </div>
        </div>
      </section>

      {/* Ruled strip of supporting facts ------------------------------------- */}
      <section aria-label="Scope at a glance" className="mt-16 md:mt-20">
        <dl className="ruled-strip grid grid-cols-2 md:grid-cols-4">
          {FACTS.map((fact, index) => (
            <div
              key={fact.label}
              className={`px-4 py-5 md:px-5 ${index === 0 ? 'md:pl-0' : ''} ${
                index % 2 === 1 ? 'border-l border-[var(--border)] md:border-l-0' : ''
              } ${index > 1 ? 'border-t border-[var(--border)] md:border-t-0' : ''}`}
            >
              <dd className="tnum font-mono text-[1.6rem] leading-none text-[var(--value)]">
                {fact.value}
              </dd>
              <dt className="mt-2 text-[13px] leading-[var(--leading-reading)] text-[var(--muted-foreground)]">
                {fact.label}
              </dt>
            </div>
          ))}
        </dl>
      </section>

      {/* Paired introduction -------------------------------------------------- */}
      <section className="mt-16 grid gap-6 md:mt-20 md:grid-cols-[minmax(0,0.85fr)_minmax(0,1.15fr)] md:gap-16">
        <h2 className="text-[clamp(1.75rem,2.6vw,2.5rem)] font-medium leading-[1.05] tracking-[-0.02em]">
          Discovery, not certification.
        </h2>
        <p className="max-w-[62ch] text-[16px] leading-[var(--leading-reading)] text-[var(--muted-foreground)]">
          A clean scan, a high readiness score or a valid CBOM is not a FIPS 140 validation
          and not an audit certificate. What the record does give you is a checkable trail:
          the file, the line, the rule and the evidence behind every claim, so a migration
          decision can be reviewed by someone who did not run the scan.
        </p>
      </section>

      {/* Capability matrix ---------------------------------------------------- */}
      <section aria-labelledby="capabilities" className="mt-10 md:mt-12">
        <h2 id="capabilities" className="sr-only">
          What the scanner establishes
        </h2>
        <div className="grid border-t border-[var(--border)] md:grid-cols-3">
          {CAPABILITIES.map((capability, index) => {
            const Icon = capability.icon
            return (
              <article
                key={capability.id}
                className={`border-b border-[var(--border)] py-6 md:px-6 md:py-8 ${
                  index === 0 ? 'md:pl-0' : ''
                } ${index > 0 ? 'md:border-l md:border-[var(--border)]' : ''}`}
              >
                <div className="flex items-center gap-2">
                  <Icon className="size-4 text-[var(--primary)]" strokeWidth={1.6} aria-hidden="true" />
                  <p className="font-mono text-[11px] uppercase tracking-[0.14em] text-[var(--muted-foreground)]">
                    {capability.label}
                  </p>
                </div>
                <h3 className="mt-3 text-[17px] font-medium leading-[1.25] tracking-[-0.01em] text-[var(--foreground)]">
                  {capability.title}
                </h3>
                <p className="mt-2.5 text-[14px] leading-[var(--leading-reading)] text-[var(--muted-foreground)]">
                  {capability.body}
                </p>
              </article>
            )
          })}
        </div>
      </section>

      {/* Stored scans --------------------------------------------------------- */}
      <section aria-labelledby="recent" className="mt-14 md:mt-16">
        <div className="flex flex-wrap items-end justify-between gap-4 border-b border-[var(--border)] pb-4">
          <div>
            <h2
              id="recent"
              className="text-[clamp(1.4rem,2vw,1.85rem)] font-medium leading-[1.1] tracking-[-0.02em]"
            >
              Recent evidence
            </h2>
            <p className="mt-1.5 text-[14px] text-[var(--muted-foreground)]">
              Stored scans for this tenant, newest first.
            </p>
          </div>
          <Link
            to="/history"
            className="inline-flex items-center gap-1.5 font-mono text-[13px] text-[var(--primary)] hover:text-[var(--foreground)]"
          >
            All scans
            <ArrowUpRight className="size-3.5" aria-hidden="true" />
          </Link>
        </div>

        <div className="mt-5">
          {state === 'loading' && (
            <div className="space-y-2" aria-busy="true">
              <Skeleton className="h-10 w-full" label="Loading stored scans" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          )}

          {state === 'error' && (
            <Panel className="flex flex-wrap items-center justify-between gap-3">
              <p role="alert" className="text-[14px] text-[var(--danger)]">
                {error}
              </p>
              <Button size="sm" onClick={() => void reload()}>
                Retry
              </Button>
            </Panel>
          )}

          {state === 'ready' && recent.length === 0 && (
            <Panel className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-start gap-3">
                <FileSearch
                  className="mt-0.5 size-4 shrink-0 text-[var(--muted-foreground)]"
                  aria-hidden="true"
                />
                <div>
                  <p className="text-[15px] font-medium">No scans recorded yet</p>
                  <p className="mt-1 max-w-[56ch] text-[14px] leading-[var(--leading-reading)] text-[var(--muted-foreground)]">
                    Choose a .zip archive. It is sent to the configured API origin and analysed
                    there; results are stored against a scan id you can reopen.
                  </p>
                </div>
              </div>
              <Button size="sm" variant="primary" asChild>
                <Link to="/scan">Start a scan</Link>
              </Button>
            </Panel>
          )}

          {state === 'ready' && recent.length > 0 && <RecentTable scans={recent} />}
        </div>
      </section>

      {/* Narrow heading beside a wider benefit list --------------------------- */}
      <section className="mt-14 grid gap-6 md:mt-16 md:grid-cols-[minmax(0,0.75fr)_minmax(0,1.25fr)] md:gap-14">
        <div>
          <p className="eyebrow">Scope and trust</p>
          <h2 className="mt-2 text-[clamp(1.35rem,2vw,1.75rem)] font-medium leading-[1.1] tracking-[-0.02em]">
            What a scan does and does not prove
          </h2>
          <Link
            to="/reliability"
            className="mt-4 inline-flex items-center gap-1.5 font-mono text-[13px] text-[var(--primary)] hover:text-[var(--foreground)]"
          >
            Measured reliability
            <ArrowRight className="size-3.5" aria-hidden="true" />
          </Link>
        </div>

        <div>
          <ul className="divide-y divide-[var(--border)] border-y border-[var(--border)]">
            <li className="py-4 text-[14px] leading-[var(--leading-reading)] text-[var(--muted-foreground)]">
              <span className="text-[var(--foreground)]">Established:</span> static source
              patterns, dependency metadata, configuration values and key material present in
              the archive.
            </li>
            <li className="py-4 text-[14px] leading-[var(--leading-reading)] text-[var(--muted-foreground)]">
              <span className="text-[var(--foreground)]">Not established:</span> runtime
              behaviour, dynamically constructed algorithm names, or code in languages outside
              the engine&rsquo;s coverage.
            </li>
            <li className="py-4 text-[14px] leading-[var(--leading-reading)] text-[var(--muted-foreground)]">
              <span className="text-[var(--foreground)]">Never implied:</span> a clean scan, a
              high readiness score or a valid CBOM is not a FIPS 140 validation or an audit
              certificate.
            </li>
          </ul>

          <div className="mt-6">
            <p className="eyebrow">Standards tracked</p>
            <ul className="mt-3 divide-y divide-[var(--border)] border-y border-[var(--border)]">
              {STANDARDS.map((standard) => (
                <li
                  key={standard.id}
                  className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1.5 py-3"
                >
                  <span className="font-mono text-[13px] uppercase tracking-[0.1em] text-[var(--muted-foreground)]">
                    {standard.id}
                  </span>
                  <span className="text-[14px] font-medium text-[var(--foreground)]">
                    {standard.algorithm}
                  </span>
                  <Badge tone={standard.lifecycle === 'final' ? 'primary' : 'neutral'}>
                    {standard.lifecycleLabel}
                  </Badge>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      {/* Closing field -------------------------------------------------------- */}
      <section className="warm-light mt-16 border-t border-[var(--border)] bg-[var(--dp-color-ground-tint)] px-5 py-14 text-center sm:px-8 md:mt-20 md:py-16">
        <div className="mx-auto max-w-[64ch]">
          <p className="eyebrow">Start with the archive you already own</p>
          <h2 className="mt-3 text-[clamp(1.8rem,3.4vw,3rem)] font-medium leading-[1.02] tracking-[-0.02em]">
            {latest
              ? `Scan #${latest.id} is on record. The next archive takes one upload.`
              : 'One archive is enough to see what your code actually uses.'}
          </h2>
          <p className="mx-auto mt-4 max-w-[54ch] text-[16px] leading-[var(--leading-reading)] text-[var(--muted-foreground)]">
            Results are stored against a scan id you can reopen, export as SARIF or a CycloneDX
            CBOM, and hand to a reviewer without re-running the analysis.
          </p>
          <div className="mt-7 flex flex-wrap items-center justify-center gap-3">
            <Button variant="primary" size="lg" asChild>
              <Link to="/scan">
                Scan an archive
                <ArrowRight className="size-4" aria-hidden="true" />
              </Link>
            </Button>
            <Button variant="outline" size="lg" asChild>
              <Link to="/history">Open scan history</Link>
            </Button>
          </div>
        </div>
      </section>
    </div>
  )
}

export default OverviewPage
