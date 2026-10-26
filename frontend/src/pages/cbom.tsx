// frontend/src/pages/cbom.tsx
//
// CBOM viewer for one stored scan. The document is fetched from the real
// endpoint and rendered as escaped text/structure. Four claims are kept apart:
// generated, downloaded, schema-valid, and "complete inventory" — this page can
// only observe the first two, so it does not assert the others.
import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ChevronDown, ChevronRight, Download, FileJson } from 'lucide-react'
import { Panel } from '@/components/ui/panel'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { EmptyState } from '@/components/ui/empty-state'
import { PageHeader } from '@/components/ui/page-header'
import { Skeleton } from '@/components/ui/skeleton'
import { apiDownload, api, ApiError, type ScanDetail } from '@/lib/api'
import { formatTimestamp } from '@/lib/utils'

type LoadState = 'loading' | 'ready' | 'notfound' | 'error'

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}
}

function asText(value: unknown, fallback = '—'): string {
  return typeof value === 'string' && value ? value : fallback
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

interface CryptoComponent {
  name: string
  type: string
  assetType: string
  primitive: string
  parameterSet: string
  version: string
}

function componentsOf(document: Record<string, unknown> | null): CryptoComponent[] {
  const raw = Array.isArray(document?.components) ? (document?.components as unknown[]) : []
  return raw.map((entry) => {
    const component = asRecord(entry)
    const properties = asRecord(component.cryptoProperties)
    const algorithm = asRecord(properties.algorithmProperties)
    return {
      name: asText(component.name, 'unnamed component'),
      type: asText(component.type, 'component'),
      assetType: asText(properties.assetType, '—'),
      primitive: asText(algorithm.primitive, '—'),
      parameterSet: asText(algorithm.parameterSetIdentifier, '—'),
      version: asText(component.version, ''),
    }
  })
}

export function CbomPage({ scanId }: { scanId?: number }) {
  const params = useParams<{ scanId: string }>()
  const id =
    scanId ?? (params.scanId && /^\d+$/.test(params.scanId) ? Number(params.scanId) : undefined)
  const { state: scanState, detail, error: scanError } = useScan(id)

  const [document, setDocument] = useState<Record<string, unknown> | null>(null)
  const [state, setState] = useState<LoadState>(id ? 'loading' : 'notfound')
  const [error, setError] = useState<string | null>(null)
  const [rawOpen, setRawOpen] = useState(false)
  const [showAll, setShowAll] = useState(false)
  const [downloadState, setDownloadState] = useState<'idle' | 'working' | 'done' | 'failed'>('idle')

  useEffect(() => {
    if (!id) return
    let cancelled = false
    const controller = new AbortController()
    api.cbom(id, controller.signal).then(
      (result) => {
        if (cancelled) return
        setDocument(result)
        setState('ready')
      },
      (err: unknown) => {
        if (cancelled) return
        if (err instanceof ApiError && err.kind === 'aborted') return
        if (err instanceof ApiError && err.kind === 'not_found') {
          setState('notfound')
          return
        }
        setError(err instanceof ApiError ? err.message : 'The CBOM could not be generated.')
        setState('error')
      },
    )
    return () => {
      cancelled = true
      controller.abort()
    }
  }, [id])

  const components = useMemo(() => componentsOf(document), [document])
  const cryptoAssets = components.filter((component) => component.type === 'cryptographic-asset')
  const specVersion = asText(document?.specVersion, 'not reported')
  const generated = asText(asRecord(document?.metadata).timestamp, '')

  const download = async () => {
    if (!id) return
    setDownloadState('working')
    try {
      const { blob, filename } = await apiDownload(`/api/v1/scans/${id}/cbom`)
      const url = URL.createObjectURL(blob)
      const anchor = window.document.createElement('a')
      anchor.href = url
      anchor.download = filename ?? `piquachu-cbom-${id}.json`
      window.document.body.appendChild(anchor)
      anchor.click()
      window.document.body.removeChild(anchor)
      URL.revokeObjectURL(url)
      setDownloadState('done')
    } catch {
      setDownloadState('failed')
    }
  }

  if (!id) {
    return (
      <div className="mx-auto w-full max-w-[1100px] px-4 py-8 sm:px-6">
        <Panel>
          <EmptyState
            tone="error"
            title="A scan id is required"
            description="A CBOM is generated from one stored scan."
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

  if (scanState === 'loading' || state === 'loading') {
    return (
      <div className="mx-auto w-full max-w-[1100px] px-4 py-8 sm:px-6">
        <Skeleton className="h-6 w-56" label="Loading the cryptographic inventory" />
        <Skeleton className="mt-4 h-24 w-full" />
        <Skeleton className="mt-3 h-48 w-full" />
      </div>
    )
  }

  if (state === 'notfound' || state === 'error' || (!document && scanState !== 'ready')) {
    return (
      <div className="mx-auto w-full max-w-[1100px] px-4 py-8 sm:px-6">
        <PageHeader eyebrow="CBOM" title="Inventory unavailable" meta={`scan #${id}`} />
        <Panel>
          <EmptyState
            tone="error"
            icon={<FileJson className="size-4" aria-hidden="true" />}
            title={state === 'notfound' || scanState === 'notfound' ? 'No artifact for this scan' : 'The artifact could not be generated'}
            description={
              state === 'notfound' || scanState === 'notfound'
                ? 'The scan does not exist for this tenant, or it has no stored result to inventory.'
                : (error ?? scanError ?? 'The API returned an error.')
            }
            action={
              <>
                <Button size="sm" onClick={() => window.location.reload()}>
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

  return (
    <div className="rise-in mx-auto w-full max-w-[1100px] px-4 py-8 sm:px-6 md:py-10">
      <PageHeader
        eyebrow="CBOM"
        parent={{ to: `/results/${id}`, label: 'Results' }}
        title="Cryptographic asset inventory"
        meta={`scan #${id} · ${detail?.filename ?? 'unnamed archive'} · ${formatTimestamp(detail?.timestamp)}`}
        actions={
          <Button size="sm" variant="secondary" onClick={() => void download()} disabled={downloadState === 'working'}>
            <Download className="size-3.5" aria-hidden="true" />
            {downloadState === 'working' ? 'Preparing…' : 'Download JSON'}
          </Button>
        }
        description="Generated on request from this scan's stored findings. It describes what the scanner observed in the files it inspected — it is not a certification of inventory completeness."
      />

      {downloadState === 'failed' && (
        <Panel className="mb-4" eyebrow="Download" title="The artifact was not downloaded">
          <p role="alert" className="text-[12.5px] text-[var(--danger)]">
            The request failed. The scan may no longer be readable by this tenant, or the API
            may be unavailable.
          </p>
        </Panel>
      )}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Panel>
          <p className="eyebrow">CycloneDX</p>
          <p className="mt-1.5 font-mono text-[1.6rem] leading-none text-[var(--value)]">{specVersion}</p>
          <p className="mt-1.5 text-[11px] text-[var(--muted-foreground)]">Specification version.</p>
        </Panel>
        <Panel>
          <p className="eyebrow">Components</p>
          <p className="tnum mt-1.5 font-mono text-[1.6rem] leading-none text-[var(--value)]">{components.length}</p>
          <p className="mt-1.5 text-[11px] text-[var(--muted-foreground)]">All reported components.</p>
        </Panel>
        <Panel>
          <p className="eyebrow">Crypto assets</p>
          <p className="tnum mt-1.5 font-mono text-[1.6rem] leading-none text-[var(--value)]">{cryptoAssets.length}</p>
          <p className="mt-1.5 text-[11px] text-[var(--muted-foreground)]">
            type = cryptographic-asset.
          </p>
        </Panel>
        <Panel>
          <p className="eyebrow">Generated</p>
          <p className="mt-1.5 font-mono text-[12px]">{generated ? formatTimestamp(generated) : 'not reported'}</p>
          <p className="mt-1.5 text-[11px] text-[var(--muted-foreground)]">
            {downloadState === 'done' ? 'Downloaded by this browser.' : 'Generated by the API on request.'}
          </p>
        </Panel>
      </div>

      <Panel className="mt-4" eyebrow="Structure" title="Reported components" flush>
        {components.length === 0 ? (
          <div className="px-4 py-8 text-[12.5px] text-[var(--muted-foreground)]">
            The document contains no components. An empty inventory means the generator had
            no mapped assets for this scan, not that the archive is free of cryptography.
          </div>
        ) : (
          <ul className="divide-y divide-[var(--border)]">
            {(showAll ? components : components.slice(0, 20)).map((component, index) => (
              <li key={`${component.name}-${index}`} className="px-4 py-3">
                <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                  <p className="min-w-0 break-all font-mono text-[12px] text-[var(--foreground)]">
                    {component.name}
                    {component.version ? ` @ ${component.version}` : ''}
                  </p>
                  <Badge tone={component.type === 'cryptographic-asset' ? 'primary' : 'neutral'}>
                    {component.type}
                  </Badge>
                </div>
                <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] sm:grid-cols-4">
                  <div>
                    <dt className="text-[var(--muted-foreground)]">Asset type</dt>
                    <dd className="font-mono">{component.assetType}</dd>
                  </div>
                  <div>
                    <dt className="text-[var(--muted-foreground)]">Primitive</dt>
                    <dd className="font-mono">{component.primitive}</dd>
                  </div>
                  <div>
                    <dt className="text-[var(--muted-foreground)]">Parameter set</dt>
                    <dd className="font-mono">{component.parameterSet}</dd>
                  </div>
                </dl>
              </li>
            ))}
          </ul>
        )}
        {components.length > 20 && (
          <div className="border-t border-[var(--border)] px-4 py-3">
            <Button size="sm" variant="ghost" onClick={() => setShowAll((value) => !value)}>
              {showAll ? 'Show first 20' : `Show all ${components.length}`}
            </Button>
          </div>
        )}
      </Panel>

      <Panel className="mt-4" eyebrow="Validation" title="What can and cannot be claimed here">
        <ul className="space-y-2 text-[12px] leading-relaxed text-[var(--muted-foreground)]">
          <li>
            <span className="text-[var(--foreground)]">Generated:</span> the API produced a
            document for this scan.
          </li>
          <li>
            <span className="text-[var(--foreground)]">Downloaded:</span>{' '}
            {downloadState === 'done' ? 'this browser received the artifact.' : 'not yet downloaded in this session.'}
          </li>
          <li>
            <span className="text-[var(--foreground)]">Schema validity:</span> the generator ships
            the official CycloneDX 1.7 schema and its CLI/test path validates against it; this
            page does not independently re-validate the response.
          </li>
          <li>
            <span className="text-[var(--foreground)]">Inventory completeness:</span> not claimed.
            Files outside the scanner's coverage cannot appear.
          </li>
        </ul>
      </Panel>

      <Panel className="mt-4" eyebrow="Raw artifact" title="CycloneDX JSON">
        <button
          type="button"
          onClick={() => setRawOpen((open) => !open)}
          aria-expanded={rawOpen}
          aria-controls="cbom-raw"
          className="inline-flex items-center gap-2 rounded-[var(--radius-sm)] text-[12px] text-[var(--muted-foreground)] transition-colors hover:text-[var(--foreground)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]"
        >
          {rawOpen ? <ChevronDown className="size-3.5" aria-hidden="true" /> : <ChevronRight className="size-3.5" aria-hidden="true" />}
          {rawOpen ? 'Collapse raw JSON' : 'Expand raw JSON'}
        </button>
        <div id="cbom-raw" hidden={!rawOpen}>
          {rawOpen && (
            <pre className="mt-3 max-h-[60vh] overflow-auto rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--background)] p-4 font-mono text-[11px] leading-relaxed text-[var(--foreground)]">
              {JSON.stringify(document, null, 2)}
            </pre>
          )}
        </div>
      </Panel>

      <div className="mt-5 flex flex-wrap gap-2">
        <Button size="sm" variant="secondary" asChild>
          <Link to={`/results/${id}/reports`}>All report formats</Link>
        </Button>
        <Button size="sm" variant="ghost" asChild>
          <Link to={`/results/${id}`}>Back to results</Link>
        </Button>
      </div>
    </div>
  )
}

export default CbomPage
