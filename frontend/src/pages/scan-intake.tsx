// frontend/src/pages/scan-intake.tsx
// Minimalist Dark redesign: Archive intake with drag-and-drop and explicit submit.
// File is selected (browse or drop), then submitted explicitly. The API answers 202 with a task id.
//
// Implements Minimalist Dark: layered slate surfaces, amber accent, Space Grotesk headlines,
// glass-effect cards, ambient glow effects on interactive elements.

import { useCallback, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ArrowRight, FileArchive, UploadCloud, X } from 'lucide-react'
import { Panel } from '@/components/ui/panel'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { PageHeader } from '@/components/ui/page-header'
import { SpotlightCard } from '@/components/ui/spotlight-card'
import { ProgressiveFluxLoader } from '@/components/ui/progressive-flux-loader'
import { api, ApiError, MAX_UPLOAD_BYTES } from '@/lib/api'

type ScanState = 'idle' | 'submitting' | 'error'

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function ScanIntakePage() {
  const [state, setState] = useState<ScanState>('idle')
  const [file, setFile] = useState<File | null>(null)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)
  const navigate = useNavigate()
  const fileRef = useRef<HTMLInputElement>(null)

  const chooseFile = useCallback((next: File | null) => {
    setErrorMessage(null)
    setState('idle')

    if (!next) {
      setFile(null)
      return
    }
    if (!next.name.toLowerCase().endsWith('.zip')) {
      setFile(null)
      setErrorMessage('Only .zip archives are accepted. The server enforces the same rule.')
      return
    }
    if (next.size > MAX_UPLOAD_BYTES) {
      setFile(null)
      setErrorMessage(
        `That archive is ${formatBytes(next.size)}; the limit is ${formatBytes(MAX_UPLOAD_BYTES)}.`
      )
      return
    }
    setFile(next)
  }, [])

  const submitScan = useCallback(async () => {
    if (!file || state === 'submitting') return
    setState('submitting')
    setErrorMessage(null)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const result = await api.submitScan(formData)
      if (result && typeof result.task_id === 'string' && result.task_id) {
        navigate(`/scan/${result.task_id}`)
        return
      }
      setErrorMessage('The API returned no task id, so this upload cannot be tracked.')
      setState('error')
    } catch (e: unknown) {
      setErrorMessage(e instanceof ApiError ? e.message : 'Scan submission failed.')
      setState('error')
    }
  }, [file, navigate, state])

  return (
    <div className="rise-in mx-auto w-full max-w-[1120px] px-4 py-8 sm:px-6 md:py-12">
      <PageHeader
        eyebrow="Scan"
        title="Scan a codebase"
        meta=".zip · one archive per run"
        description="PiQuaChu inspects a supported archive for cryptographic usage and migration-relevant evidence. The archive is uploaded to the configured API origin; nothing is read or executed in the browser."
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
        <SpotlightCard className="rounded-[var(--radius-lg)] border border-[var(--border)] bg-[var(--surface)]">
          <div
            onDragOver={(event) => {
              event.preventDefault()
              setDragging(true)
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(event) => {
              event.preventDefault()
              setDragging(false)
              chooseFile(event.dataTransfer.files?.[0] ?? null)
            }}
            className={`lattice-field rounded-[var(--radius-lg)] p-6 sm:p-9 transition-colors duration-200 sm:p-9 ${dragging ? 'bg-[color-mix(in_oklch,var(--primary)_28%,transparent)]' : ''}`}
          >
            <p className="eyebrow">Archive</p>

            {!file && state !== 'submitting' && (
              <>
                <h2 className="mt-3 text-[clamp(1.4rem,3vw,1.85rem)] font-medium leading-tight tracking-[-0.03em]">
                  Drop a source archive here
                </h2>
                <p className="mt-2 max-w-[48ch] text-[13px] leading-relaxed text-[var(--muted-foreground)]">
                  or browse files. ZIP only, up to {formatBytes(MAX_UPLOAD_BYTES)}. Nothing is uploaded until you press Analyze.
                </p>
                <div className="mt-6 flex flex-wrap items-center gap-3">
                  <Button variant="primary" onClick={() => fileRef.current?.click()}>
                    <UploadCloud className="size-4" aria-hidden="true" />
                    Browse files
                  </Button>
                  <span className="font-mono text-[11px] text-[var(--muted-foreground)]">
                    .zip only
                  </span>
                </div>
              </>
            )}

            {file && state !== 'submitting' && (
              <div>
                <div className="flex items-start gap-3">
                  <span
                    aria-hidden="true"
                    className="grid size-9 shrink-0 place-items-center rounded-[var(--radius-md)] border border-[color-mix(in_oklch,var(--primary)_28%,transparent)] bg-[var(--primary-subtle)] text-[var(--primary)]"
                  >
                    <FileArchive className="size-4" strokeWidth={1.6} />
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-[13px]" title={file.name}>
                      {file.name}
                    </p>
                    <p className="mt-1 text-[11px] text-[var(--muted-foreground)]">
                      {formatBytes(file.size)} · ready to submit
                    </p>
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    aria-label="Remove selected archive"
                    onClick={() => chooseFile(null)}
                  >
                    <X className="size-3.5" aria-hidden="true" />
                  </Button>
                </div>

                <div className="mt-6 flex flex-wrap items-center gap-2">
                  <Button variant="primary" onClick={() => void submitScan()}>
                    Analyze archive
                    <ArrowRight className="size-4" aria-hidden="true" />
                  </Button>
                  <Button variant="ghost" onClick={() => fileRef.current?.click()}>
                    Replace
                  </Button>
                </div>
              </div>
            )}

            {state === 'submitting' && (
              <div className="mt-2">
                <p className="text-[13px] text-[var(--muted-foreground)]">
                  Uploading{' '}
                  <span className="font-mono text-[var(--foreground)]">{file?.name}</span>…
                </p>
                <div className="mt-4">
                  <ProgressiveFluxLoader mode="indeterminate" label="Uploading archive" />
                </div>
              </div>
            )}

            <div className="mt-6 border-t border-[var(--border)] pt-4">
              <label htmlFor="scan-archive" className="sr-only">
                Choose a source archive
              </label>
              <input
                id="scan-archive"
                type="file"
                accept=".zip,application/zip"
                ref={fileRef}
                onChange={(event) => chooseFile(event.target.files?.[0] ?? null)}
                className="sr-only"
              />
              <p className="text-[11px] leading-relaxed text-[var(--muted-foreground)]">
                The archive is sent to the API origin this build is configured with. It is unpacked in an isolated temporary directory with entry, size, compression and path-traversal limits, then deleted. Uploaded code is never executed.
              </p>
            </div>
          </div>
        </SpotlightCard>

        <div className="space-y-4">
          <Panel eyebrow="Pre-flight" title="What happens next">
            <ol className="space-y-3 text-[12px] leading-relaxed text-[var(--muted-foreground)]">
              {
                [
                  'The server validates the archive before dispatch: entry count, zip bombs, paths, symlinks.',
                  'A background job is queued and given a task id.',
                  'The task view polls that job and reports its real state — no invented percentage.',
                  'Results are stored against a numeric scan id you can reopen from history.',
                ].map((step, index) => (
                  <li key={step} className="flex gap-2.5">
                    <span className="mt-0.5 font-mono text-[10px] text-[var(--primary)]">
                      {String(index + 1).padStart(2, '0')}
                    </span>
                    {step}
                  </li>
                ))}
              </ol>
            </Panel>

            <Panel eyebrow="Limits" title="Upload rules">
              <dl className="space-y-2 text-[12px] leading-snug">
                <div className="flex items-center justify-between gap-2">
                  <dt className="text-[var(--muted-foreground)]">Format</dt>
                  <dd><Badge tone="neutral">.zip</Badge></dd>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <dt className="text-[var(--muted-foreground)]">Maximum size</dt>
                  <dd><Badge tone="neutral">{formatBytes(MAX_UPLOAD_BYTES)}</Badge></dd>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <dt className="text-[var(--muted-foreground)]">Duplicate submit</dt>
                  <dd><Badge tone="neutral">blocked while pending</Badge></dd>
                </div>
              </dl>
            </Panel>
        </div>
      </div>

      {errorMessage && (
        <Panel className="mt-4" eyebrow="Upload failed" title="The archive was not accepted">
          <p role="alert" className="text-[13px] text-[var(--danger)]">
            {errorMessage}
          </p>
          <p className="mt-2 text-[11px] text-[var(--muted-foreground)]">
            Nothing was queued. Choose the archive again to retry, or check the API connection if the request could not be sent.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            <Button size="sm" onClick={() => fileRef.current?.click()}>
              Choose another archive
            </Button>
            <Button size="sm" variant="ghost" asChild>
              <Link to="/settings">Check the API connection</Link>
            </Button>
          </div>
        </Panel>
      )}
    </div>
  )
}

export default ScanIntakePage