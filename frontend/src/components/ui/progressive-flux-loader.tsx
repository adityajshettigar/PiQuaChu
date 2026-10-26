// frontend/src/components/ui/progressive-flux-loader.tsx
//
// Adapted from the supplied `progressive-flux-loader`. The supplied component
// runs a decorative loop and invents its own percentage; that is acceptable
// only as a non-operational preview, never for a live scan. This version:
//
//  * has an explicit `mode`: `determinate` (a real server percentage) or
//    `indeterminate` (no percentage is known — no number is shown);
//  * clamps out-of-range/NaN values and refuses to claim 100% unless the value
//    really is 100;
//  * fires `onComplete` exactly once per completion transition;
//  * announces the server phase through a polite live region, not every tick;
//  * exposes `role="progressbar"` with aria-value* only in determinate mode,
//    and `role="status"` without a value in indeterminate mode;
//  * respects prefers-reduced-motion (the sweep is disabled by CSS).
import {
  useEffect,
  useId,
  useMemo,
  useRef,
  type ReactNode,
} from 'react'
import { cn, clamp } from '@/lib/utils'

export type LoaderMode = 'determinate' | 'indeterminate'

export interface LoaderPhase {
  id: string
  label: string
}

export interface ProgressiveFluxLoaderProps {
  mode?: LoaderMode
  /** Real completion percentage (0–100). Ignored in indeterminate mode. */
  value?: number
  phases?: LoaderPhase[]
  /** Id of the phase the server reports as current. */
  activePhaseId?: string | null
  /** Accessible name of the progress region. */
  label?: string
  /** Truthful status line, e.g. the server job state. */
  statusText?: ReactNode
  onComplete?: () => void
  className?: string
}

function normalizePhases(phases: LoaderPhase[] | undefined): LoaderPhase[] {
  if (!phases) return []
  const seen = new Set<string>()
  return phases.filter((phase) => {
    const valid = Boolean(phase?.id) && Boolean(phase?.label)
    if (!valid || seen.has(phase.id)) return false
    seen.add(phase.id)
    return true
  })
}

export function ProgressiveFluxLoader({
  mode = 'indeterminate',
  value,
  phases,
  activePhaseId = null,
  label = 'Scan progress',
  statusText,
  onComplete,
  className,
}: ProgressiveFluxLoaderProps) {
  const statusId = useId()
  const headingId = useId()

  const determinate = mode === 'determinate' && Number.isFinite(value)
  const percent = determinate ? Math.round(clamp(value as number, 0, 100)) : null
  const busy = determinate ? percent! < 100 : true

  // Exactly one completion callback per transition into "complete".
  const completedRef = useRef(false)
  useEffect(() => {
    if (!determinate) {
      completedRef.current = false
      return
    }
    if (percent! >= 100 && !completedRef.current) {
      completedRef.current = true
      onComplete?.()
    } else if (percent! < 100) {
      completedRef.current = false
    }
  }, [determinate, percent, onComplete])

  const items = useMemo(() => normalizePhases(phases), [phases])
  const activeIndex = items.findIndex((phase) => phase.id === activePhaseId)
  const currentLabel = activeIndex >= 0 ? items[activeIndex].label : null

  return (
    <section
      aria-labelledby={headingId}
      aria-busy={busy}
      className={cn(
        'rounded-[var(--radius-lg)] border border-[var(--border)] bg-[var(--surface)] p-4',
        className,
      )}
    >
      <div className="flex items-baseline justify-between gap-3">
        <h2
          id={headingId}
          className="font-mono text-[11px] uppercase tracking-[0.14em] text-[var(--muted-foreground)]"
        >
          {label}
        </h2>
        {determinate && (
          <span className="tnum font-mono text-sm text-[var(--foreground)]">
            {percent}%
          </span>
        )}
      </div>

      <div
        role={determinate ? 'progressbar' : 'status'}
        aria-valuemin={determinate ? 0 : undefined}
        aria-valuemax={determinate ? 100 : undefined}
        aria-valuenow={determinate ? percent! : undefined}
        aria-valuetext={determinate ? `${percent}% complete` : undefined}
        aria-labelledby={headingId}
        className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-[var(--surface-subtle)]"
      >
        {determinate ? (
          <div
            className="h-full rounded-full bg-[var(--primary)] transition-[width] duration-500 ease-out"
            style={{ width: `${percent}%` }}
          />
        ) : (
          <div className="h-full w-1/3 rounded-full bg-[var(--primary)] opacity-70 motion-safe:animate-[flux-sweep_1.8s_ease-in-out_infinite]" />
        )}
        {determinate && <span className="sr-only">{percent}% complete</span>}
      </div>

      <p
        id={statusId}
        aria-live="polite"
        className="mt-2 min-h-[1.25rem] text-xs text-[var(--muted-foreground)]"
      >
        {statusText ??
          (determinate
            ? busy
              ? `In progress — ${percent}% reported by the server.`
              : 'Complete.'
            : 'Analysis in progress — the server has not reported a percentage.')}
      </p>

      {items.length > 0 && (
        <ol className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px]">
          {items.map((phase, index) => {
            const isCurrent = phase.id === activePhaseId
            const isDone =
              activeIndex >= 0 && index < activeIndex
            const isPending = activeIndex >= 0 && index > activeIndex
            return (
              <li
                key={phase.id}
                aria-current={isCurrent ? 'step' : undefined}
                className={cn(
                  'flex items-center gap-1.5',
                  isCurrent && 'text-[var(--foreground)]',
                  isDone && 'text-[var(--success)]',
                  isPending && 'text-[var(--muted-foreground)] opacity-70',
                )}
              >
                <span
                  aria-hidden="true"
                  className={cn(
                    'size-1.5 rounded-full',
                    isDone && 'bg-[var(--success)]',
                    isCurrent && 'bg-[var(--primary)]',
                    (isPending || activeIndex < 0) && 'bg-[var(--border-strong)]',
                  )}
                />
                {phase.label}
                {isCurrent && <span className="sr-only"> (current phase)</span>}
              </li>
            )
          })}
        </ol>
      )}

      {currentLabel && (
        <p className="sr-only" aria-live="polite">
          Current phase: {currentLabel}
        </p>
      )}
    </section>
  )
}

export default ProgressiveFluxLoader
