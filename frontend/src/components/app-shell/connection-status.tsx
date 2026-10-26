// frontend/src/components/app-shell/connection-status.tsx
//
// Reports the API's real health. There is no hard-coded "all systems
// operational" light: before the first successful probe the state is
// "not checked", and an unreachable API is shown as unavailable.
import { useCallback, useEffect, useRef, useState } from 'react'
import { CircleAlert, CircleCheck, CircleDashed, RefreshCw } from 'lucide-react'
import { api, ApiError, type HealthResponse } from '@/lib/api'
import { cn } from '@/lib/utils'

type ConnectionState = 'idle' | 'checking' | 'online' | 'unreachable'

export interface ConnectionStatusProps {
  /** Dense form for headers: dot + short label, detail in the title tooltip. */
  compact?: boolean
  className?: string
}

export function ConnectionStatus({ compact = false, className }: ConnectionStatusProps) {
  // The provider is probed on mount, so "checking" is the truthful initial state.
  const [state, setState] = useState<ConnectionState>('checking')
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [detail, setDetail] = useState<string | null>(null)
  const controllerRef = useRef<AbortController | null>(null)

  const applyHealth = useCallback((result: HealthResponse) => {
    setHealth(result)
    setDetail(null)
    setState('online')
  }, [])

  const applyError = useCallback((error: unknown) => {
    if (error instanceof ApiError && error.kind === 'aborted') return
    setHealth(null)
    setDetail(
      error instanceof ApiError ? error.message : 'The API could not be reached.',
    )
    setState('unreachable')
  }, [])

  const probe = useCallback(() => {
    controllerRef.current?.abort()
    const controller = new AbortController()
    controllerRef.current = controller
    api.health(controller.signal).then(applyHealth, applyError)
  }, [applyHealth, applyError])

  useEffect(() => {
    probe()
    return () => controllerRef.current?.abort()
  }, [probe])

  const recheck = useCallback(() => {
    setState('checking')
    probe()
  }, [probe])

  const label =
    state === 'online'
      ? 'API connected'
      : state === 'checking'
        ? 'Checking API'
        : state === 'unreachable'
          ? 'API unavailable'
          : 'Not checked'

  const Icon =
    state === 'online'
      ? CircleCheck
      : state === 'unreachable'
        ? CircleAlert
        : CircleDashed

  const tone =
    state === 'online'
      ? 'text-[var(--success)]'
      : state === 'unreachable'
        ? 'text-[var(--danger)]'
        : 'text-[var(--muted-foreground)]'

  const title =
    state === 'online' && health
      ? `${health.service} v${health.version} · ${health.configuration.environment} · ${health.configuration.tenancy_mode} tenancy · ${health.checks.job_backend} jobs`
      : (detail ?? label)

  return (
    <div
      className={cn(
        'inline-flex items-center gap-1.5 rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--surface)] px-2 py-1',
        className,
      )}
      title={title}
    >
      <Icon className={cn('size-3.5 shrink-0', tone)} aria-hidden="true" />
      <span
        className={cn(
          'font-mono text-[10px] uppercase tracking-[0.1em]',
          state === 'unreachable' ? 'text-[var(--danger)]' : 'text-[var(--muted-foreground)]',
        )}
      >
        {label}
      </span>
      {health && !compact && (
        <span className="font-mono text-[10px] text-[var(--muted-foreground)]">
          v{health.version}
        </span>
      )}
      <button
        type="button"
        onClick={recheck}
        disabled={state === 'checking'}
        aria-label="Re-check API connection"
        className="ml-0.5 rounded-[var(--radius-sm)] p-0.5 text-[var(--muted-foreground)] hover:text-[var(--foreground)] disabled:opacity-50"
      >
        <RefreshCw
          className={cn('size-3', state === 'checking' && 'motion-safe:animate-spin')}
          aria-hidden="true"
        />
      </button>
    </div>
  )
}
