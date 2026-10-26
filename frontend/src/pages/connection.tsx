// frontend/src/pages/connection.tsx (exported as SettingsPage)
//
// Settings and connection. Everything here is verified from the client side:
// the API origin this build actually calls, whether a key is configured (never
// the key itself), live health/readiness, the real session the API reports, and
// the theme preference. No fake login, tenant switcher or admin controls.
import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Panel } from '@/components/ui/panel'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { PageHeader } from '@/components/ui/page-header'
import { useTheme } from '@/components/app-shell/theme-context'
import { useSession } from '@/lib/session'
import {
  api,
  API_BASE_URL,
  API_KEY,
  ApiError,
  type HealthResponse,
  type ReadinessResponse,
} from '@/lib/api'
import { cn } from '@/lib/utils'

type Fetched<T> =
  | { state: 'loading' }
  | { state: 'ok'; value: T }
  | { state: 'error'; message: string }

function useHealth() {
  const [health, setHealth] = useState<Fetched<HealthResponse>>({ state: 'loading' })
  const [ready, setReady] = useState<Fetched<ReadinessResponse>>({ state: 'loading' })

  const applyHealth = useCallback((value: HealthResponse) => {
    setHealth({ state: 'ok', value })
  }, [])
  const applyHealthError = useCallback((error: unknown) => {
    setHealth({
      state: 'error',
      message: error instanceof ApiError ? error.message : 'Health check failed.',
    })
  }, [])
  const applyReady = useCallback((value: ReadinessResponse) => {
    setReady({ state: 'ok', value })
  }, [])
  const applyReadyError = useCallback((error: unknown) => {
    setReady({
      state: 'error',
      message: error instanceof ApiError ? error.message : 'Readiness check failed.',
    })
  }, [])

  const request = useCallback(() => {
    api.health().then(applyHealth, applyHealthError)
    api.readiness().then(applyReady, applyReadyError)
  }, [applyHealth, applyHealthError, applyReady, applyReadyError])

  const reload = useCallback(() => {
    setHealth({ state: 'loading' })
    setReady({ state: 'loading' })
    request()
  }, [request])

  useEffect(() => {
    request()
  }, [request])

  return { health, ready, reload }
}

function Row({ label, value, mono = false }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-2 py-2">
      <dt className="text-[12px] text-[var(--muted-foreground)]">{label}</dt>
      <dd
        className={cn(
          'text-right text-[12px] text-[var(--foreground)]',
          mono && 'break-all font-mono text-[11px]',
        )}
      >
        {value}
      </dd>
    </div>
  )
}

function AccountPanel() {
  const { state, session, error, signOut } = useSession()

  return (
    <Panel eyebrow="Account" title="Identity used for this request">
      {state === 'loading' ? (
        <div className="space-y-2.5">
          <Skeleton className="h-4 w-1/2" label="Reading the session" />
          <Skeleton className="h-4 w-2/3" />
        </div>
      ) : state === 'error' || !session ? (
        <div className="space-y-2">
          <p className="text-[12.5px] text-[var(--danger)]">
            {error ?? 'The session endpoint did not answer.'}
          </p>
          <p className="text-[11px] text-[var(--muted-foreground)]">
            Credential state is unknown; no sign-in claim is made.
          </p>
        </div>
      ) : session.authenticated ? (
        <>
          <dl className="divide-y divide-[var(--border)]">
            <Row label="Principal" value={session.principal?.name ?? '—'} />
            <Row label="Tenant" value={session.principal?.tenant_id ?? '—'} mono />
            <Row label="Role" value={session.principal?.role ?? '—'} mono />
            <Row
              label="Method"
              value={
                <Badge tone={session.method === 'session' ? 'success' : 'warning'}>
                  {session.method === 'session' ? 'OIDC session' : 'shared API key'}
                </Badge>
              }
            />
            {session.expires_at && (
              <Row
                label="Session expires"
                value={new Date(session.expires_at * 1000).toLocaleString()}
                mono
              />
            )}
          </dl>
          {session.method === 'session' ? (
            <Button size="sm" className="mt-3" variant="outline" onClick={() => void signOut()}>
              Sign out
            </Button>
          ) : (
            <p className="mt-3 text-[11px] leading-relaxed text-[var(--muted-foreground)]">
              This build authenticates with a shared development key. For a real identity, the
              operator must configure an OIDC provider.
            </p>
          )}
        </>
      ) : (
        <>
          <p className="text-[12.5px] leading-relaxed text-[var(--muted-foreground)]">
            No credential is attached to this browser. Requests only succeed if the build has a
            key, or if you sign in with the configured provider.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <Button size="sm" variant="primary" asChild>
              <Link to="/login">Sign in</Link>
            </Button>
          </div>
        </>
      )}

      {session?.configured ? (
        <p className="mt-3 border-t border-[var(--border)] pt-3 text-[11px] text-[var(--muted-foreground)]">
          Provider: <span className="font-mono">{session.provider ?? 'OIDC'}</span> · issuer{' '}
          <span className="font-mono">{session.issuer ?? '—'}</span>
        </p>
      ) : (
        <div className="mt-3 border-t border-[var(--border)] pt-3">
          <p className="text-[11px] text-[var(--muted-foreground)]">
            Single sign-on is not configured on this server.
          </p>
          {session?.problems && session.problems.length > 0 && (
            <ul className="mt-1.5 list-disc space-y-1 pl-4 text-[10.5px] leading-snug text-[var(--warning)]">
              {session.problems.map((problem) => (
                <li key={problem}>{problem}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Panel>
  )
}

export function SettingsPage() {
  const { health, ready, reload } = useHealth()
  const { mode, setMode } = useTheme()
  const healthValue = health.state === 'ok' ? health.value : null

  return (
    <div className="rise-in mx-auto w-full max-w-[1100px] px-4 py-8 sm:px-6 md:py-10">
      <PageHeader
        eyebrow="Settings"
        title="Connection and environment"
        description="The API origin this build actually calls, its live checks, the identity attached to requests, and the boundary between this browser and the server."
        actions={
          <Button size="sm" onClick={() => void reload()}>
            Re-check
          </Button>
        }
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel eyebrow="Endpoint" title="API this browser talks to" highlighted>
          <dl className="divide-y divide-[var(--border)]">
            <Row label="Origin" value={API_BASE_URL} mono />
            <Row
              label="API key"
              value={
                API_KEY ? (
                  <Badge tone="warning">configured · dev key in bundle</Badge>
                ) : (
                  <Badge tone="neutral">not configured</Badge>
                )
              }
            />
            <Row label="Version" value={healthValue ? `v${healthValue.version}` : '—'} mono />
            <Row label="Environment" value={healthValue?.configuration.environment ?? '—'} mono />
            <Row label="Tenancy" value={healthValue?.configuration.tenancy_mode ?? '—'} mono />
            <Row label="Job backend" value={healthValue?.checks.job_backend ?? '—'} mono />
          </dl>
          <p className="mt-3 border-t border-[var(--border)] pt-3 text-[11px] leading-relaxed text-[var(--muted-foreground)]">
            Vite inlines <span className="font-mono">VITE_API_KEY</span> into the bundle, so it is
            only appropriate for a localhost-only deployment. Do not publish a build containing a
            production key.
          </p>
        </Panel>

        <AccountPanel />

        <Panel eyebrow="Health" title="Live checks">
          {health.state === 'loading' ? (
            <div className="space-y-2.5">
              <Skeleton className="h-4 w-1/2" label="Checking API health" />
              <Skeleton className="h-4 w-2/3" />
              <Skeleton className="h-4 w-1/3" />
            </div>
          ) : health.state === 'error' ? (
            <div className="space-y-3">
              <p role="alert" className="text-[13px] text-[var(--danger)]">
                {health.message}
              </p>
              <Button size="sm" onClick={() => void reload()}>
                Retry
              </Button>
            </div>
          ) : (
            <dl className="divide-y divide-[var(--border)]">
              <Row label="Service" value={health.value.service} />
              <Row
                label="Database"
                value={<Badge tone="success">{health.value.checks.database.status}</Badge>}
              />
              <Row
                label="Rate limiter"
                value={
                  <span className="flex items-center gap-1.5">
                    <Badge tone="neutral">{health.value.checks.rate_limiter.backend}</Badge>
                    <span className="text-[11px] text-[var(--muted-foreground)]">
                      failure mode: {health.value.checks.rate_limiter.failure_mode}
                    </span>
                  </span>
                }
              />
              <Row
                label="Readiness"
                value={
                  ready.state === 'ok' ? (
                    <Badge tone={ready.value.status === 'ready' ? 'success' : 'danger'}>
                      {ready.value.status.replace('_', ' ')}
                    </Badge>
                  ) : ready.state === 'error' ? (
                    <Badge tone="danger">unavailable</Badge>
                  ) : (
                    <Badge tone="neutral">checking</Badge>
                  )
                }
              />
            </dl>
          )}

          {healthValue && healthValue.configuration.warnings.length > 0 && (
            <>
              <Separator className="my-4" />
              <p className="eyebrow mb-2">Server configuration warnings</p>
              <ul className="list-disc space-y-1.5 pl-4 text-[11px] leading-snug text-[var(--warning)]">
                {healthValue.configuration.warnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            </>
          )}
        </Panel>

        <Panel eyebrow="Appearance" title="Theme">
          <p className="text-[12px] leading-relaxed text-[var(--muted-foreground)]">
            The preference is stored in this browser only. It is not sent to the API.
          </p>
          <div
            role="group"
            aria-label="Theme"
            className="mt-3 inline-flex rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--surface-raised)] p-0.5"
          >
            {(['light', 'dark'] as const).map((option) => (
              <button
                key={option}
                type="button"
                aria-pressed={mode === option}
                onClick={() => setMode(option)}
                className={cn(
                  'rounded-[var(--radius-sm)] px-3 py-1.5 text-[12px] capitalize transition-colors duration-200',
                  mode === option
                    ? 'bg-[var(--primary-subtle)] text-[var(--foreground)]'
                    : 'text-[var(--muted-foreground)] hover:text-[var(--foreground)]',
                )}
              >
                {option}
              </button>
            ))}
          </div>
          <p className="mt-3 text-[11px] leading-relaxed text-[var(--muted-foreground)]">
            The product is designed dark-first; the light theme is a warm mineral variant.
          </p>
        </Panel>

        <Panel eyebrow="Privacy" title="What leaves this machine">
          <ul className="space-y-2.5 text-[12px] leading-relaxed text-[var(--muted-foreground)]">
            <li>
              <span className="font-medium text-[var(--foreground)]">Browser scans</span> upload the
              selected archive to the API origin above. A browser upload is not
              &ldquo;local-only&rdquo; — the archive is transmitted to that server.
            </li>
            <li>
              <span className="font-medium text-[var(--foreground)]">CLI scans</span> run on the
              machine that invokes them and can be used without any telemetry.
            </li>
            <li>
              <span className="font-medium text-[var(--foreground)]">Remote AI enrichment</span> is
              opt-in on the server. When enabled, only allow-listed finding metadata and the
              assistant question are sent — never source text, file paths, secrets or the archive.
            </li>
            <li>
              <span className="font-medium text-[var(--foreground)]">Session cookies</span> are
              HttpOnly and SameSite=Lax, and are only sent when the API is served from the same
              origin as this app.
            </li>
          </ul>
        </Panel>

        <Panel eyebrow="Limits" title="Known boundaries" className="lg:col-span-2">
          <ul className="grid gap-2 text-[12px] leading-snug text-[var(--muted-foreground)] sm:grid-cols-2">
            <li>Static analysis cannot prove cryptographic absence.</li>
            <li>Runtime inventory is CLI-only and opt-in, not a browser feature.</li>
            <li>Readiness and weighted risk are separate measures, not a certification.</li>
            <li>The UI cannot cancel a job or apply patches: no such HTTP API exists.</li>
          </ul>
          <div className="mt-4 flex flex-wrap gap-2 border-t border-[var(--border)] pt-4">
            <Button size="sm" variant="ghost" asChild>
              <Link to="/">Back to home</Link>
            </Button>
            <Button size="sm" variant="ghost" asChild>
              <Link to="/reliability">Detection reliability</Link>
            </Button>
            <Button size="sm" variant="ghost" asChild>
              <Link to="/standards">Standards registry</Link>
            </Button>
          </div>
        </Panel>
      </div>
    </div>
  )
}

/** Backwards-compatible alias for older imports/tests. */
export const ConnectionPage = SettingsPage

export default SettingsPage
