// frontend/src/pages/login.tsx
//
// Sign-in. The button starts a server-mediated OIDC Authorization Code + PKCE
// flow; no client secret, token or provider SDK exists in this bundle. When the
// server has no provider configured, the page says exactly that instead of
// offering a button that cannot work.
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ArrowRight, KeyRound, ShieldCheck } from 'lucide-react'
import { Panel } from '@/components/ui/panel'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useSession } from '@/lib/session'
import { loginUrl } from '@/lib/api'

function safeReturnTo(value: string | null): string {
  if (!value) return '/'
  if (!value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return '/'
  return value
}

export function LoginPage() {
  const [params] = useSearchParams()
  const returnTo = safeReturnTo(params.get('return_to'))
  const errorParam = params.get('error')
  const { state, session, signOut } = useSession()
  const [redirecting, setRedirecting] = useState(false)

  return (
    <div className="relative mx-auto flex min-h-[calc(100dvh-3.5rem)] w-full max-w-[520px] flex-col justify-center px-4 py-12 sm:px-6">
      <div className="lattice-field absolute inset-x-0 top-0 -z-10 h-64 opacity-60" aria-hidden="true" />

      <div className="mb-7 flex items-center gap-2.5">
        <span
          aria-hidden="true"
          className="grid size-8 place-items-center rounded-[var(--radius-md)] border border-[color-mix(in_oklch,var(--primary)_28%,transparent)] bg-[var(--primary-subtle)]"
        >
          <svg viewBox="0 0 20 20" className="size-[18px]" fill="none" strokeWidth="1.1">
            <path d="M10 2.5 16 6v8l-6 3.5L4 14V6z" className="stroke-[var(--primary)]" />
            <path
              d="M10 2.5V10m0 0 6-4m-6 4-6-4m6 4v7.5"
              className="stroke-[color-mix(in_oklch,var(--primary)_45%,transparent)]"
            />
          </svg>
        </span>
        <span className="text-[15px] font-semibold tracking-[-0.03em]">PiQuaChu</span>
      </div>

      <h1 className="text-[clamp(1.8rem,4vw,2.4rem)] font-medium leading-[1.05] tracking-[-0.035em]">
        Sign in to PiQuaChu
      </h1>
      <p className="mt-3 max-w-[46ch] text-[13px] leading-relaxed text-[var(--muted-foreground)]">
        Scans, findings and exports are scoped to a tenant. Signing in identifies you to this
        deployment so the API can enforce that boundary on every request.
      </p>

      {errorParam && (
        <Panel className="mt-5" eyebrow="Sign-in" title="The sign-in did not complete">
          <p role="alert" className="text-[12.5px] leading-relaxed text-[var(--danger)]">
            The identity provider response could not be verified, or the attempt expired. Start
            again; if it keeps failing, an operator should check the server log.
          </p>
        </Panel>
      )}

      <div className="mt-6">
        {state === 'loading' ? (
          <div className="space-y-3">
            <Skeleton className="h-11 w-full" label="Checking sign-in state" />
            <Skeleton className="h-4 w-2/3" />
          </div>
        ) : state === 'error' || !session ? (
          <Panel eyebrow="Unavailable" title="The API did not answer">
            <p className="text-[12.5px] leading-relaxed text-[var(--muted-foreground)]">
              Sign-in state could not be read from the configured API origin. Check the connection
              and try again.
            </p>
            <Button size="sm" className="mt-3" asChild>
              <Link to="/settings">Open connection settings</Link>
            </Button>
          </Panel>
        ) : session.authenticated ? (
          <Panel eyebrow="Signed in" title={session.principal?.name ?? 'This browser is signed in'}>
            <dl className="space-y-1.5 text-[12px]">
              <div className="flex justify-between gap-3">
                <dt className="text-[var(--muted-foreground)]">Tenant</dt>
                <dd className="font-mono text-[11px]">{session.principal?.tenant_id ?? '—'}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-[var(--muted-foreground)]">Role</dt>
                <dd className="font-mono text-[11px]">{session.principal?.role ?? '—'}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-[var(--muted-foreground)]">Method</dt>
                <dd className="font-mono text-[11px]">{session.method ?? '—'}</dd>
              </div>
            </dl>
            <div className="mt-4 flex flex-wrap gap-2">
              <Button size="sm" variant="primary" asChild>
                <Link to={returnTo}>
                  Continue
                  <ArrowRight className="size-3.5" aria-hidden="true" />
                </Link>
              </Button>
              {session.method === 'session' && (
                <Button size="sm" variant="ghost" onClick={() => void signOut()}>
                  Sign out
                </Button>
              )}
            </div>
          </Panel>
        ) : session.configured && session.providers.length > 0 ? (
          <Panel highlighted>
            <p className="eyebrow">Identity provider</p>
            <div className="mt-3 space-y-2">
              {session.providers.map((provider) => (
                <div key={provider.id}>
                  <a
                    href={loginUrl(returnTo)}
                    onClick={() => setRedirecting(true)}
                    className="inline-flex h-11 w-full items-center justify-center gap-2 rounded-[var(--radius-md)] border border-[var(--primary)] bg-[var(--primary)] px-5 text-[14px] font-medium text-[var(--primary-foreground)] transition-all duration-200 hover:brightness-110 hover:shadow-[0_0_20px_color-mix(in_oklch,var(--primary)_40%,transparent)] active:scale-[0.99] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--background)]"
                    aria-busy={redirecting}
                  >
                    <ShieldCheck className="size-4" aria-hidden="true" />
                    {redirecting ? 'Redirecting…' : `Continue with ${provider.name}`}
                  </a>
                  <p className="mt-2 break-all text-center font-mono text-[10px] text-[var(--muted-foreground)]">
                    {provider.issuer}
                  </p>
                </div>
              ))}
            </div>
            <p className="mt-4 text-[11px] leading-relaxed text-[var(--muted-foreground)]">
              You are redirected to your provider. PiQuaChu never asks for your password and never
              receives your provider credentials. The server verifies the returned identity token
              against the provider&apos;s published signing keys.
            </p>
          </Panel>
        ) : (
          <Panel eyebrow="Not configured" title="Single sign-on is not available on this server">
            <p className="text-[12.5px] leading-relaxed text-[var(--muted-foreground)]">
              No identity provider has been configured, so there is no working sign-in to offer.
              The deployment can still be used with a local API key.
            </p>
            {session.problems.length > 0 && (
              <div className="mt-3 border-t border-[var(--border)] pt-3">
                <p className="eyebrow mb-2">Operator configuration</p>
                <ul className="list-disc space-y-1.5 pl-4 text-[11px] leading-snug text-[var(--warning)]">
                  {session.problems.map((problem) => (
                    <li key={problem}>{problem}</li>
                  ))}
                </ul>
                <p className="mt-2 font-mono text-[10px] leading-relaxed text-[var(--muted-foreground)]">
                  PIQUACHU_OIDC_ISSUER · PIQUACHU_OIDC_CLIENT_ID · PIQUACHU_OIDC_REDIRECT_URI ·
                  PIQUACHU_SESSION_SECRET
                </p>
              </div>
            )}
            <div className="mt-4 flex flex-wrap gap-2">
              <Button size="sm" variant="secondary" asChild>
                <Link to={returnTo}>Continue with the configured key</Link>
              </Button>
              <Button size="sm" variant="ghost" asChild>
                <Link to="/settings">Connection settings</Link>
              </Button>
            </div>
          </Panel>
        )}
      </div>

      <div className="mt-6 flex items-start gap-2.5 text-[11px] leading-relaxed text-[var(--muted-foreground)]">
        <KeyRound className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
        <p>
          Sessions are held in an HttpOnly cookie and are only sent when the API is served from
          this origin. No token is written to local storage, and logging out clears the session.
        </p>
      </div>

      <div className="mt-6 flex flex-wrap items-center gap-3 border-t border-[var(--border)] pt-4 text-[11px]">
        <Link to="/" className="text-[var(--muted-foreground)] hover:text-[var(--foreground)]">
          Back to home
        </Link>
        <Badge tone="neutral">OIDC · PKCE</Badge>
      </div>
    </div>
  )
}

export default LoginPage
