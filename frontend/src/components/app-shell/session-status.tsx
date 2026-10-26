// frontend/src/components/app-shell/session-status.tsx
//
// The header's account region. It shows what the API actually reports: a
// signed-in identity, a shared API key, or no credential at all. There is no
// invented avatar and no optimistic "logged in" state.
import { Link, useLocation } from 'react-router-dom'
import { LogIn, LogOut, UserRound } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useSession } from '@/lib/session'

export interface SessionStatusProps {
  /** Right-aligned header form. */
  compact?: boolean
  className?: string
}

export function SessionStatus({ compact = false, className }: SessionStatusProps) {
  const { state, session, error, signOut } = useSession()
  const location = useLocation()

  if (state === 'loading') {
    return (
      <span
        className={cn(
          'font-mono text-[10px] uppercase tracking-[0.1em] text-[var(--muted-foreground)]',
          className,
        )}
        aria-hidden="true"
      >
        …
      </span>
    )
  }

  if (state === 'error' || !session) {
    return (
      <span
        className={cn(
          'font-mono text-[10px] uppercase tracking-[0.1em] text-[var(--muted-foreground)]',
          className,
        )}
        title={error ?? 'The session endpoint did not answer.'}
      >
        auth unknown
      </span>
    )
  }

  if (!session.authenticated) {
    return (
      <Link
        to={`/login?return_to=${encodeURIComponent(location.pathname)}`}
        className={cn(
          'inline-flex items-center gap-1.5 rounded-[var(--radius-md)] border border-[var(--border)] px-2.5 py-1.5',
          'text-[12px] text-[var(--foreground)] transition-colors hover:border-[var(--border-strong)] hover:bg-[var(--surface-subtle)]',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]',
          className,
        )}
      >
        <LogIn className="size-3.5" strokeWidth={1.6} aria-hidden="true" />
        Sign in
      </Link>
    )
  }

  const name = session.principal?.name || 'Signed-in'
  const detail = [
    session.principal?.tenant_id && `tenant ${session.principal.tenant_id}`,
    session.principal?.role,
    session.method === 'api_key' ? 'shared key' : 'session',
  ]
    .filter(Boolean)
    .join(' · ')

  return (
    <div className={cn('flex items-center gap-1', className)}>
      <span
        className="inline-flex min-w-0 items-center gap-1.5 rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--surface)] px-2 py-1"
        title={detail}
      >
        <UserRound
          className="size-3.5 shrink-0 text-[var(--muted-foreground)]"
          strokeWidth={1.6}
          aria-hidden="true"
        />
        {!compact && (
          <span className="max-w-[16ch] truncate text-[12px] text-[var(--foreground)]">{name}</span>
        )}
        <span className="sr-only">
          Signed in as {name}
          {detail ? ` (${detail})` : ''}
        </span>
      </span>
      {session.method === 'session' && (
        <button
          type="button"
          onClick={() => void signOut()}
          aria-label="Sign out"
          title="Sign out"
          className="grid size-8 place-items-center rounded-[var(--radius-md)] border border-[var(--border)] text-[var(--muted-foreground)] transition-colors hover:border-[var(--border-strong)] hover:text-[var(--foreground)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]"
        >
          <LogOut className="size-3.5" strokeWidth={1.6} aria-hidden="true" />
        </button>
      )}
    </div>
  )
}
