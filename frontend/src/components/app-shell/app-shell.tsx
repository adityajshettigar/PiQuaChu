// frontend/src/components/app-shell/app-shell.tsx
// Financial: one compact sticky top bar (wordmark, primary sections, connection
// state, account, settings) and the routed page. Dark navy ground, hairline
// rules, orange selection and pill controls. No page-wide warm light.

import { useState, type ReactNode } from 'react'
import { Link, NavLink, Outlet } from 'react-router-dom'
import { Menu, Moon, Sun } from 'lucide-react'
import { cn } from '@/lib/utils'
import { NAV_ITEMS } from './nav'
import { ConnectionStatus } from './connection-status'
import { SessionStatus } from './session-status'
import { useTheme } from './theme-context'
import { Sheet } from '@/components/ui/sheet'

function NavList({
  onNavigate,
  vertical = false,
}: {
  onNavigate?: () => void
  vertical?: boolean
}) {
  return (
    <nav
      aria-label="Primary"
      className={cn(vertical ? 'flex flex-col' : 'flex items-center gap-1')}
    >
      {NAV_ITEMS.map((item) => {
        const Icon = item.icon
        return (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            onClick={onNavigate}
            className={({ isActive }) =>
              cn(
                'group relative inline-flex items-center gap-2 rounded-[var(--radius-sm)] px-2.5 py-1.5',
                'text-[14px] transition-colors duration-[var(--dp-motion-interaction)] ease-[var(--dp-motion-easing)]',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]',
                vertical && 'w-full items-start rounded-none px-0 py-2.5',
                isActive
                  ? 'text-[var(--primary)]'
                  : 'text-[var(--muted-foreground)] hover:text-[var(--foreground)]',
              )
            }
          >
            {({ isActive }) => (
              <>
                <Icon
                  className={cn(
                    'size-[15px] shrink-0',
                    isActive ? 'text-[var(--primary)]' : 'text-[var(--muted-foreground)]',
                  )}
                  strokeWidth={1.6}
                  aria-hidden="true"
                />
                <span className="font-medium">{item.label}</span>
                {vertical && (
                  <span className="mt-1 block text-[13px] leading-snug text-[var(--muted-foreground)]">
                    {item.description}
                  </span>
                )}
                {isActive && !vertical && (
                  <span
                    aria-hidden="true"
                    className="absolute inset-x-2.5 bottom-0 h-px bg-[var(--primary)]"
                  />
                )}
              </>
            )}
          </NavLink>
        )
      })}
    </nav>
  )
}

function Wordmark() {
  return (
    <Link
      to="/"
      className="flex items-center gap-2.5 rounded-[var(--radius-sm)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]"
      aria-label="PiQuaChu — home"
    >
      <span
        aria-hidden="true"
        className="grid size-7 place-items-center rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--surface)]"
      >
        <svg viewBox="0 0 20 20" className="size-[15px]" fill="none" strokeWidth="1.1">
          <path d="M10 2.5 16 6v8l-6 3.5L4 14V6z" className="stroke-[var(--primary)]" />
          <path d="M10 2.5V10m0 0 6-4m-6 4-6-4m6 4v7.5" className="stroke-[var(--value)]" />
        </svg>
      </span>
      <span className="text-[15px] font-semibold tracking-[-0.015em] text-[var(--foreground)]">
        PiQuaChu
      </span>
    </Link>
  )
}

function IconControl({
  to,
  label,
  children,
}: {
  to: string
  label: string
  children: ReactNode
}) {
  return (
    <Link
      to={to}
      aria-label={label}
      title={label}
      className={cn(
        'grid size-9 place-items-center rounded-[var(--radius-control)] border border-[var(--border)]',
        'bg-transparent text-[var(--muted-foreground)]',
        'transition-[color,border-color] duration-[var(--dp-motion-interaction)] ease-[var(--dp-motion-easing)]',
        'hover:border-[var(--primary)] hover:text-[var(--primary)]',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]',
      )}
    >
      {children}
    </Link>
  )
}

function ThemeToggle() {
  const { mode, toggle } = useTheme()
  const next = mode === 'dark' ? 'light' : 'dark'
  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={`Switch to ${next} theme`}
      title={`Switch to ${next} theme`}
      className={cn(
        'grid size-9 place-items-center rounded-[var(--radius-control)] border border-[var(--border)]',
        'bg-transparent text-[var(--muted-foreground)]',
        'transition-[color,border-color] duration-[var(--dp-motion-interaction)] ease-[var(--dp-motion-easing)]',
        'hover:border-[var(--primary)] hover:text-[var(--primary)]',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]',
      )}
    >
      {mode === 'dark' ? (
        <Sun className="size-[15px]" strokeWidth={1.6} aria-hidden="true" />
      ) : (
        <Moon className="size-[15px]" strokeWidth={1.6} aria-hidden="true" />
      )}
    </button>
  )
}

export function AppShell() {
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <div className="relative flex min-h-dvh flex-col bg-[var(--background)] text-[var(--foreground)]">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded-[var(--radius-control)] focus:border focus:border-[var(--primary)] focus:bg-[var(--surface-raised)] focus:px-4 focus:py-2 focus:text-sm"
      >
        Skip to content
      </a>

      <header className="sticky top-0 z-30 border-b border-[var(--border)] bg-[var(--background)]">
        <div className="mx-auto flex h-14 w-full max-w-[1440px] items-center gap-3 px-4 sm:px-6">
          <Wordmark />

          <div className="ml-4 hidden md:block">
            <NavList />
          </div>

          <div className="ml-auto flex items-center gap-1.5">
            <ConnectionStatus compact className="hidden lg:inline-flex" />
            <SessionStatus compact className="hidden sm:block" />
            <ThemeToggle />
            <IconControl to="/settings" label="Settings and connection">
              <svg
                viewBox="0 0 24 24"
                className="size-[15px]"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.6"
                aria-hidden="true"
              >
                <circle cx="12" cy="12" r="3" />
                <path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06A1.7 1.7 0 0 0 15 19.4a1.7 1.7 0 0 0-1 1.55V21a2 2 0 1 1-4 0v-.05A1.7 1.7 0 0 0 9 19.4a1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-1.55-1H3a2 2 0 1 1 0-4h.05A1.7 1.7 0 0 0 4.6 9a1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.7 1.7 0 0 0 9 4.6h.05a1.7 1.7 0 0 0 1-1.55V3a2 2 0 1 1 4 0v.05a1.7 1.7 0 0 0 1 1.55 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.7 1.7 0 0 0 19.4 9v.05a1.7 1.7 0 0 0 1.55 1H21a2 2 0 1 1 0 4h-.05a1.7 1.7 0 0 0-1.55 1z" />
              </svg>
            </IconControl>
            <button
              type="button"
              onClick={() => setMobileOpen(true)}
              aria-label="Open navigation"
              aria-expanded={mobileOpen}
              className={cn(
                'grid size-9 place-items-center rounded-[var(--radius-control)] border border-[var(--border)]',
                'text-[var(--muted-foreground)] hover:border-[var(--primary)] hover:text-[var(--primary)]',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] md:hidden',
              )}
            >
              <Menu className="size-4" strokeWidth={1.6} aria-hidden="true" />
            </button>
          </div>
        </div>
      </header>

      <main id="main" className="relative z-10 min-w-0 flex-1">
        <Outlet />
      </main>

      <footer className="relative z-10 border-t border-[var(--border)] bg-[var(--dp-color-ground-tint)]">
        <div className="mx-auto grid w-full max-w-[1440px] gap-6 px-4 py-8 sm:grid-cols-2 sm:px-6 md:grid-cols-[minmax(0,1.4fr)_repeat(2,minmax(0,1fr))]">
          <div>
            <Wordmark />
            <p className="mt-3 max-w-[42ch] text-[13px] leading-[var(--leading-reading)] text-[var(--muted-foreground)]">
              Static discovery evidence — not a compliance certificate.
            </p>
          </div>
          <div>
            <p className="eyebrow">Product</p>
            <ul className="mt-2.5 space-y-1.5 text-[13px] text-[var(--muted-foreground)]">
              <li>
                <Link to="/scan" className="hover:text-[var(--foreground)]">
                  Scan an archive
                </Link>
              </li>
              <li>
                <Link to="/history" className="hover:text-[var(--foreground)]">
                  Scan history
                </Link>
              </li>
              <li>
                <Link to="/settings" className="hover:text-[var(--foreground)]">
                  Connection
                </Link>
              </li>
            </ul>
          </div>
          <div>
            <p className="eyebrow">Evidence</p>
            <ul className="mt-2.5 space-y-1.5 text-[13px] text-[var(--muted-foreground)]">
              <li>
                <Link to="/standards" className="hover:text-[var(--foreground)]">
                  Standards
                </Link>
              </li>
              <li>
                <Link to="/reliability" className="hover:text-[var(--foreground)]">
                  Detection reliability
                </Link>
              </li>
            </ul>
          </div>
        </div>
        <div className="mx-auto w-full max-w-[1440px] border-t border-[var(--border)] px-4 py-3 sm:px-6">
          <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
            PiQuaChu · post-quantum cryptography discovery
          </p>
        </div>
      </footer>

      <Sheet
        open={mobileOpen}
        onOpenChange={setMobileOpen}
        title="Navigation"
        description="PiQuaChu sections"
      >
        <NavList vertical onNavigate={() => setMobileOpen(false)} />
        <div className="mt-4 flex flex-col gap-3 border-t border-[var(--border)] pt-3">
          <ConnectionStatus />
          <SessionStatus />
          <Link
            to="/settings"
            onClick={() => setMobileOpen(false)}
            className="text-[13px] text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
          >
            Settings and connection
          </Link>
        </div>
      </Sheet>
    </div>
  )
}
