// frontend/src/components/results/insight.tsx
//
// The result bento primitives: a card that is genuinely interactive, and the
// side panel that explains what a number means. A card that says "click for
// methodology" is a <button>; a card that navigates is a link. Nothing here
// looks clickable without being operable from the keyboard.
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ArrowUpRight, Info } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Sheet } from '@/components/ui/sheet'

export interface InsightCardProps {
  eyebrow: ReactNode
  title: ReactNode
  /** One-line summary under the title. */
  summary?: ReactNode
  children: ReactNode
  /** Accessible name of the action that opens the explanation. */
  actionLabel: string
  onOpen: () => void
  className?: string
  /** Slightly stronger edge for the focal card of the grid. */
  highlighted?: boolean
}

export function InsightCard({
  eyebrow,
  title,
  summary,
  children,
  actionLabel,
  onOpen,
  className,
  highlighted = false,
}: InsightCardProps) {
  return (
    <section
      className={cn(
        'surface-glass group relative flex h-full flex-col rounded-[var(--radius-lg)] border',
        highlighted
          ? 'border-[color-mix(in_oklch,var(--primary)_26%,transparent)]'
          : 'border-[var(--border)]',
        'transition-colors duration-300 ease-out hover:border-[var(--border-strong)]',
        className,
      )}
    >
      <header className="border-b border-[var(--border)] px-4 py-3">
        <p className="eyebrow">{eyebrow}</p>
        <h2 className="mt-1.5 text-[15px] font-medium leading-tight tracking-[-0.012em]">
          {title}
        </h2>
        {summary && (
          <p className="mt-1 text-[11px] leading-snug text-[var(--muted-foreground)]">{summary}</p>
        )}
      </header>

      <div className="min-w-0 flex-1 px-4 py-4">{children}</div>

      <footer className="border-t border-[var(--border)] px-4 py-2">
        <button
          type="button"
          onClick={onOpen}
          className="inline-flex items-center gap-1.5 rounded-[var(--radius-sm)] py-1 text-[11px] text-[var(--muted-foreground)] transition-colors hover:text-[var(--foreground)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]"
        >
          <Info className="size-3.5" strokeWidth={1.6} aria-hidden="true" />
          {actionLabel}
          <span className="sr-only"> — opens an explanation panel</span>
        </button>
      </footer>
    </section>
  )
}

export interface InsightSheetProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  eyebrow: string
  title: string
  children: ReactNode
}

export function InsightSheet({ open, onOpenChange, eyebrow, title, children }: InsightSheetProps) {
  return (
    <Sheet
      open={open}
      onOpenChange={onOpenChange}
      title={title}
      description={eyebrow}
      side="right"
      widthClassName="w-[min(34rem,94vw)]"
    >
      <div className="space-y-4 px-1 pb-6 text-[13px] leading-relaxed text-[var(--muted-foreground)]">
        {children}
      </div>
    </Sheet>
  )
}

export interface ExplanationSectionProps {
  title: string
  children: ReactNode
}

export function ExplanationSection({ title, children }: ExplanationSectionProps) {
  return (
    <section>
      <h3 className="font-mono text-[10px] uppercase tracking-[0.14em] text-[var(--muted-foreground)]">
        {title}
      </h3>
      <div className="mt-1.5 space-y-2 text-[13px] leading-relaxed text-[var(--foreground)]">
        {children}
      </div>
    </section>
  )
}

/** A quiet link used inside insight cards. */
export function CardLink({
  to,
  children,
  className,
}: {
  to: string
  children: ReactNode
  className?: string
}) {
  return (
    <Link
      to={to}
      className={cn(
        'inline-flex items-center gap-1 text-[11.5px] text-[var(--primary)] transition-colors hover:text-[var(--foreground)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]',
        className,
      )}
    >
      {children}
      <ArrowUpRight className="size-3" aria-hidden="true" />
    </Link>
  )
}
