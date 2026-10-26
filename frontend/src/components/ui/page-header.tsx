// frontend/src/components/ui/page-header.tsx
//
// One page header for the whole product. Every page previously re-implemented
// the eyebrow + title + breadcrumb block with raw <a href> links (full page
// reloads). This owns the hierarchy, the monospace metadata line and the
// breadcrumb, so a change to the rhythm lands everywhere at once.

import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { cn } from '@/lib/utils'

export interface PageHeaderProps {
  /** Monospace uppercase label above the title, e.g. "Scan results". */
  eyebrow: ReactNode
  title: ReactNode
  /** One or two sentences of context. Keep it short — it is read every visit. */
  description?: ReactNode
  /** Monospace facts under the title: scan id, task id, timestamps. */
  meta?: ReactNode
  /** Trailing actions (buttons, badges). Wraps under the title on small screens. */
  actions?: ReactNode
  /** Parent destination. The shell already owns the breadcrumb landmark, so this
   * renders a plain back link instead of a second one. */
  parent?: { to: string; label: string }
  className?: string
}

export function PageHeader({
  eyebrow,
  title,
  description,
  meta,
  actions,
  parent,
  className,
}: PageHeaderProps) {
  return (
    <header className={cn('mb-6 border-b border-[var(--border)] pb-5', className)}>
      <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
        <div className="min-w-0">
          {parent ? (
            <Link
              to={parent.to}
              className="mb-2 inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.14em] text-[var(--muted-foreground)] transition-colors hover:text-[var(--foreground)] focus-visible:text-[var(--primary)] focus-visible:outline-none"
            >
              <ArrowLeft className="size-3" strokeWidth={1.8} aria-hidden="true" />
              {parent.label}
            </Link>
          ) : (
            <p className="eyebrow mb-2">{eyebrow}</p>
          )}

          <h1 className="text-[clamp(1.6rem,2.8vw,2.25rem)] font-medium leading-[1.05] tracking-[-0.02em] text-[var(--foreground)]">
            {title}
          </h1>

          {meta && (
            <p className="mt-2 truncate font-mono text-[11px] tracking-[0.02em] text-[var(--muted-foreground)]">
              {meta}
            </p>
          )}
        </div>

        {actions && (
          <div className="flex flex-wrap items-center gap-2">{actions}</div>
        )}
      </div>

      {description && (
        <p className="mt-3 max-w-[68ch] text-[14px] leading-[var(--leading-reading)] text-[var(--muted-foreground)]">
          {description}
        </p>
      )}
    </header>
  )
}

export default PageHeader
