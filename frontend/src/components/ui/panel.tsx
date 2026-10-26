// frontend/src/components/ui/panel.tsx
import type { HTMLAttributes, ReactNode } from 'react'
import { cn } from '@/lib/utils'

// `title` is a ReactNode heading here, not the native tooltip attribute.
export interface PanelProps extends Omit<HTMLAttributes<HTMLDivElement>, 'title'> {
  /** Small uppercase label rendered above the title, inside the header rule. */
  eyebrow?: ReactNode
  title?: ReactNode
  /** Right-aligned header content (badges, actions). */
  aside?: ReactNode
  /** Remove body padding when the children manage their own layout. */
  flush?: boolean
  /** Orange hairline edge. Use for one focal surface per view. */
  highlighted?: boolean
  /** Adds hover affordance. Only for surfaces that actually do something. */
  interactive?: boolean
}

/**
 * A single opaque panel on the dark ground. Panels are not nested inside
 * panels: sections inside a panel use hairlines and spacing instead.
 */
export function Panel({
  className,
  eyebrow,
  title,
  aside,
  flush = false,
  highlighted = false,
  interactive = false,
  children,
  ...props
}: PanelProps) {
  const hasHeader = Boolean(eyebrow || title || aside)
  return (
    <section
      className={cn(
        'surface-glass relative isolate rounded-[var(--radius-lg)] border',
        'transition-[border-color,background-color] duration-[var(--dp-motion-interaction)] ease-[var(--dp-motion-easing)]',
        highlighted ? 'border-[var(--primary)]' : 'border-[var(--border)]',
        interactive &&
          'hover:border-[var(--border-strong)] hover:bg-[var(--surface-raised)]',
        className,
      )}
      {...props}
    >
      {hasHeader && (
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-[var(--border)] px-4 py-3 sm:px-5">
          <div className="min-w-0">
            {eyebrow && <p className="eyebrow mb-1.5">{eyebrow}</p>}
            {title && (
              <h2 className="text-[15px] font-medium leading-tight text-[var(--foreground)]">
                {title}
              </h2>
            )}
          </div>
          {aside && <div className="flex shrink-0 items-center gap-2">{aside}</div>}
        </header>
      )}
      <div className={flush ? '' : 'px-4 py-4 sm:px-5 sm:py-5'}>{children}</div>
    </section>
  )
}
