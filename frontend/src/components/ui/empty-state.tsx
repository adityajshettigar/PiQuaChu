// frontend/src/components/ui/empty-state.tsx
//
// Honest empty states. No placeholder metrics, no fake rows: the copy explains
// what the screen will show once there is real data, and offers the next step.

import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

export interface EmptyStateProps {
  icon?: ReactNode
  title: ReactNode
  description?: ReactNode
  action?: ReactNode
  /** `error` renders the copy in the danger tone; no other visual change. */
  tone?: 'neutral' | 'error'
  className?: string
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  tone = 'neutral',
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-start gap-3 rounded-[var(--radius-lg)] px-1 py-8 sm:items-center sm:py-12 sm:text-center',
        className,
      )}
    >
      {icon && (
        <span
          aria-hidden="true"
          className={cn(
            'grid size-10 place-items-center rounded-full border',
            tone === 'error'
              ? 'border-[color-mix(in_oklch,var(--danger)_35%,transparent)] bg-[var(--danger-subtle)] text-[var(--danger)]'
              : 'border-[var(--border)] bg-[var(--surface-raised)] text-[var(--muted-foreground)]',
          )}
        >
          {icon}
        </span>
      )}

      <h2
        className={cn(
          'text-[17px] font-medium tracking-[-0.015em]',
          tone === 'error' ? 'text-[var(--danger)]' : 'text-[var(--foreground)]',
        )}
      >
        {title}
      </h2>

      {description && (
        <p className="max-w-[52ch] text-[13px] leading-relaxed text-[var(--muted-foreground)]">
          {description}
        </p>
      )}

      {action && <div className="mt-1 flex flex-wrap gap-2">{action}</div>}
    </div>
  )
}

export default EmptyState
