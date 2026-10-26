// frontend/src/components/ui/badge.tsx
import type { HTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

export type BadgeTone =
  | 'neutral'
  | 'info'
  | 'success'
  | 'warning'
  | 'danger'
  | 'primary'

const TONE_CLASS: Record<BadgeTone, string> = {
  neutral:
    'bg-transparent text-[var(--muted-foreground)] border-[var(--border)]',
  info: 'bg-transparent text-[var(--info)] border-[color-mix(in_oklab,var(--info)_40%,transparent)]',
  success:
    'bg-transparent text-[var(--success)] border-[color-mix(in_oklab,var(--success)_40%,transparent)]',
  warning:
    'bg-transparent text-[var(--warning)] border-[color-mix(in_oklab,var(--warning)_40%,transparent)]',
  danger:
    'bg-transparent text-[var(--danger)] border-[color-mix(in_oklab,var(--danger)_40%,transparent)]',
  primary:
    'bg-transparent text-[var(--primary)] border-[color-mix(in_oklab,var(--primary)_45%,transparent)]',
}

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone
}

/**
 * Status badge. Colour is never the only signal: callers always pass a text
 * label, and screen readers get the label (not a colour name).
 */
export function Badge({ className, tone = 'neutral', ...props }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-[var(--radius-sm)] border px-2 py-[4px]',
        'font-mono text-[11px] uppercase leading-none tracking-[0.08em] whitespace-nowrap',
        TONE_CLASS[tone],
        className,
      )}
      {...props}
    />
  )
}
