// frontend/src/components/ui/separator.tsx
import { cn } from '@/lib/utils'

export interface SeparatorProps {
  orientation?: 'horizontal' | 'vertical'
  className?: string
  /** Decorative rules are hidden from assistive tech (the default). */
  decorative?: boolean
}

export function Separator({
  orientation = 'horizontal',
  className,
  decorative = true,
}: SeparatorProps) {
  return (
    <div
      role={decorative ? 'presentation' : 'separator'}
      aria-orientation={decorative ? undefined : orientation}
      className={cn(
        'shrink-0 bg-[var(--border)]',
        orientation === 'horizontal' ? 'h-px w-full' : 'h-full w-px',
        className,
      )}
    />
  )
}
