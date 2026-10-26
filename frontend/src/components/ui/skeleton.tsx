// frontend/src/components/ui/skeleton.tsx
import { cn } from '@/lib/utils'

export interface SkeletonProps {
  className?: string
  /** Announced once for the whole loading region, not per block. */
  label?: string
}

export function Skeleton({ className, label }: SkeletonProps) {
  return (
    <div
      aria-hidden={label ? undefined : true}
      aria-label={label}
      aria-busy={label ? true : undefined}
      role={label ? 'status' : undefined}
      className={cn(
        'animate-pulse rounded-[var(--radius-sm)] bg-[var(--surface-subtle)]',
        className,
      )}
    />
  )
}
