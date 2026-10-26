// frontend/src/components/ui/button.tsx
import { forwardRef, type ButtonHTMLAttributes, cloneElement, type ReactElement } from 'react'
import { cn } from '@/lib/utils'

export type ButtonVariant = 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger'
export type ButtonSize = 'sm' | 'md' | 'lg'

const VARIANT_CLASS: Record<ButtonVariant, string> = {
  primary: cn(
    'bg-[var(--primary)] text-[var(--primary-foreground)] border border-[var(--primary)]',
    'font-medium hover:bg-[color-mix(in_oklab,var(--primary)_86%,white)]',
    'active:bg-[color-mix(in_oklab,var(--primary)_80%,black)]',
  ),
  secondary: cn(
    'bg-[var(--surface-raised)] text-[var(--foreground)] border border-[var(--border)]',
    'hover:border-[var(--border-strong)] hover:bg-[var(--surface-subtle)]',
  ),
  outline: cn(
    'bg-transparent text-[var(--foreground)] border border-[var(--border-strong)]',
    'hover:border-[var(--primary)] hover:text-[var(--primary)]',
  ),
  ghost: cn(
    'bg-transparent text-[var(--muted-foreground)] border border-transparent',
    'hover:bg-[var(--surface-subtle)] hover:text-[var(--foreground)]',
  ),
  danger: cn(
    'bg-transparent text-[var(--danger)] border border-[color-mix(in_oklab,var(--danger)_45%,transparent)]',
    'hover:border-[var(--danger)] hover:bg-[var(--danger-subtle)]',
  ),
}

const SIZE_CLASS: Record<ButtonSize, string> = {
  sm: 'h-8 px-3 text-[13px] gap-1.5',
  md: 'h-10 px-4 text-[14px] gap-2',
  lg: 'h-11 px-5 text-[15px] gap-2',
}

const BASE_CLASS = cn(
  'inline-flex select-none items-center justify-center whitespace-nowrap rounded-[var(--radius-control)]',
  'font-medium transition-[background-color,border-color,color] duration-[var(--dp-motion-interaction)] ease-[var(--dp-motion-easing)]',
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]',
  'focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--background)]',
  'disabled:pointer-events-none disabled:opacity-45',
)

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  /** When true, the button renders its single child element as the button itself
   * (portal-like rendering). Useful for rendering an <a> or <Link> as the button. */
  asChild?: boolean
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'secondary', size = 'md', type = 'button', asChild = false, children, ...props }, ref) => {
    if (asChild && typeof children === 'object' && children !== null) {
      // Render the child element as the button root. Only the first child is
      // unwrapped; this is the same shape the classic console expects.
      const child = children as ReactElement<{
        href?: string
        to?: string
        className?: string
        'aria-label'?: string
        onClick?: React.MouseEventHandler<HTMLButtonElement>
       [key: string]: unknown
      }>
      return cloneElement(child, {
        className: cn(
          child.props.className as string,
          BASE_CLASS,
          VARIANT_CLASS[variant],
          SIZE_CLASS[size],
        ),
        ...props,
      })
    }
    return (
      <button
        ref={ref}
        type={type}
        className={cn(BASE_CLASS, VARIANT_CLASS[variant], SIZE_CLASS[size], className)}
        {...props}
      >
        {children}
      </button>
    )
  },
)
Button.displayName = 'Button'
