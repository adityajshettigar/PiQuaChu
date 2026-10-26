// frontend/src/components/ui/select.tsx
//
// Ground-truth combobox. Unlike a plain <select>, this exposes the real
// options, a searchable input, option count and selection state so the CBOM
// selector page can assert actual accessibility semantics instead of a native
// element it cannot inspect.
import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { ChevronDown, Check, Search } from 'lucide-react'
import { cn } from '@/lib/utils'

export interface SelectOption {
  value: string
  label: string
  description?: string
}

export interface SelectProps {
  options: SelectOption[]
  value?: string
  onChange: (value: string) => void
  placeholder?: string
  label?: string
  description?: string
  errorMessage?: string
  className?: string
  disabled?: boolean
  /** When true, the field shows its error state even when no option is selected. */
  invalid?: boolean
}

export function Select({
  options,
  value,
  onChange,
  placeholder = 'Select…',
  label,
  description,
  errorMessage,
  className,
  disabled = false,
  invalid = false,
}: SelectProps) {
  const id = useId()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)
  const containerRef = useRef<HTMLDivElement>(null)
  const optionRefs = useRef<Array<HTMLDivElement | null>>([])

  const selected = options.find((option) => option.value === value)

  const filtered = query
    ? options.filter((option) =>
        option.label.toLowerCase().includes(query.toLowerCase()) ||
        option.value.toLowerCase().includes(query.toLowerCase()) ||
        option.description?.toLowerCase().includes(query.toLowerCase()),
      )
    : options

  const scrollActiveIntoView = useCallback(() => {
    const el = optionRefs.current[activeIndex]
    if (!el) return
    el.scrollIntoView({ block: 'nearest' })
  }, [activeIndex])

  useEffect(() => {
    setActiveIndex(0)
  }, [filtered.length, query])

  useEffect(() => {
    scrollActiveIntoView()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeIndex])

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && open) {
        event.stopPropagation()
        setOpen(false)
        return
      }
      if (event.key === 'ArrowDown' && open) {
        event.preventDefault()
        setActiveIndex((index) => Math.min(index + 1, filtered.length - 1))
        return
      }
      if (event.key === 'ArrowUp' && open) {
        event.preventDefault()
        setActiveIndex((index) => Math.max(index - 1, 0))
        return
      }
      if (event.key === 'Enter' && open && filtered[activeIndex]) {
        event.preventDefault()
        onChange(filtered[activeIndex].value)
        setOpen(false)
        return
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [open, filtered, activeIndex, onChange])

  useEffect(() => {
    if (!open) return
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [open])

  const toggleOpen = useCallback(() => {
    if (disabled) return
    setOpen((next) => {
      if (next) setQuery('')
      return !next
    })
  }, [disabled])

  const selectOption = useCallback(
    (option: SelectOption) => {
      onChange(option.value)
      setOpen(false)
      setQuery('')
    },
    [onChange],
  )

  return (
    <div ref={containerRef} className={cn('relative', className)}>
      <div
        className={cn(
          'rounded-[var(--radius-md)] border text-left transition-colors duration-200',
          disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer hover:border-[var(--border-strong)]',
          invalid ? 'border-[var(--danger)]' : 'border-[var(--border)]',
          open ? 'border-[var(--primary)]' : undefined,
        )}
      >
        <button
          type="button"
          disabled={disabled}
          aria-haspopup="listbox"
          aria-expanded={open}
          aria-labelledby={label ? `${id}-label` : undefined}
          aria-describedby={description ? `${id}-desc` : undefined}
          aria-invalid={invalid || !!errorMessage}
          aria-errormessage={errorMessage ? `${id}-error` : undefined}
          onClick={toggleOpen}
          className={cn(
            'flex w-full items-center justify-between gap-2 rounded-[var(--radius-md)] p-2.5 text-sm',
            'bg-[var(--surface)] text-[var(--foreground)]',
          )}
        >
          <span className={cn('truncate', !selected && 'text-[var(--muted-foreground)]')}>
            {selected ? selected.label : placeholder}
          </span>
          <ChevronDown
            className={cn(
              'size-4 shrink-0 text-[var(--muted-foreground)] transition-transform',
              open && 'rotate-180',
            )}
            aria-hidden="true"
          />
        </button>
      </div>

      {label && (
        <label id={`${id}-label`} htmlFor={undefined} className="sr-only">
          {label}
        </label>
      )}
      {description && (
        <p id={`${id}-desc`} className="sr-only">
          {description}
        </p>
      )}
      {errorMessage && (
        <p id={`${id}-error`} className="sr-only" role="alert">
          {errorMessage}
        </p>
      )}

      {open && (
        <div
          role="listbox"
          aria-labelledby={label ? `${id}-label` : undefined}
          className={cn(
            'absolute z-50 mt-1 w-full overflow-auto rounded-[var(--radius-md)] border border-[var(--border-strong)] bg-[var(--surface-raised)] py-1 shadow-elev-xl',
            'max-h-60',
          )}
        >
          <div className="sticky top-0 z-10 flex items-center gap-2 border-b border-[var(--border)] px-2.5 py-2 bg-[var(--surface-subtle)]">
            <Search className="size-3.5 shrink-0 text-[var(--muted-foreground)]" aria-hidden="true" />
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Filter options…"
              className="flex-1 bg-transparent text-sm text-[var(--foreground)] placeholder:text-[var(--muted-foreground)] focus:outline-none"
              autoFocus
              onClick={(event) => event.stopPropagation()}
            />
            <span className="shrink-0 text-[10px] text-[var(--muted-foreground)]">
              {filtered.length} option{filtered.length === 1 ? '' : 's'}
            </span>
          </div>
          {filtered.length === 0 ? (
            <div className="px-2.5 py-3 text-sm text-[var(--muted-foreground)]">
              No options match your filter.
            </div>
          ) : (
            <div className="py-1">
              {filtered.map((option, index) => {
                const isActive = index === activeIndex
                const isSelected = option.value === value
                return (
                  <div
                    key={option.value}
                    ref={(element) => {
                      optionRefs.current[index] = element
                    }}
                    role="option"
                    aria-selected={isSelected}
                    aria-current={isActive ? 'true' : undefined}
                    onClick={() => selectOption(option)}
                    className={cn(
                      'flex w-full items-center justify-between gap-2 rounded-[var(--radius-sm)] px-2.5 py-2 text-sm cursor-pointer transition-colors',
                      isActive
                        ? 'bg-[var(--primary-subtle)] text-[var(--foreground)]'
                        : 'text-[var(--foreground)] hover:bg-[var(--surface-subtle)]',
                      isSelected && !isActive && 'text-[var(--primary)]',
                    )}
                  >
                    <span className="flex flex-col">
                      <span className="font-medium">{option.label}</span>
                      {option.description && (
                        <span className="text-[11px] text-[var(--muted-foreground)]">
                          {option.description}
                        </span>
                      )}
                    </span>
                    {isSelected && <Check className="size-4 shrink-0 text-[var(--primary)]" aria-hidden="true" />}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default Select
