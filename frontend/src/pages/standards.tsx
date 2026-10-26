// frontend/src/pages/standards.tsx
//
// NIST PQC standards registry. The registry is mirrored from
// backend/standards.py via frontend/src/lib/standards.ts. The page renders the
// four canonical standards with their roles, lifecycles and detection caveats —
// and links back to the authoritative NIST CSRC pages.

import { ArrowUpRight } from 'lucide-react'
import { Panel } from '@/components/ui/panel'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { PageHeader } from '@/components/ui/page-header'
import { STANDARDS, STANDARDS_REVIEWED_ON, type StandardEntry } from '@/lib/standards'

function StandardCard({ standard }: { standard: StandardEntry }) {
  const lifecycleTone = standard.lifecycle === 'final' ? 'info' : 'neutral'

  return (
    <Panel className="h-full" interactive>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="eyebrow">{standard.id}</p>
          <h3 className="mt-1.5 text-[20px] font-medium leading-tight tracking-[-0.025em]">
            {standard.algorithm}
          </h3>
          <p className="mt-1 font-mono text-[11px] text-[var(--muted-foreground)]">
            {standard.former}
          </p>
        </div>
        <Badge tone={lifecycleTone}>{standard.lifecycleLabel}</Badge>
      </div>

      <Separator className="my-4" />

      <dl className="space-y-2.5 text-[12px]">
        <div className="flex justify-between gap-3">
          <dt className="text-[var(--muted-foreground)]">Role</dt>
          <dd className="max-w-[62%] text-right leading-snug text-[var(--foreground)]">
            {standard.role}
          </dd>
        </div>
        <div className="flex justify-between gap-3">
          <dt className="text-[var(--muted-foreground)]">Lifecycle</dt>
          <dd className="text-right font-mono text-[11px] text-[var(--muted-foreground)]">
            {standard.lifecycle === 'final' ? 'final' : 'in development'}
          </dd>
        </div>
      </dl>

      <Separator className="my-4" />

      <p className="text-[12px] leading-relaxed text-[var(--muted-foreground)]">
        {standard.caveat}
      </p>

      <div className="mt-4">
        <Button size="sm" variant="outline" asChild>
          <a
            href={standard.href}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5"
          >
            NIST reference
            <ArrowUpRight className="size-3.5" aria-hidden="true" />
          </a>
        </Button>
      </div>
    </Panel>
  )
}

export function StandardsPage() {
  return (
    <div className="rise-in mx-auto w-full max-w-[1100px] px-3 py-6 sm:px-6 lg:py-9">
      <PageHeader
        eyebrow="Standards"
        parent={{ to: '/', label: 'PiQuaChu' }}
        title="Four canonical standards"
        meta={`Registry reviewed ${STANDARDS_REVIEWED_ON}`}
        description="Detection of an algorithm is evidence of use, not of compliance. Lifecycle status here mirrors the backend registry."
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {STANDARDS.map((standard) => (
          <StandardCard key={standard.id} standard={standard} />
        ))}
      </div>

      <Separator className="my-7" />

      <Panel eyebrow="About" title="How this registry is used" highlighted>
        <div className="space-y-2.5 text-[12.5px] leading-relaxed">
          <p>
            Each scan maps detected cryptography against these four standards. The registry
            is the front-end source of truth for lifecycle status and detection caveats —
            the authoritative backend registry lives in{' '}
            <code className="rounded bg-[var(--surface-subtle)] px-1 py-0.5 font-mono text-[11px] text-[var(--foreground)]">
              backend/standards.py
            </code>
            .
          </p>
          <p className="text-[var(--muted-foreground)]">
            When that backend registry changes, update{' '}
            <code className="rounded bg-[var(--surface-subtle)] px-1 py-0.5 font-mono text-[11px] text-[var(--foreground)]">
              frontend/src/lib/standards.ts
            </code>{' '}
            in the same change and bump{' '}
            <code className="rounded bg-[var(--surface-subtle)] px-1 py-0.5 font-mono text-[11px] text-[var(--foreground)]">
              STANDARDS_REVIEWED_ON
            </code>
            .
          </p>
        </div>
      </Panel>
    </div>
  )
}

export default StandardsPage
