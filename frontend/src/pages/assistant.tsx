// frontend/src/pages/assistant.tsx
//
// Assistant over one stored scan. Questions go to the API's assistant endpoint
// with an explicit scan id; the page shows which scan is in context, why the
// answer exists (local rule engine or an optional remote provider), and the
// privacy note the backend returned. Nothing is invented client-side.
import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowUp, FileSearch, Sparkles } from 'lucide-react'
import { Panel } from '@/components/ui/panel'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { PageHeader } from '@/components/ui/page-header'
import { EmptyState } from '@/components/ui/empty-state'
import { api, ApiError, type AssistantAnswer, type ScanDetail } from '@/lib/api'
import { formatTimestamp } from '@/lib/utils'

type Message =
  | { id: string; role: 'question'; text: string }
  | { id: string; role: 'answer'; answer: AssistantAnswer }
  | { id: string; role: 'error'; text: string }

const SUGGESTIONS = [
  'What are the most critical findings?',
  'What should I remediate first?',
  'Which standard has the weakest evidence?',
] as const

const REQUEST_TIMEOUT_MS = 30_000

export function AssistantPage({ scanId }: { scanId?: number }) {
  const params = useParams<{ scanId: string }>()
  const id =
    scanId ?? (params.scanId && /^\d+$/.test(params.scanId) ? Number(params.scanId) : undefined)

  const [detail, setDetail] = useState<ScanDetail | null>(null)
  const [state, setState] = useState<'loading' | 'ready' | 'notfound' | 'error'>(
    id ? 'loading' : 'notfound',
  )
  const [loadError, setLoadError] = useState<string | null>(null)
  const [messages, setMessages] = useState<Message[]>([])
  const [draft, setDraft] = useState('')
  const [thinking, setThinking] = useState(false)
  const listRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!id) return
    let cancelled = false
    const controller = new AbortController()
    api.scan(id, controller.signal).then(
      (result) => {
        if (cancelled) return
        setDetail(result)
        setState('ready')
      },
      (err: unknown) => {
        if (cancelled) return
        if (err instanceof ApiError && err.kind === 'aborted') return
        if (err instanceof ApiError && err.kind === 'not_found') {
          setState('notfound')
          return
        }
        setLoadError(err instanceof ApiError ? err.message : 'The scan could not be read.')
        setState('error')
      },
    )
    return () => {
      cancelled = true
      controller.abort()
    }
  }, [id])

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' })
  }, [messages, thinking])

  const ask = useCallback(
    async (question: string) => {
      const trimmed = question.trim()
      if (!trimmed || !id || thinking) return

      const questionId = `q-${Date.now()}`
      setMessages((previous) => [...previous, { id: questionId, role: 'question', text: trimmed }])
      setDraft('')
      setThinking(true)

      const controller = new AbortController()
      const timer = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
      try {
        const answer = await api.assistant(trimmed, id, controller.signal)
        setMessages((previous) => [
          ...previous,
          { id: `a-${Date.now()}`, role: 'answer', answer },
        ])
      } catch (err) {
        const text =
          err instanceof ApiError
            ? err.kind === 'aborted'
              ? 'The request timed out after 30 seconds. Try a shorter question.'
              : err.message
            : 'The assistant request failed.'
        setMessages((previous) => [...previous, { id: `e-${Date.now()}`, role: 'error', text }])
      } finally {
        window.clearTimeout(timer)
        setThinking(false)
      }
    },
    [id, thinking],
  )

  const lastAnswer = [...messages].reverse().find((message) => message.role === 'answer')

  if (!id) {
    return (
      <div className="mx-auto w-full max-w-[900px] px-4 py-8 sm:px-6">
        <Panel>
          <EmptyState
            tone="error"
            title="No scan selected"
            description="The assistant explains the evidence of one specific scan."
            action={
              <Button size="sm" variant="primary" asChild>
                <Link to="/history">Open scan history</Link>
              </Button>
            }
          />
        </Panel>
      </div>
    )
  }

  if (state === 'notfound' || state === 'error') {
    return (
      <div className="mx-auto w-full max-w-[900px] px-4 py-8 sm:px-6">
        <PageHeader eyebrow="Assistant" title="Scan unavailable" meta={`scan #${id}`} />
        <Panel>
          <EmptyState
            tone="error"
            icon={<FileSearch className="size-4" aria-hidden="true" />}
            title={state === 'notfound' ? 'No stored scan with this id' : 'The scan could not be read'}
            description={state === 'notfound' ? 'It may belong to another tenant or may not exist.' : (loadError ?? 'The API returned an error.')}
            action={
              <Button size="sm" variant="primary" asChild>
                <Link to="/history">Scan history</Link>
              </Button>
            }
          />
        </Panel>
      </div>
    )
  }

  return (
    <div className="rise-in mx-auto flex w-full max-w-[900px] flex-col px-4 py-8 sm:px-6 md:py-10">
      <PageHeader
        eyebrow="Assistant"
        parent={{ to: `/results/${id}`, label: 'Results' }}
        title="Ask about this scan"
        meta={`scan #${id}${detail?.filename ? ` · ${detail.filename}` : ''}${detail?.timestamp ? ` · ${formatTimestamp(detail.timestamp)}` : ''}`}
        actions={
          <Badge tone={lastAnswer?.answer.remote_ai ? 'warning' : 'neutral'}>
            {lastAnswer?.answer.remote_ai ? 'remote provider enabled' : 'local answers'}
          </Badge>
        }
        description="Answers are generated by the API from this scan's stored findings. The question is sent to your PiQuaChu backend; whether an optional external provider also receives it is reported with every answer."
      />

      {state === 'loading' ? (
        <Panel>
          <p className="text-[13px] text-[var(--muted-foreground)]">Loading the scan context…</p>
        </Panel>
      ) : (
        <div className="flex flex-1 flex-col gap-4">
          <Panel className="flex min-h-[380px] flex-col" flush highlighted>
            <div
              ref={listRef}
              className="flex-1 space-y-4 overflow-y-auto px-4 py-5 sm:px-5"
              aria-live="polite"
            >
              {messages.length === 0 && (
                <div className="flex flex-col items-start gap-3 py-10 sm:items-center sm:py-14 sm:text-center">
                  <span
                    aria-hidden="true"
                    className="grid size-10 place-items-center rounded-full border border-[color-mix(in_oklch,var(--primary)_30%,transparent)] bg-[var(--primary-subtle)] text-[var(--primary)]"
                  >
                    <Sparkles className="size-4" strokeWidth={1.6} />
                  </span>
                  <p className="text-[15px] font-medium tracking-[-0.01em]">
                    Ask about the evidence in scan #{id}
                  </p>
                  <p className="max-w-[48ch] text-[12.5px] leading-relaxed text-[var(--muted-foreground)]">
                    {detail
                      ? `${detail.findings.length} finding(s) are in context. Ask about severities, standards, or what to fix first.`
                      : 'Try one of the prompts below.'}
                  </p>
                </div>
              )}

              {messages.map((message) => {
                if (message.role === 'question') {
                  return (
                    <div key={message.id} className="flex justify-end">
                      <p className="max-w-[80%] rounded-[var(--radius-md)] rounded-br-sm bg-[var(--primary-subtle)] px-3 py-2 text-[13px] leading-relaxed text-[var(--foreground)]">
                        {message.text}
                      </p>
                    </div>
                  )
                }
                if (message.role === 'error') {
                  return (
                    <div key={message.id} className="flex justify-start">
                      <p role="alert" className="max-w-[85%] rounded-[var(--radius-md)] border border-[color-mix(in_oklch,var(--danger)_35%,transparent)] bg-[var(--danger-subtle)] px-3 py-2 text-[12.5px] leading-relaxed text-[var(--danger)]">
                        {message.text}
                      </p>
                    </div>
                  )
                }
                return (
                  <div key={message.id} className="flex flex-col items-start gap-1.5">
                    <div className="max-w-[88%] rounded-[var(--radius-md)] rounded-bl-sm border border-[var(--border)] bg-[var(--surface-raised)] px-3 py-2">
                      <p className="whitespace-pre-line text-[13px] leading-relaxed text-[var(--foreground)]">
                        {message.answer.answer}
                      </p>
                      {message.answer.code && (
                        <pre className="mt-2 max-h-64 overflow-auto rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--background)] p-3 font-mono text-[11px] leading-relaxed">
                          {message.answer.code}
                        </pre>
                      )}
                    </div>
                    <p className="max-w-[88%] font-mono text-[10px] uppercase tracking-[0.08em] text-[var(--muted-foreground)]">
                      {message.answer.remote_ai ? 'assistant · remote provider' : 'assistant · local rule engine'}
                      {message.answer.has_context ? ' · scan context attached' : ' · no scan context'}
                    </p>
                  </div>
                )
              })}

              {thinking && (
                <div className="flex justify-start">
                  <p className="rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--surface-raised)] px-3 py-2 text-[12px] text-[var(--muted-foreground)]">
                    Reading the findings…
                  </p>
                </div>
              )}
            </div>

            <form
              onSubmit={(event) => {
                event.preventDefault()
                void ask(draft)
              }}
              className="border-t border-[var(--border)] px-4 py-3 sm:px-5"
            >
              <div className="flex items-end gap-2">
                <label htmlFor="assistant-input" className="sr-only">
                  Ask a question about this scan
                </label>
                <input
                  id="assistant-input"
                  type="text"
                  value={draft}
                  onChange={(event) => setDraft(event.target.value)}
                  maxLength={2000}
                  placeholder="Ask about severity, standards or remediation…"
                  className="h-10 min-w-0 flex-1 rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--surface-raised)] px-3 text-[13px] text-[var(--foreground)] placeholder:text-[var(--muted-foreground)] transition-colors focus:border-[color-mix(in_oklch,var(--primary)_50%,transparent)] focus:outline-none focus:ring-2 focus:ring-[color-mix(in_oklch,var(--primary)_22%,transparent)]"
                />
                <Button
                  type="submit"
                  variant="primary"
                  size="md"
                  disabled={!draft.trim() || thinking}
                  aria-label="Send question"
                >
                  <ArrowUp className="size-4" aria-hidden="true" />
                </Button>
              </div>
            </form>
          </Panel>

          <div className="flex flex-wrap gap-2">
            {SUGGESTIONS.map((suggestion) => (
              <Button
                key={suggestion}
                size="sm"
                variant="outline"
                disabled={thinking}
                onClick={() => void ask(suggestion)}
              >
                {suggestion}
              </Button>
            ))}
          </div>

          <p className="text-[11px] leading-relaxed text-[var(--muted-foreground)]">
            Answers are suggestions derived from the stored findings, not independent analysis.
            Check them against the findings workbench. Exporting a scan never sends source to the
            assistant. Conversation history lives only in this tab and is lost on reload.
          </p>
        </div>
      )}
    </div>
  )
}

export default AssistantPage
