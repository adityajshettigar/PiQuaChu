// frontend/src/components/app-shell/route-error-boundary.tsx
//
// Last-resort recovery surface. A render exception in one page must not blank
// the whole console: the shell, the navigation and the connection status stay
// usable, and the error is reported without any scanned source or credentials.

import { Component, type ErrorInfo, type ReactNode } from 'react'
import { Panel } from '@/components/ui/panel'
import { Button } from '@/components/ui/button'

interface Props {
  children: ReactNode
}

interface State {
  error: Error | null
}

export class RouteErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Development-only diagnostics. No source contents, paths or keys are logged.
    if (import.meta.env.DEV) {
      console.error('[PiQuaChu] render error:', error.message, info.componentStack)
    }
  }

  private reset = (): void => {
    this.setState({ error: null })
  }

  render(): ReactNode {
    const { error } = this.state
    if (!error) return this.props.children

    return (
      <Panel className="mx-auto w-full max-w-[720px] px-3 py-5 sm:px-5 lg:py-7">
        <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-[var(--muted-foreground)]">
          Recoverable error
        </p>
        <h1 className="mt-1 font-display text-[clamp(1.35rem,2.4vw,1.8rem)] leading-tight">
          This view could not be rendered
        </h1>
        <p className="mt-3 text-[13px] leading-relaxed text-[var(--muted-foreground)]">
          The rest of the console is still usable. No scan data was discarded by this
          failure, and nothing was sent anywhere.
        </p>
        <p className="mt-3 font-mono text-[11px] text-[var(--danger)]">{error.message}</p>
        <div className="mt-4 flex flex-wrap gap-2">
          <Button size="sm" onClick={this.reset}>
            Try again
          </Button>
          <Button size="sm" variant="ghost" onClick={() => window.location.assign('/')}>
            Back to overview
          </Button>
        </div>
      </Panel>
    )
  }
}

export default RouteErrorBoundary
