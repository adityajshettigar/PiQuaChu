// frontend/src/App.test.tsx
//
// Route-tree regressions: the root renders the product home, an unknown address
// stays usable inside the shell, a non-numeric scan id is rejected without a
// bogus request, and the login route renders even with no provider configured.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import App from './App'
import { ThemeProvider } from '@/components/app-shell/theme-provider'

const HEALTH = {
  status: 'ok',
  service: 'PiQuaChu API',
  version: '2.4.0',
  checks: {
    database: { status: 'ok' },
    rate_limiter: { backend: 'in-memory', failure_mode: 'closed' },
    job_backend: 'threads',
  },
  configuration: { environment: 'development', tenancy_mode: 'local', warnings: [] },
}

const SESSION = {
  authenticated: false,
  method: null,
  principal: null,
  permissions: [],
  providers: [],
  configured: false,
  problems: ['PIQUACHU_OIDC_ISSUER is not set.'],
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderAt(path: string) {
  return render(
    <ThemeProvider>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </ThemeProvider>,
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

function stubApi() {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/auth/session')) return jsonResponse(SESSION)
      if (url.includes('/api/v1/scans')) return jsonResponse({ scans: [] })
      return jsonResponse(HEALTH)
    }),
  )
}

describe('App route tree', () => {
  it('renders the home page — not the legacy upload dashboard — at the root route', async () => {
    stubApi()
    renderAt('/')

    expect(await screen.findByText(/no scans recorded yet/i)).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: /understand your cryptographic exposure/i }),
    ).toBeInTheDocument()
    expect(screen.queryByText(/deploy target archive/i)).not.toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: /primary/i })).toBeInTheDocument()
  })

  it('keeps the shell usable on an unknown address', async () => {
    stubApi()
    renderAt('/does-not-exist')

    expect(await screen.findByText(/no page at this address/i)).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: /primary/i })).toBeInTheDocument()
  })

  it('rejects a non-numeric scan id instead of fetching a bogus result', async () => {
    stubApi()
    renderAt('/results/not-a-number')

    expect(await screen.findByText(/no page at this address/i)).toBeInTheDocument()
  })

  it('redirects the legacy intake path to the scan page', async () => {
    stubApi()
    renderAt('/intake')

    expect(await screen.findByText(/scan a codebase/i)).toBeInTheDocument()
  })

  it('renders an honest not-configured login state', async () => {
    stubApi()
    renderAt('/login')

    expect(
      await screen.findByText(/single sign-on is not available on this server/i),
    ).toBeInTheDocument()
    expect(screen.getByText(/PIQUACHU_OIDC_ISSUER is not set/i)).toBeInTheDocument()
  })
})
