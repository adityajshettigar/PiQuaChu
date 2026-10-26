// frontend/src/pages/pages.test.tsx
import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { OverviewPage } from './overview'
import { SettingsPage } from './connection'
import { ThemeProvider } from '@/components/app-shell/theme-provider'

const HISTORY = {
  scans: [
    {
      id: 7,
      timestamp: '2026-10-20T10:00:00Z',
      filename: 'checkout-service.zip',
      pqc_score: 62,
      verdict: 'at_risk',
    },
    {
      id: 6,
      timestamp: '2026-10-19T09:00:00Z',
      filename: 'ledger.zip',
      pqc_score: 88,
      verdict: 'partial',
    },
  ],
}

const HEALTH = {
  status: 'ok',
  service: 'PiQuaChu API',
  version: '2.4.0',
  checks: {
    database: { status: 'ok' },
    rate_limiter: { backend: 'redis', failure_mode: 'closed' },
    job_backend: 'celery',
  },
  configuration: {
    environment: 'development',
    tenancy_mode: 'local',
    warnings: [],
  },
}

const READY = {
  status: 'ready',
  version: '2.4.0',
  checks: { database: 'ok', rate_limiter: 'ok' },
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

function mockApi(handler: (url: string) => Response) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => handler(String(input))),
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('OverviewPage', () => {
  it('renders the latest recorded scan from the API', async () => {
    mockApi(() => jsonResponse(HISTORY))
    render(
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>,
    )

    expect((await screen.findAllByText('checkout-service.zip')).length).toBeGreaterThan(0)
    expect(screen.getByText('62')).toBeInTheDocument()
    expect(screen.getAllByText('at risk').length).toBeGreaterThan(0)
    expect(screen.getByText(/ledger.zip/i)).toBeInTheDocument()
  })

  it('shows an honest empty state when no scans are recorded', async () => {
    mockApi(() => jsonResponse({ scans: [] }))
    render(
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>,
    )

    expect(await screen.findByText(/no scans recorded yet/i)).toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  it('surfaces an API failure with a retry, not fake data', async () => {
    mockApi(() => jsonResponse({ error: 'nope' }, 401))
    render(
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>,
    )

    expect((await screen.findAllByText(/rejected this key/i)).length).toBeGreaterThan(0)
    expect(screen.getAllByRole('button', { name: /retry/i }).length).toBeGreaterThan(0)
  })
})

describe('SettingsPage', () => {
  it('shows the real health and readiness values', async () => {
    mockApi((url) => {
      if (url.includes('/ready')) return jsonResponse(READY)
      if (url.includes('/auth/session')) return jsonResponse(SESSION)
      return jsonResponse(HEALTH)
    })
    render(
      <ThemeProvider>
        <MemoryRouter>
          <SettingsPage />
        </MemoryRouter>
      </ThemeProvider>,
    )

    expect(await screen.findByText('PiQuaChu API')).toBeInTheDocument()
    expect(screen.getByText('v2.4.0')).toBeInTheDocument()
    expect(screen.getByText('celery')).toBeInTheDocument()
    expect(screen.getByText('redis')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument())
  })

  it('reports an unreachable API instead of a healthy state', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch')
      }),
    )
    render(
      <ThemeProvider>
        <MemoryRouter>
          <SettingsPage />
        </MemoryRouter>
      </ThemeProvider>,
    )

    expect(
      (await screen.findAllByText(/could not reach the api/i)).length,
    ).toBeGreaterThan(0)
  })

  it('shows the identity method the API reports', async () => {
    mockApi((url) => {
      if (url.includes('/ready')) return jsonResponse(READY)
      if (url.includes('/auth/session')) {
        return jsonResponse({
          ...SESSION,
          authenticated: true,
          method: 'api_key',
          principal: { id: 'legacy-env', tenant_id: 'local', name: 'Local operator', role: 'owner' },
          permissions: ['scan:read'],
        })
      }
      return jsonResponse(HEALTH)
    })

    render(
      <ThemeProvider>
        <MemoryRouter>
          <SettingsPage />
        </MemoryRouter>
      </ThemeProvider>,
    )

    expect(await screen.findByText('shared API key')).toBeInTheDocument()
    expect(screen.getByText('Local operator')).toBeInTheDocument()
  })
})
