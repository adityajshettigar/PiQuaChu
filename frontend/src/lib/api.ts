// frontend/src/lib/api.ts
//
// Single network boundary for the whole UI. Every request goes through
// `apiFetch`, which maps failures into a typed ApiError the UI can render
// truthfully (no raw server text, no stack traces).
//
// Authentication is either an API key (local / CI deployments) or an OIDC
// session cookie issued by the backend. The cookie is only sent when the API is
// same-origin (`credentials: 'same-origin'`), so a production deployment serves
// the SPA and /api from one origin. The client never stores tokens.

export const API_BASE_URL = (
  import.meta.env.VITE_API_URL || 'http://localhost:5000'
).replace(/\/+$/, '')

/**
 * Local development key. Vite inlines VITE_* into the bundle, so this is only
 * ever acceptable for a localhost-only deployment — never a production secret.
 */
export const API_KEY: string = import.meta.env.VITE_API_KEY || ''

export const MAX_UPLOAD_BYTES = 50 * 1024 * 1024
export const ACCEPTED_ARCHIVE_EXTENSIONS = ['.zip'] as const

export type ApiErrorKind =
  | 'aborted'
  | 'network'
  | 'unauthorized'
  | 'forbidden'
  | 'rate_limited'
  | 'not_found'
  | 'too_large'
  | 'server'
  | 'malformed'
  | 'unknown'

const KIND_MESSAGES: Record<ApiErrorKind, string> = {
  aborted: 'Request cancelled.',
  network: 'Could not reach the API. Is the PiQuaChu backend running?',
  unauthorized: "The API rejected this key (401). Check the key configured for this build.",
  forbidden: 'This key is not permitted to perform that action (403).',
  rate_limited: 'Rate limit reached. Wait a moment before trying again (429).',
  not_found: 'Not found. The scan or job may no longer exist for this tenant.',
  too_large: 'The upload exceeds the server limit (413).',
  server: 'The API reported an internal error.',
  malformed: 'The API returned a response this interface could not read.',
  unknown: 'The request failed.',
}

export class ApiError extends Error {
  readonly kind: ApiErrorKind
  readonly status?: number

  constructor(kind: ApiErrorKind, status?: number, detail?: string) {
    super(detail ? `${KIND_MESSAGES[kind]} (${detail})` : KIND_MESSAGES[kind])
    this.name = 'ApiError'
    this.kind = kind
    this.status = status
  }
}

function kindForStatus(status: number): ApiErrorKind {
  if (status === 401) return 'unauthorized'
  if (status === 403) return 'forbidden'
  if (status === 404) return 'not_found'
  if (status === 413) return 'too_large'
  if (status === 429) return 'rate_limited'
  if (status >= 500) return 'server'
  return 'unknown'
}

export interface ApiRequestOptions {
  method?: 'GET' | 'POST' | 'DELETE'
  body?: BodyInit | null
  /** JSON body convenience: sets Content-Type and stringifies. */
  json?: unknown
  signal?: AbortSignal
  /** Defaults to true for JSON endpoints; export endpoints pass false. */
  parseJson?: boolean
}

export async function apiFetch<T>(
  path: string,
  options: ApiRequestOptions = {},
): Promise<T> {
  const { method = 'GET', body, json, signal, parseJson = true } = options
  const headers: Record<string, string> = {
    ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
    Accept: parseJson ? 'application/json' : '*/*',
  }
  let payload = body
  if (json !== undefined) {
    headers['Content-Type'] = 'application/json'
    payload = JSON.stringify(json)
  }

  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method,
      body: payload,
      signal,
      headers,
      // Session cookies (when the API is same-origin). Never sends them
      // cross-origin, where the deployment cannot set them anyway.
      credentials: 'same-origin',
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new ApiError('aborted')
    }
    throw new ApiError('network')
  }

  if (!response.ok) {
    // A 401 with no configured key is a configuration problem, not a bad key:
    // say so instead of blaming a key that was never sent.
    if (response.status === 401 && !API_KEY) {
      throw new ApiError(
        'unauthorized',
        401,
        'no X-API-Key is configured for this build — set VITE_API_KEY or sign in',
      )
    }
    throw new ApiError(kindForStatus(response.status), response.status)
  }
  if (!parseJson) {
    return response as unknown as T
  }
  try {
    return (await response.json()) as T
  } catch {
    throw new ApiError('malformed', response.status)
  }
}

// ---------------------------------------------------------------------------
// Contracts (mirrors of verified backend responses — see
// docs/frontend-revamp-architecture-audit.md)
// ---------------------------------------------------------------------------

export interface HealthResponse {
  status: string
  service: string
  version: string
  checks: {
    database: { status: string }
    rate_limiter: { backend: string; failure_mode: string }
    job_backend: string
  }
  configuration: {
    environment: string
    tenancy_mode: string
    warnings: string[]
  }
}

export interface ReadinessResponse {
  status: 'ready' | 'not_ready'
  version: string
  checks: { database: string; rate_limiter: string }
}

export interface ScanHistoryItem {
  id: number
  timestamp: string
  filename: string
  pqc_score: number
  verdict: string
}

export interface ScanHistoryResponse {
  scans: ScanHistoryItem[]
}

export interface JobLogEntry {
  t: string
  level: string
  message: string
}

export type JobStatus =
  | 'PENDING'
  | 'ANALYSING'
  | 'SUCCESS'
  | 'FAILED'
  | 'TIMEOUT'

export interface ScanJobResponse {
  status: JobStatus | string
  scan_id?: number | null
  engine?: string | null
  findings?: unknown[]
  compliance?: Record<string, unknown> | null
  remediation_plans?: unknown[]
  count?: number
  logs?: JobLogEntry[]
  error?: string
  updated_at?: string
}

/**
 * One rule match. Every field other than the location/identity is optional
 * because older scans stored fewer of them; the UI shows "unreported" rather
 * than inventing a value.
 */
export interface Finding {
  rule_id?: string
  vulnerability?: string
  severity?: string
  verdict?: string
  category?: string
  nist_standard?: string
  target_algorithm?: string
  algorithm?: string
  file?: string
  line?: number | string
  line_start?: number
  line_end?: number
  line_text?: string
  snippet?: Array<{ line: number; text: string }>
  recommendation?: string
  rationale?: string
  evidence_type?: string
  evidence_source?: string
  evidence_kind?: string
  engine?: string
  engine_version?: string
  confidence?: string
  confidence_score?: number
  confidence_tier?: string
  pqc_compliant?: boolean
  limitations?: string
  fingerprint?: string
  standard_lifecycle?: string
  [key: string]: unknown
}

export interface RemediationPlan {
  replacement_code?: string
  dependencies?: string
  justification?: string
  risk?: string
  source?: string
  [key: string]: unknown
}

export interface RemediationEntry {
  file?: string
  line?: number | string
  rule?: string
  standard?: string
  plan: RemediationPlan
  created_at?: string
}

export interface StandardAssessment {
  algorithm?: string
  former?: string
  role?: string
  status?: string
  evidence_status?: string
  standard_lifecycle?: string
  lifecycle_label?: string
  confidence?: string
  rationale?: string
  compliant_count?: number
  legacy_count?: number
  severity?: string
  source?: string
  reviewed?: string
}

export interface AdvisoryCounts {
  hashing?: number
  symmetric?: number
  tls?: number
  secrets?: number
  dependencies?: number
  kdf?: number
  randomness?: number
  total?: number
}

export interface ComplianceSummary {
  pqc_score?: number
  risk_score?: number
  risk_level?: string
  verdict?: string
  summary?: string
  findings_count?: number
  hybrid?: boolean
  informational_count?: number
  assessment?: {
    status?: string
    evidence_coverage?: string
    standards_registry_reviewed?: string
    semantics_version?: string
    score_formula_version?: string
    risk_formula_version?: string
    limitations?: string
  }
  standards?: Record<string, StandardAssessment>
  advisory?: AdvisoryCounts
  [key: string]: unknown
}

export interface ScanDetail {
  scan_id: number
  timestamp: string | null
  filename: string | null
  pqc_score: number | null
  verdict: string | null
  compliance: ComplianceSummary | null
  findings: Finding[]
  remediation_plans: RemediationEntry[]
  baseline: Record<string, unknown> | null
  counts: { findings: number; remediation_plans: number }
}

/** Detection metrics over the labeled corpus. Never invented: when the
 * benchmark has not run the API answers 202 with `status: 'computing'`. */
export interface ReliabilityResponse {
  status: string
  metric_source?: string
  generated_at?: string | null
  age_seconds?: number | null
  stale?: boolean
  corpus_size?: number
  confusion?: { tp: number; fp: number; fn: number; tn: number }
  metrics?: {
    accuracy?: number | null
    precision?: number | null
    recall?: number | null
    f1?: number | null
  }
  external_validation?: {
    metric_source?: string
    status?: string
    note?: string
    generated_at?: string | null
    age_seconds?: number | null
    targets?: unknown
    confusion?: unknown
    micro?: Record<string, number | null>
    macro?: Record<string, number | null>
    per_target?: Record<string, unknown>
  }
  release_gates?: Record<string, unknown>
  ruleset?: Record<string, unknown>
  corpus?: Record<string, unknown>
  note?: string
  [key: string]: unknown
}

export interface AssistantAnswer {
  question: string
  answer: string
  code: string | null
  has_context: boolean
  scan_id?: number | null
  remote_ai?: boolean
  privacy_note?: string
}

/** CycloneDX CBOM document for a stored scan (`GET /api/v1/scans/{id}/cbom`). */
export type CbomDocument = Record<string, unknown>

/** SARIF 2.1.0 log for a stored scan (`GET /api/v1/scans/{id}/sarif`). */
export type SarifDocument = Record<string, unknown>

export interface AuthProvider {
  id: string
  name: string
  issuer: string
  scopes?: string
}

export interface AuthSessionResponse {
  authenticated: boolean
  method: 'session' | 'api_key' | null
  principal: {
    id?: string
    tenant_id?: string
    name?: string
    role?: string
    legacy?: boolean
    key_prefix?: string | null
  } | null
  permissions: string[]
  expires_at?: number | null
  providers: AuthProvider[]
  configured: boolean
  provider?: string | null
  issuer?: string | null
  problems: string[]
  session_cookie_secure?: boolean
  session_ttl_seconds?: number
  tenant?: string
  default_role?: string
  same_origin_required?: boolean
}

export const api = {
  health: (signal?: AbortSignal) =>
    apiFetch<HealthResponse>('/api/v1/health', { signal }),
  reliability: (signal?: AbortSignal) =>
    apiFetch<ReliabilityResponse>('/api/v1/reliability', { signal }),
  cbom: (scanId: number, signal?: AbortSignal) =>
    apiFetch<CbomDocument>(`/api/v1/scans/${scanId}/cbom`, { signal }),
  sarif: (scanId: number, signal?: AbortSignal) =>
    apiFetch<SarifDocument>(`/api/v1/scans/${scanId}/sarif`, { signal }),
  readiness: (signal?: AbortSignal) =>
    apiFetch<ReadinessResponse>('/api/v1/ready', { signal }),
  history: (signal?: AbortSignal) =>
    apiFetch<ScanHistoryResponse>('/api/v1/scans', { signal }),
  scan: (scanId: number, signal?: AbortSignal) =>
    apiFetch<ScanDetail>(`/api/v1/scans/${scanId}`, { signal }),
  job: (taskId: string, signal?: AbortSignal) =>
    apiFetch<ScanJobResponse>(`/api/v1/scan/${encodeURIComponent(taskId)}`, {
      signal,
    }),
  jobLogs: (taskId: string, signal?: AbortSignal) =>
    apiFetch<{ logs: JobLogEntry[] }>(
      `/api/v1/scan/${encodeURIComponent(taskId)}/logs`,
      { signal },
    ),
  submitScan: (form: FormData, signal?: AbortSignal) =>
    apiFetch<{ status: string; task_id: string }>('/api/v1/sast-scan', {
      method: 'POST',
      body: form,
      signal,
    }),
  assistant: (question: string, scanId?: number, signal?: AbortSignal) =>
    apiFetch<AssistantAnswer>('/api/v1/assistant/query', {
      method: 'POST',
      json: scanId === undefined ? { question } : { question, scan_id: scanId },
      signal,
    }),
  session: (signal?: AbortSignal) =>
    apiFetch<AuthSessionResponse>('/api/v1/auth/session', { signal }),
  logout: () =>
    apiFetch<{ authenticated: boolean }>('/api/v1/auth/logout', {
      method: 'POST',
    }),
}

/** Absolute URL that starts the provider login. The backend sets the cookies;
 * `return_to` is restricted to same-application paths server-side. */
export function loginUrl(returnTo: string): string {
  return `${API_BASE_URL}/api/v1/auth/login?return_to=${encodeURIComponent(returnTo)}`
}

/** Fetch an exported artifact as a Blob, so the browser can save exactly what
 * the server produced (no re-serialization). */
export async function apiDownload(
  path: string,
  signal?: AbortSignal,
): Promise<{ blob: Blob; filename: string | null }> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
      Accept: '*/*',
    },
    credentials: 'same-origin',
    signal,
  })
  if (!response.ok) {
    throw new ApiError(
      kindForStatus(response.status),
      response.status,
      `export failed (HTTP ${response.status})`,
    )
  }
  const disposition = response.headers.get('Content-Disposition') || ''
  const match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disposition)
  return { blob: await response.blob(), filename: match ? match[1] : null }
}
