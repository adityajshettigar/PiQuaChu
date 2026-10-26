// frontend/src/test/fixtures.ts
//
// Shapes verified against the backend's real responses (see
// docs/frontend-revamp-architecture-audit.md). Tests import these instead of
// re-inventing a payload per file.
import { vi } from 'vitest'
import type { ScanDetail } from '@/lib/api'

export const HEALTH = {
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

export const SESSION_UNAUTHENTICATED = {
  authenticated: false,
  method: null,
  principal: null,
  permissions: [],
  providers: [],
  configured: false,
  problems: ['PIQUACHU_OIDC_ISSUER is not set.'],
  session_cookie_secure: false,
  session_ttl_seconds: 28800,
  same_origin_required: true,
}

export const RELIABILITY_COMPUTING = { status: 'computing', metric_source: 'not-run' }

export const SCAN_DETAIL: ScanDetail = {
  scan_id: 12,
  timestamp: '2026-10-21T08:30:00Z',
  filename: 'checkout-service.zip',
  pqc_score: 41,
  verdict: 'at_risk',
  compliance: {
    risk_score: 72,
    risk_level: 'high',
    verdict: 'at_risk',
    summary: 'PQC readiness score 41/100 (weighted risk 72/100, high).',
    findings_count: 2,
    standards: {
      'FIPS 203': {
        algorithm: 'ML-KEM',
        status: 'partial',
        evidence_status: 'mixed',
        compliant_count: 2,
        legacy_count: 3,
        rationale: '2 ML-KEM evidence finding(s) alongside 3 legacy finding(s) in the same category.',
        standard_lifecycle: 'final',
      },
      'FIPS 204': {
        algorithm: 'ML-DSA',
        status: 'non_compliant',
        compliant_count: 0,
        legacy_count: 1,
        rationale: 'Only legacy signature evidence was detected.',
      },
      'FIPS 205': {
        algorithm: 'SLH-DSA',
        status: 'not_detected',
        compliant_count: 0,
        legacy_count: 0,
        rationale: 'No qualifying evidence observed.',
      },
      'FIPS 206': {
        algorithm: 'FN-DSA',
        status: 'detected_in_development',
        compliant_count: 1,
        legacy_count: 0,
        rationale: 'Algorithm evidence only; FIPS 206 is not finalized.',
      },
    },
    advisory: { hashing: 2, symmetric: 1, tls: 0, total: 3 },
    assessment: {
      status: 'static_discovery',
      evidence_coverage: 'static source-pattern evidence only',
      standards_registry_reviewed: '2026-10-18',
      score_formula_version: 'readiness-v1',
      risk_formula_version: 'risk-v1',
      limitations: 'Static evidence only. Not a compliance certificate.',
    },
  },
  findings: [
    {
      rule_id: 'rsa-keypair',
      severity: 'ERROR',
      verdict: 'FAIL',
      nist_standard: 'FIPS 203',
      category: 'key-encapsulation',
      file: 'src/auth/Keys.java',
      line: 42,
      fingerprint: 'fp-rsa',
      pqc_compliant: false,
      engine: 'semgrep',
      engine_version: '2.3.0',
      evidence_type: 'ast_api_pattern',
      rationale: 'Rule matched RSA key generation in a key-establishment path.',
      recommendation: 'Replace RSA key transport with ML-KEM.',
      target_algorithm: 'ML-KEM',
      limitations: 'Static pattern evidence only.',
      snippet: [
        { line: 41, text: '  // key exchange' },
        { line: 42, text: '  KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");' },
      ],
    },
    {
      rule_id: 'weak-crypto-md5',
      severity: 'WARNING',
      verdict: 'WARN',
      nist_standard: 'FIPS 202',
      category: 'hashing',
      file: 'src/util/hash.py',
      line: 9,
      fingerprint: 'fp-md5',
      pqc_compliant: false,
      engine: 'ast',
    },
  ],
  remediation_plans: [
    {
      file: 'src/auth/Keys.java',
      line: 42,
      rule: 'rsa-keypair',
      standard: 'FIPS 203',
      plan: {
        risk: 'high',
        source: 'local-rule-engine',
        justification: 'RSA key transport is not quantum-resistant; ML-KEM is the finalized replacement.',
        dependencies: 'liboqs',
        replacement_code: 'KEM kem = KEM.getInstance("ML-KEM");',
      },
    },
  ],
  baseline: null,
  counts: { findings: 2, remediation_plans: 1 },
}

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

export function stubScanApi(detail: ScanDetail = SCAN_DETAIL) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.includes('/reliability')) return jsonResponse(RELIABILITY_COMPUTING)
    if (url.includes('/auth/session')) return jsonResponse(SESSION_UNAUTHENTICATED)
    if (url.endsWith(`/api/v1/scans/${detail.scan_id}`)) return jsonResponse(detail)
    if (url.includes(`/api/v1/scans/${detail.scan_id}/cbom`)) {
      return jsonResponse({ bomFormat: 'CycloneDX', specVersion: '1.7', components: [] })
    }
    return jsonResponse({ error: 'not found' }, 404)
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}
