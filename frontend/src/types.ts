// frontend/src/types.ts
export interface Finding {
  file: string;
  line: number;
  vulnerability: string;
  recommendation: string;
  severity: string;
  nist_standard?: string;
  category?: string;
  pqc_compliant?: boolean;
  target_algorithm?: string;
  verdict?: string;
}

export interface NistStandardInfo {
  algorithm: string;
  former: string;
  role: string;
  // Public status (backward compatible). `detected_in_development` means the
  // algorithm was detected but its standard is not finalized (FIPS 206).
  status: string; // compliant | partial | non_compliant | not_detected | transitional | detected_in_development
  evidence_status?: string; // detected | legacy_detected | mixed | not_detected | unsupported_or_inconclusive
  standard_lifecycle?: string; // final | in_development
  lifecycle_label?: string;
  confidence?: string; // high | medium | none
  rationale?: string;
  compliant_count: number;
  legacy_count: number;
  severity: string; // ok | warning | critical | info
}

export interface ComplianceMatrix {
  pqc_score: number;
  risk_score?: number;
  risk_level?: string; // low | medium | high | critical
  verdict: string; // compliant | at_risk | non_compliant | transitional | incomplete | not_assessed
  summary: string;
  findings_count: number;
  assessment?: {
    status: string;
    evidence_coverage: string;
    standards_registry_reviewed: string;
    semantics_version: string;
    score_formula_version: string;
    risk_formula_version: string;
    limitations: string;
  };
  standards: Record<string, NistStandardInfo>;
  advisory: {
    hashing: number;
    symmetric: number;
    tls: number;
    secrets?: number;
    dependencies?: number;
    kdf?: number;
    randomness?: number;
    total: number;
  };
}

export interface ScanHistoryItem {
  id: number;
  timestamp: string;
  filename: string;
  pqc_score: number;
  verdict: string;
}

export interface JobLog {
  t: string;
  level: string;
  message: string;
}

export interface RemediationPlan {
  file: string;
  line: number;
  rule: string;
  standard: string;
  plan: {
    replacement_code: string;
    dependencies: string;
    justification: string;
    risk: string;
    source: string;
  };
}

// Phase 3: baseline comparison. Only present when a baseline (or gate policy)
// was supplied with the scan; mirrors the CLI's `--baseline` / `--fail-on`.
export interface BaselineCounts {
  new: number;
  persistent: number;
  moved: number;
  changed: number;
  suppressed: number;
  resolved: number;
}

export interface BaselineDelta {
  mode: string; // no-baseline | compared
  counts: BaselineCounts;
  uncertain?: { is_uncertain: boolean; reasons?: string[] };
  baseline?: { path?: string | null; present: boolean };
}

export interface GateFailure {
  status: string;
  rule_id?: string;
  file?: string;
  line?: number;
  severity?: string;
  fingerprint?: string;
  uncertain_identity?: boolean;
}

export interface GateResult {
  policy: string;
  scope?: string;
  min_severity?: string | null;
  triggered: boolean;
  exit_code: number;
  failures: GateFailure[];
  counts?: Record<string, number>;
  annotation_only?: string[];
}

export interface AssistantResponse {
  question: string;
  answer: string;
  code: string | null;
  has_context: boolean;
}

export const STANDARD_ORDER = ['FIPS 203', 'FIPS 204', 'FIPS 205', 'FIPS 206'] as const;

// Color language: crimson = quantum-vulnerable, cobalt = quantum-safe,
// amber = partially migrated, violet = hybrid/transitional, ink = neutral.
export const STATUS_STYLE: Record<string, { label: string; color: string; bg: string; border: string }> = {
  compliant: { label: 'PQC EVIDENCE', color: 'cobalt.200', bg: 'cobalt.900', border: 'cobalt.600' },
  partial: { label: 'PARTIAL', color: 'amber.200', bg: 'amber.900', border: 'amber.600' },
  non_compliant: { label: 'MIGRATION NEEDED', color: 'crimson.200', bg: 'crimson.900', border: 'crimson.600' },
  not_detected: { label: 'NOT OBSERVED', color: 'ink.200', bg: 'ink.800', border: 'ink.500' },
  transitional: { label: 'TRANSITIONAL (HYBRID)', color: 'violet.200', bg: 'violet.900', border: 'violet.600' },
  detected_in_development: { label: 'STANDARD IN DEVELOPMENT', color: 'violet.200', bg: 'violet.900', border: 'violet.600' },
};

export const CATEGORY_LABEL: Record<string, string> = {
  'key-encapsulation': 'Key Encapsulation',
  signatures: 'Digital Signatures',
  hashing: 'Hashing',
  symmetric: 'Symmetric Ciphers',
  tls: 'Transport (TLS)',
  provider: 'PQC Provider',
  secrets: 'Secrets Hygiene',
  dependencies: 'Dependencies',
  kdf: 'KDF / Salt',
  randomness: 'Randomness',
  unknown: 'Other',
};

// colorScheme tokens (must match keys defined in theme.ts colors)
export const CATEGORY_SCHEME: Record<string, string> = {
  'key-encapsulation': 'cobalt',
  signatures: 'violet',
  hashing: 'amber',
  symmetric: 'crimson',
  tls: 'cobalt',
  provider: 'violet',
  secrets: 'amber',
  dependencies: 'ink',
  kdf: 'amber',
  randomness: 'cobalt',
  unknown: 'ink',
};

export const RISK_COLOR: Record<string, string> = {
  low: 'cobalt.300',
  medium: 'amber.300',
  high: 'crimson.300',
  critical: 'crimson.400',
};

export const RISK_SCHEME: Record<string, string> = {
  low: 'cobalt',
  medium: 'amber',
  high: 'crimson',
  critical: 'crimson',
};

// Single source of truth for the four compliance statuses — used by the
// ComplianceMatrix cards, the ThreatMap severity logic, the findings table
// badges and the TimelineChart dots so a status is always the same color.
export const STATUS_SCHEME: Record<string, string> = {
  compliant: 'cobalt',
  partial: 'amber',
  non_compliant: 'crimson',
  not_detected: 'ink',
  transitional: 'violet',
  detected_in_development: 'violet',
};

// Panel recipe shared by every dashboard card (deep near-black, subtle
// border, soft glow on hover) — the "audit console" look.
export const PANEL = {
  bg: 'ink.800',
  borderColor: 'ink.600',
  borderRadius: 'xl',
} as const;

export function panelGlow(scheme: string) {
  return {
    boxShadow: 'none',
    transition: 'all 0.25s ease',
    _hover: {
      borderColor: `var(--chakra-colors-${scheme}-500)`,
      boxShadow: `0 0 24px -6px var(--chakra-colors-${scheme}-500)`,
    },
  };
}