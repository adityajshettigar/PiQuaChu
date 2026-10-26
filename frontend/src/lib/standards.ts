// frontend/src/lib/standards.ts
//
// The one place the frontend states NIST PQC standard lifecycle. This mirrors
// `backend/standards.py` (the maintained registry, reviewed 2026-10-18) because
// the API does not expose a standards endpoint. The backend suite
// (`backend/test_standards.py`, `backend/test_docs.py`) is the source of truth;
// when that registry changes, update this file in the same change and bump
// REVIEWED_ON. Never claim a standard is final unless the registry says so.
//
// Detection of an algorithm is evidence, not proof of compliance.

export type StandardLifecycle = 'final' | 'in_development'

export interface StandardEntry {
  /** Official standard code, e.g. "FIPS 203". */
  id: string
  algorithm: string
  /** Former/working name, e.g. "CRYSTALS-Kyber". */
  former: string
  role: string
  lifecycle: StandardLifecycle
  /** Human label used in the UI. */
  lifecycleLabel: string
  /** Primary documentation, maintained here (allow-listed links only). */
  href: string
  /** One-line detection caveat shown with the entry. */
  caveat: string
}

export const STANDARDS_REVIEWED_ON = '2026-10-18'

export const STANDARDS: StandardEntry[] = [
  {
    id: 'FIPS 203',
    algorithm: 'ML-KEM',
    former: 'CRYSTALS-Kyber',
    role: 'Key encapsulation (general encryption)',
    lifecycle: 'final',
    lifecycleLabel: 'Final',
    href: 'https://csrc.nist.gov/pubs/fips/203/final',
    caveat: 'Detecting ML-KEM in source is evidence of use, not of correct parameters or key handling.',
  },
  {
    id: 'FIPS 204',
    algorithm: 'ML-DSA',
    former: 'CRYSTALS-Dilithium',
    role: 'Digital signatures (primary)',
    lifecycle: 'final',
    lifecycleLabel: 'Final',
    href: 'https://csrc.nist.gov/pubs/fips/204/final',
    caveat: 'A signature algorithm found in code is not proof that keys are managed correctly.',
  },
  {
    id: 'FIPS 205',
    algorithm: 'SLH-DSA',
    former: 'SPHINCS+',
    role: 'Digital signatures (hash-based backup)',
    lifecycle: 'final',
    lifecycleLabel: 'Final',
    href: 'https://csrc.nist.gov/pubs/fips/205/final',
    caveat: 'Hash-based signatures are slower; presence does not imply a migration plan.',
  },
  {
    id: 'FIPS 206',
    algorithm: 'FN-DSA',
    former: 'FALCON',
    role: 'Digital signatures (lattice-based)',
    lifecycle: 'in_development',
    lifecycleLabel: 'In development',
    href: 'https://csrc.nist.gov/projects/post-quantum-cryptography',
    caveat: 'FIPS 206 is not finalized. Detecting a FALCON-style implementation is not FIPS 206 compliance.',
  },
]

export function standardsById(): Record<string, StandardEntry> {
  return Object.fromEntries(STANDARDS.map((entry) => [entry.id, entry]))
}
