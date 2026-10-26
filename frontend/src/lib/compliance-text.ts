// frontend/src/lib/compliance-text.ts
//
// Phase 2: short, truthful compliance summary strings for the scan results
// page. These mirror the verdict vocabulary the API returns — no invented
// scores or verdicts.
export const COMPLIANCE_SUMMARY_TEXT: Record<string, string> = {
  compliant:
    'Recognized PQC algorithm evidence was detected for a finalized standard. Static pattern evidence only — not a compliance certification.',
  partial:
    'PQC usage was found, but legacy algorithm(s) of the same category remain. Continue migration work before relying on this as evidence of readiness.',
  non_compliant:
    'Only legacy cryptography was observed for the standards in scope. Migration planning is needed before post-quantum readiness can be asserted.',
  at_risk:
    'The scan found a mix of PQC and legacy evidence, or evidence in a category that is not yet fully migrated. Treat this as a warning, not a pass.',
  transitional:
    'Hybrid classical and PQC usage was detected. Migration appears to be in progress; confirm the transition is complete before relying on these findings.',
  incomplete:
    'The scan returned incomplete evidence for this archive. Re-run the scan or check the archive contents.',
  not_assessed:
    'No matching cryptographic evidence was observed. This is not a pass — absence of detected evidence is not proof the cryptography is absent.',
  unknown:
    'The API did not return a verdict for this scan.',
}
