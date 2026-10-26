// frontend/src/components/ReportModal.tsx
import {
  Box, Button, Heading, Modal, ModalBody, ModalContent, ModalFooter,
  ModalHeader, ModalOverlay, Table, Thead, Tbody, Tr, Th, Td, Text, Badge, CloseButton,
} from '@chakra-ui/react'
import { Printer } from 'lucide-react'
import { STANDARD_ORDER, STATUS_STYLE } from '../types'
import type { ComplianceMatrix, Finding, RemediationPlan } from '../types'

const VERDICT_SCHEME: Record<string, string> = {
  compliant: 'cobalt',
  at_risk: 'amber',
  transitional: 'violet',
  incomplete: 'amber',
  not_assessed: 'ink',
}

export default function ReportModal({
  isOpen, onClose, compliance, findings, plans, scanId,
}: {
  isOpen: boolean
  onClose: () => void
  compliance: ComplianceMatrix | null
  findings: Finding[]
  plans: RemediationPlan[]
  scanId: number | null
}) {
  if (!compliance) return null
  return (
    <Modal isOpen={isOpen} onClose={onClose} size="5xl" scrollBehavior="inside">
      <ModalOverlay bg="blackAlpha.700" backdropFilter="blur(4px)" />
      <ModalContent bg="ink.800" border="1px solid" borderColor="ink.600">
        <ModalHeader display="flex" justifyContent="space-between" alignItems="center" borderBottom="1px solid" borderColor="ink.700">
          <Heading size="md" fontFamily="heading">Executive PQC Discovery & Readiness Report</Heading>
          <CloseButton onClick={onClose} />
        </ModalHeader>
        <ModalBody id="report-content">
          {/* Header */}
          <Box mb={6} p={4} bg="ink.700" borderRadius="lg" border="1px solid" borderColor="ink.600">
            <Text fontSize="xl" fontWeight="bold" fontFamily="heading" color="ink.50">
              PiQuaChu — NIST PQC Readiness Report
            </Text>
            <Text fontSize="sm" color="ink.400" mt={1}>
              {new Date().toISOString().replace('T', ' ').slice(0, 19)} · Scan #{scanId ?? '—'} · Verdict:{' '}
              <Badge colorScheme={VERDICT_SCHEME[compliance.verdict] ?? 'crimson'}>
                {compliance.verdict.replace('_', ' ')}
              </Badge>
            </Text>
          </Box>

          {/* Executive summary */}
          <Heading size="sm" fontFamily="heading" mb={2}>
            1. Executive Summary
          </Heading>
          <Text fontSize="sm" color="ink.300" mb={4}>
            PQC Readiness Score: <Text as="b" color="cobalt.300">{compliance.pqc_score}/100</Text>. {compliance.summary}
          </Text>

          {/* Standards table */}
          <Heading size="sm" fontFamily="heading" mb={2}>
            2. NIST PQC Evidence Matrix
          </Heading>
          <Table size="sm" variant="simple" mb={4}>
            <Thead bg="blackAlpha.300">
              <Tr>
                <Th color="ink.400" borderColor="ink.700">Standard</Th>
                <Th color="ink.400" borderColor="ink.700">Algorithm</Th>
                <Th color="ink.400" borderColor="ink.700">Role</Th>
                <Th color="ink.400" borderColor="ink.700">Status</Th>
                <Th color="ink.400" borderColor="ink.700">PQC evidence / Legacy</Th>
              </Tr>
            </Thead>
            <Tbody>
              {STANDARD_ORDER.map((std) => {
                const info = compliance.standards?.[std]
                if (!info) return null
                const style = STATUS_STYLE[info.status] ?? STATUS_STYLE.not_detected
                return (
                  <Tr key={std}>
                    <Td borderColor="ink.700" color="cobalt.300" fontFamily="mono" fontSize="xs">{std}</Td>
                    <Td borderColor="ink.700" fontWeight="bold">{info.algorithm}</Td>
                    <Td borderColor="ink.700" fontSize="xs" color="ink.400">{info.role}</Td>
                    <Td borderColor="ink.700">
                      <Badge bg={style.bg} color={style.color} fontSize="xs">{style.label}</Badge>
                    </Td>
                    <Td borderColor="ink.700" fontSize="xs">{info.compliant_count} / {info.legacy_count}</Td>
                  </Tr>
                )
              })}
            </Tbody>
          </Table>

          {/* Findings */}
          <Heading size="sm" fontFamily="heading" mb={2}>
            3. Detailed Findings ({findings.length})
          </Heading>
          {findings.length === 0 ? (
            <Text fontSize="sm" color="ink.300" mb={4}>
              No matching cryptographic patterns were observed. This is not an assessment
              that the system is secure or compliant.
            </Text>
          ) : (
            <Table size="sm" variant="simple" mb={4}>
              <Thead bg="blackAlpha.300">
                <Tr>
                  <Th color="ink.400" borderColor="ink.700">Severity</Th>
                  <Th color="ink.400" borderColor="ink.700">Location</Th>
                  <Th color="ink.400" borderColor="ink.700">Issue</Th>
                  <Th color="ink.400" borderColor="ink.700">Migrate To</Th>
                </Tr>
              </Thead>
              <Tbody>
                {findings.map((f, i) => (
                  <Tr key={i}>
                    <Td borderColor="ink.700">
                      <Badge colorScheme={f.severity === 'ERROR' ? 'crimson' : f.severity === 'INFO' ? 'cobalt' : 'amber'} fontSize="xs">
                        {f.severity}
                      </Badge>
                    </Td>
                    <Td borderColor="ink.700" fontFamily="mono" fontSize="xs">{f.file}:{f.line}</Td>
                    <Td borderColor="ink.700" fontSize="xs">{f.vulnerability}</Td>
                    <Td borderColor="ink.700" fontSize="xs" color="cobalt.300">{f.target_algorithm || '—'}</Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          )}

          {/* Migration steps */}
          <Heading size="sm" fontFamily="heading" mb={2}>
            4. Migration Steps ({plans.length})
          </Heading>
          {plans.length === 0 ? (
            <Text fontSize="sm" color="ink.400">No migration plans were generated for the detected evidence.</Text>
          ) : (
            <Box>
              {plans.map((p, i) => (
                <Box key={i} mb={3} p={3} bg="ink.700" borderRadius="md" border="1px solid" borderColor="ink.600">
                  <Text fontSize="xs" color="ink.400">
                    {p.file}:{p.line} — <Text as="b" color="ink.50">{p.rule}</Text> → {p.standard} (risk: {p.plan.risk})
                  </Text>
                  <Text fontSize="xs" color="ink.500" mt={1}>{p.plan.dependencies}</Text>
                  <Box mt={2} bg="ink.900" borderRadius="sm" p={2} fontFamily="mono" fontSize="xs" overflowX="auto" whiteSpace="pre">
                    {p.plan.replacement_code}
                  </Box>
                </Box>
              ))}
            </Box>
          )}
        </ModalBody>
        <ModalFooter borderTop="1px solid" borderColor="ink.700">
          <Button leftIcon={<Printer size={16} />} colorScheme="cobalt" onClick={() => window.print()}>
            Print / Save as PDF
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  )
}