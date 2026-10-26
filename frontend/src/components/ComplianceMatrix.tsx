// frontend/src/components/ComplianceMatrix.tsx
import { Box, Flex, Heading, Progress, SimpleGrid, Text, Badge } from '@chakra-ui/react'
import { motion } from 'framer-motion'
import { STANDARD_ORDER, STATUS_STYLE, STATUS_SCHEME, panelGlow } from '../types'
import type { ComplianceMatrix as ComplianceMatrixType } from '../types'

const STATUS_TOOLTIP: Record<string, string> = {
  compliant: 'Recognized PQC algorithm evidence detected for a finalized standard — static pattern evidence only',
  partial: 'PQC usage found, but legacy algorithm of the same category remains',
  non_compliant: 'Only legacy algorithms found — migration required',
  not_detected: 'No matching evidence observed — unknown/not assessed, not a pass',
  transitional: 'Hybrid classical+PQC in place — migration in progress',
  detected_in_development: 'Algorithm detected, but the standard is still in development (FIPS 206 / FN-DSA) — not a finalized pass',
}

const VERDICT_SCHEME: Record<string, string> = {
  compliant: 'cobalt',
  at_risk: 'amber',
  transitional: 'violet',
  incomplete: 'amber',
  not_assessed: 'ink',
}

export default function ComplianceMatrix({ compliance }: { compliance: ComplianceMatrixType }) {
  return (
    <Box>
      <Flex align="center" justify="space-between" mb={4} flexWrap="wrap" gap={3}>
        <Box>
          <Text fontSize="2xs" letterSpacing="0.14em" color="ink.400" textTransform="uppercase" mb={1}>
            Standards Coverage
          </Text>
          <Heading size="md" fontFamily="heading" letterSpacing="tight">
            NIST PQC Discovery Matrix
          </Heading>
        </Box>
        <Badge
          colorScheme={VERDICT_SCHEME[compliance.verdict] ?? 'crimson'}
          px={3}
          py={1}
          borderRadius="full"
          fontSize="xs"
          textTransform="uppercase"
          fontFamily="mono"
        >
          Verdict: {compliance.verdict.replace('_', ' ')}
        </Badge>
      </Flex>

      <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={4}>
        {STANDARD_ORDER.map((std, idx) => {
          const info = compliance.standards?.[std]
          if (!info) return null
          const style = STATUS_STYLE[info.status] ?? STATUS_STYLE.not_detected
          const scheme = STATUS_SCHEME[info.status] ?? 'ink'
          const total = info.compliant_count + info.legacy_count
          const ratio = total > 0 ? (info.compliant_count / total) * 100 : 0
          return (
            <motion.div
              key={std}
              initial={{ opacity: 0, y: 18 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: idx * 0.07, duration: 0.45, ease: [0.16, 1, 0.3, 1] }}
            >
              <Box
                bg="ink.800"
                border="1px solid"
                borderColor={style.border}
                borderRadius="xl"
                p={5}
                height="100%"
                {...panelGlow(scheme)}
              >
                <Flex align="center" justify="space-between" mb={2}>
                  <Badge colorScheme="ink" variant="subtle" fontSize="xs" px={2} py={0.5} borderRadius="md" fontFamily="mono">
                    {std}
                  </Badge>
                  <Badge bg={style.bg} color={style.color} border="1px solid" borderColor={style.border} px={3} py={1} borderRadius="full" fontSize="xs" title={STATUS_TOOLTIP[info.status]}>
                    {style.label}
                  </Badge>
                </Flex>

                <Heading size="lg" fontFamily="heading" letterSpacing="tight" color="ink.50">
                  {info.algorithm}
                </Heading>
                <Text fontSize="xs" color="ink.400" mb={3} fontFamily="mono">
                  formerly {info.former}
                </Text>
                {info.standard_lifecycle && info.standard_lifecycle !== 'final' && (
                  <Text fontSize="2xs" color="violet.300" mb={2} fontFamily="mono">
                    {info.lifecycle_label || 'standard in development'}
                  </Text>
                )}
                <Text fontSize="sm" color="ink.300" minH="40px">
                  {info.role}
                </Text>

                <Progress
                  mt={3}
                  value={ratio}
                  colorScheme={scheme}
                  size="xs"
                  borderRadius="full"
                  bg="ink.700"
                />
                <Flex justify="space-between" mt={2} fontSize="xs" color="ink.400" fontFamily="mono">
                  <Text color="cobalt.300">{info.compliant_count} PQC evidence</Text>
                  <Text color={info.legacy_count > 0 ? 'crimson.300' : 'ink.400'}>
                    {info.legacy_count} legacy use{info.legacy_count === 1 ? '' : 's'}
                  </Text>
                </Flex>
              </Box>
            </motion.div>
          )
        })}
      </SimpleGrid>
    </Box>
  )
}
