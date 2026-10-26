// frontend/src/components/ThreatMap.tsx
import { useMemo, useState } from 'react'
import { Box, Flex, Heading, Text, Badge, VStack, Collapse } from '@chakra-ui/react'
import { motion } from 'framer-motion'
import { KeyRound, FileSignature, Fingerprint, Lock, Shield, Layers } from 'lucide-react'
import { CATEGORY_LABEL, CATEGORY_SCHEME, panelGlow } from '../types'
import type { Finding } from '../types'

const CATEGORY_ICON: Record<string, typeof Lock> = {
  'key-encapsulation': KeyRound,
  signatures: FileSignature,
  hashing: Fingerprint,
  symmetric: Lock,
  tls: Shield,
}

export default function ThreatMap({ findings, onSelect }: { findings: Finding[]; onSelect: (category: string | null) => void }) {
  const [expanded, setExpanded] = useState<string | null>(null)
  const [active, setActive] = useState<string | null>(null)

  const groups = useMemo(() => {
    const map = new Map<string, Finding[]>()
    for (const f of findings) {
      const cat = f.category || 'unknown'
      if (!map.has(cat)) map.set(cat, [])
      map.get(cat)!.push(f)
    }
    return Array.from(map.entries()).sort((a, b) => b[1].length - a[1].length)
  }, [findings])

  if (groups.length === 0) return null

  const toggle = (cat: string) => {
    setExpanded(expanded === cat ? null : cat)
    setActive(active === cat ? null : cat)
    onSelect(active === cat ? null : cat)
  }

  return (
    <Box>
      <Text fontSize="2xs" letterSpacing="0.14em" color="ink.400" textTransform="uppercase" mb={1}>
        Exposure Surface
      </Text>
      <Heading size="md" fontFamily="heading" letterSpacing="tight" mb={4}>
        Threat Map — by Crypto Category
      </Heading>
      <Flex gap={3} flexWrap="wrap">
        {groups.map(([cat, items], idx) => {
          const Icon = CATEGORY_ICON[cat] ?? Layers
          const scheme = CATEGORY_SCHEME[cat] ?? 'ink'
          const critical = items.some((f) => f.severity === 'ERROR')
          const compliant = items.filter((f) => f.pqc_compliant).length
          return (
            <motion.div
              key={cat}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: idx * 0.05, duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
              style={{ width: 'calc(50% - 6px)', minWidth: '150px', maxWidth: '220px', flexGrow: 1 }}
            >
              <Box
                as="button"
                onClick={() => toggle(cat)}
                bg={active === cat ? 'ink.700' : 'ink.800'}
                border="1px solid"
                borderColor={active === cat ? `${scheme}.400` : 'ink.600'}
                borderRadius="lg"
                p={4}
                textAlign="left"
                w="100%"
                {...panelGlow(scheme)}
                _hover={{
                  ...panelGlow(scheme)._hover,
                  transform: 'translateY(-2px)',
                }}
              >
                <Flex align="center" justify="space-between" mb={2}>
                  <Icon size={18} color={`var(--chakra-colors-${scheme}-300)`} />
                  <Badge colorScheme={critical ? 'crimson' : compliant ? 'cobalt' : 'amber'} fontSize="xs" borderRadius="full" fontFamily="mono">
                    {items.length}
                  </Badge>
                </Flex>
                <Text fontWeight="semibold" fontSize="sm" color="ink.50">
                  {CATEGORY_LABEL[cat] ?? cat}
                </Text>
                <Text fontSize="xs" color="ink.400" mt={1}>
                  {critical ? '⚠ critical exposures' : compliant ? `${compliant} PQC-compliant` : 'review findings'}
                </Text>
              </Box>
              <Collapse in={expanded === cat} animateOpacity>
                <Box mt={2} bg="ink.900" borderRadius="md" p={3} border="1px solid" borderColor="ink.700">
                  <VStack align="stretch" spacing={2} maxH="180px" overflowY="auto">
                    {items.slice(0, 12).map((f, i) => (
                      <Box key={i} fontSize="xs">
                        <Text
                          color={f.pqc_compliant ? 'cobalt.300' : f.severity === 'ERROR' ? 'crimson.300' : 'amber.300'}
                          fontFamily="mono"
                          noOfLines={1}
                        >
                          {f.file}:{f.line}
                        </Text>
                        <Text color="ink.400" noOfLines={1}>
                          {f.vulnerability}
                        </Text>
                      </Box>
                    ))}
                  </VStack>
                </Box>
              </Collapse>
            </motion.div>
          )
        })}
      </Flex>
    </Box>
  )
}
