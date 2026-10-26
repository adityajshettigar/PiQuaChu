// frontend/src/ScanLogs.tsx
import { useEffect, useRef } from 'react'
import { Box, Flex, Text, Badge } from '@chakra-ui/react'
import { motion } from 'framer-motion'
import type { JobLog } from './types'

const LEVEL_COLOR: Record<string, string> = {
  info: 'ink.200',
  debug: 'ink.400',
  warn: 'amber.300',
  warning: 'amber.300',
  error: 'crimson.300',
  success: 'cobalt.300',
}

export default function ScanLogs({ logs, status }: { logs: JobLog[]; status: string | null }) {
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [logs])

  const running = status === 'PENDING' || status === 'ANALYSING'

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <Box bg="ink.800" border="1px solid" borderColor="ink.600" borderRadius="xl" overflow="hidden" shadow="lg">
        <Flex align="center" justify="space-between" px={4} py={2.5} bg="ink.700" borderBottom="1px solid" borderColor="ink.600">
          <Flex align="center" gap={2}>
            <Box w="8px" h="8px" borderRadius="full" bg={running ? 'cobalt.400' : 'ink.400'} className={running ? 'pulse-dot' : undefined} />
            <Text fontFamily="heading" fontSize="xs" letterSpacing="0.08em" color="ink.100" textTransform="uppercase">
              Analysis Console
            </Text>
          </Flex>
          <Badge colorScheme={running ? 'cobalt' : status === 'FAILED' ? 'crimson' : 'ink'} fontSize="2xs" borderRadius="full" px={2}>
            {status ?? 'idle'}
          </Badge>
        </Flex>
        <Box ref={scrollRef} maxH="220px" overflowY="auto" px={4} py={3} fontFamily="mono" fontSize="xs" bg="ink.900">
          {logs.length === 0 ? (
            <Text color="ink.400">waiting for the engine to emit logs…</Text>
          ) : (
            logs.map((log, i) => (
              <Flex key={i} gap={2} py={0.5} whiteSpace="pre-wrap">
                <Text color="ink.500" flexShrink={0}>
                  {log.t?.split('T')[1]?.slice(0, 8) ?? log.t}
                </Text>
                <Text color={LEVEL_COLOR[log.level?.toLowerCase()] ?? 'ink.200'} flexShrink={0} minW="52px" textTransform="uppercase">
                  {log.level}
                </Text>
                <Text color="ink.200">{log.message}</Text>
              </Flex>
            ))
          )}
        </Box>
      </Box>
    </motion.div>
  )
}