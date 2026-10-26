// frontend/src/App.tsx
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useDropzone } from 'react-dropzone'
import {
  Box, VStack, Heading, Text, Table, Thead, Tbody, Tr, Th, Td,
  Badge, Spinner, useToast, Container, Icon, SimpleGrid, Stat,
  StatLabel, StatNumber, StatHelpText, Card, CardBody, Flex,
  Button, Tag, Divider, Alert, AlertIcon, AlertTitle, AlertDescription,
  Select, Collapse, UnorderedList, ListItem, VisuallyHidden,
} from '@chakra-ui/react'
import { motion } from 'framer-motion'
import { UploadCloud, ShieldAlert, AlertTriangle, ShieldCheck, FileText, History, Loader2, Download, FileArchive, Radar, ClipboardList } from 'lucide-react'
import { ConnectionStatus } from '../components/app-shell/connection-status'
import { ProgressiveFluxLoader } from '../components/ui/progressive-flux-loader'
import ComplianceMatrix from '../components/ComplianceMatrix'
import ThreatMap from '../components/ThreatMap'
import TimelineChart from '../components/TimelineChart'
import AssistantPanel from '../components/AssistantPanel'
import ReportModal from '../components/ReportModal'
import ReadinessGauge from '../components/ReadinessGauge'
import QuantumFlux from '../components/ui/quantum-flux'
import ScanLogs from '../ScanLogs'
import type {
  BaselineDelta, ComplianceMatrix as ComplianceType, Finding, GateResult,
  JobLog, RemediationPlan, ScanHistoryItem,
} from '../types'
import '../App.css'

import logoMark from '../brand/logo.png'
import logoWord from '../brand/word.png'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000'
const API_KEY = import.meta.env.VITE_API_KEY || 'super-secret-key-123'

const STANDARD_INTRO = [
  { std: 'FIPS 203', alg: 'ML-KEM', role: 'Key encapsulation — general encryption', scheme: 'cobalt' },
  { std: 'FIPS 204', alg: 'ML-DSA', role: 'Digital signatures — primary', scheme: 'violet' },
  { std: 'FIPS 205', alg: 'SLH-DSA', role: 'Digital signatures — hash-based backup', scheme: 'amber' },
  { std: 'FIPS 206', alg: 'FN-DSA', role: 'Digital signatures — lattice (FALCON, in development)', scheme: 'ink' },
] as const

function BrandLockup() {
  const [markOk, setMarkOk] = useState(true)
  return (
    <Flex align="center" gap={3}>
      <Flex
        w="46px"
        h="46px"
        borderRadius="14px"
        align="center"
        justify="center"
        overflow="hidden"
        flexShrink={0}
      >
        {markOk ? (
          <img
            src={logoMark}
            alt="PiQuaChu logo"
            className="brand-mark"
            onError={() => setMarkOk(false)}
          />
        ) : (
          <Icon as={ShieldAlert} boxSize={6} color="cobalt.300" />
        )}
      </Flex>
      <Box minH="28px">
        <Heading size="lg" fontFamily="heading" letterSpacing="tight" bgGradient="linear(to-r, crimson.300, cobalt.300)" bgClip="text">
          PiQuaChu
        </Heading>
      </Box>
    </Flex>
  )
}

export default function ClassicConsole() {
  const [findings, setFindings] = useState<Finding[]>([])
  const [compliance, setCompliance] = useState<ComplianceType | null>(null)
  const [plans, setPlans] = useState<RemediationPlan[]>([])
  const [jobStatus, setJobStatus] = useState<string | null>(null)
  const [logs, setLogs] = useState<JobLog[]>([])
  const [engine, setEngine] = useState<string | null>(null)
  const [history, setHistory] = useState<ScanHistoryItem[]>([])
  const [isScanning, setIsScanning] = useState(false)
  const [scanComplete, setScanComplete] = useState(false)
  const [scanId, setScanId] = useState<number | null>(null)
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null)
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [sortBy, setSortBy] = useState<string>('none')
  const [reportOpen, setReportOpen] = useState(false)
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())
  // Phase 3 workflow controls: optional committed baseline + gate policy.
  const [baselineFile, setBaselineFile] = useState<File | null>(null)
  const [failOn, setFailOn] = useState<string>('new-error')
  const [baselineDelta, setBaselineDelta] = useState<BaselineDelta | null>(null)
  const [gate, setGate] = useState<GateResult | null>(null)
  const [sarifLoading, setSarifLoading] = useState(false)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const toast = useToast()

  const fetchHistory = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/scans`, {
        headers: { 'X-API-Key': API_KEY },
      })
      if (!res.ok) return
      const data = await res.json()
      setHistory(data.scans ?? [])
    } catch {
      /* history is non-critical */
    }
  }, [])

  const exportJson = useCallback(() => {
    const payload = {
      generated_at: new Date().toISOString(),
      scan_id: scanId,
      compliance,
      findings,
      remediation_plans: plans,
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `piquachu-report-${scanId ?? 'export'}.json`
    a.click()
    URL.revokeObjectURL(url)
  }, [scanId, compliance, findings, plans])

  const downloadSarif = useCallback(async () => {
    if (!scanId) return
    setSarifLoading(true)
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/scans/${scanId}/sarif`, {
        headers: { 'X-API-Key': API_KEY },
      })
      if (!res.ok) throw new Error(`SARIF export failed (HTTP ${res.status})`)
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `piquachu-scan-${scanId}.sarif`
      a.click()
      URL.revokeObjectURL(url)
    } catch (error) {
      toast({
        title: 'SARIF export failed',
        description: error instanceof Error ? error.message : String(error),
        status: 'error',
        duration: 5000,
        isClosable: true,
      })
    } finally {
      setSarifLoading(false)
    }
  }, [scanId, toast])

  useEffect(() => {
    fetchHistory()
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [fetchHistory])

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }, [])

  const pollTask = useCallback(
    (taskId: string) => {
      stopPolling()
      let elapsed = 0
      pollRef.current = setInterval(async () => {
        elapsed += 2000
        try {
          const res = await fetch(`${API_BASE_URL}/api/v1/scan/${taskId}`, {
            headers: { 'X-API-Key': API_KEY },
          })
          const data = await res.json()
          if (!res.ok) {
            if (res.status === 404) {
              stopPolling()
              setJobStatus('FAILED')
              toast({ title: 'Scan job not found', status: 'error', duration: 4000 })
            }
            return
          }
          setJobStatus(data.status)
          if (Array.isArray(data.logs)) setLogs(data.logs)
          if (data.status === 'SUCCESS') {
            stopPolling()
            setFindings(data.findings ?? [])
            setCompliance(data.compliance ?? null)
            setScanId(data.scan_id ?? null)
            setEngine(data.engine ?? null)
            setPlans(data.remediation_plans ?? [])
            setBaselineDelta(data.baseline_delta ?? null)
            setGate(data.gate ?? null)
            setScanComplete(true)
            fetchHistory()
            toast({
              title: 'Analysis complete',
              description: `${data.findings?.length ?? 0} finding(s) · score ${data.compliance?.pqc_score ?? '?'}/100 · ${data.count ?? 0} migration plan(s)`,
              status: 'success',
              duration: 4000,
              isClosable: true,
              position: 'top-right',
            })
          } else if (data.status === 'FAILED') {
            stopPolling()
            setScanComplete(false)
            toast({
              title: 'Scan job failed',
              description: data.error ?? 'Check the live logs for details.',
              status: 'error',
              duration: 6000,
              isClosable: true,
            })
          }
        } catch {
          /* transient poll error */
        }
        if (elapsed >= 180000) {
          stopPolling()
          setJobStatus((s) => (s === 'SUCCESS' || s === 'FAILED' ? s : 'TIMEOUT'))
        }
      }, 2000)
    },
    [stopPolling, toast, fetchHistory],
  )

  const onDrop = useCallback(
    async (acceptedFiles: File[]) => {
      const file = acceptedFiles[0]
      if (!file) return

      setIsScanning(true)
      setScanComplete(false)
      setFindings([])
      setPlans([])
      setCompliance(null)
      setLogs([])
      setEngine(null)
      setBaselineDelta(null)
      setGate(null)
      setJobStatus('PENDING')
      const formData = new FormData()
      formData.append('file', file)
      if (baselineFile) {
        formData.append('baseline', baselineFile)
        formData.append('fail_on', failOn)
      }

      try {
        const response = await fetch(`${API_BASE_URL}/api/v1/sast-scan`, {
          method: 'POST',
          headers: { 'X-API-Key': API_KEY },
          body: formData,
        })
        const data = await response.json()

        if (response.ok) {
          if (data.task_id) pollTask(data.task_id)
          if (Array.isArray(data.findings)) {
            setFindings(data.findings)
            setCompliance(data.compliance ?? null)
            setScanId(data.scan_id ?? null)
            setEngine(data.engine ?? null)
            setScanComplete(true)
            fetchHistory()
          }
          toast({
            title: 'Analysis dispatched',
            description: `Scanning ${file.name} — results will appear when analysis completes.`,
            status: 'info',
            duration: 4000,
            isClosable: true,
            position: 'top-right',
          })
        } else {
          throw new Error(data.error || 'Scan failed')
        }
      } catch (error) {
        setJobStatus(null)
        setLogs([])
        toast({
          title: 'Scan Failed',
          description: error instanceof Error ? error.message : String(error),
          status: 'error',
          duration: 5000,
          isClosable: true,
        })
      } finally {
        setIsScanning(false)
      }
    },
    [toast, pollTask, fetchHistory, baselineFile, failOn],
  )

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'application/zip': ['.zip'] },
    multiple: false,
  })

  const toggleRow = useCallback((key: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }, [])

  const { totalIssues, criticalIssues, warningIssues, compliantUses } = useMemo(() => {
    const critical = findings.filter((f) => f.severity === 'ERROR').length
    const warning = findings.filter((f) => f.severity === 'WARNING').length
    const ok = findings.filter((f) => f.pqc_compliant).length
    return { totalIssues: findings.length, criticalIssues: critical, warningIssues: warning, compliantUses: ok }
  }, [findings])

  const score = compliance?.pqc_score ?? (totalIssues === 0 ? 100 : Math.max(0, 100 - criticalIssues * 15 - warningIssues * 5))
  const visibleFindings = useMemo(() => {
    let list = categoryFilter
      ? findings.filter((f) => (f.category || 'unknown') === categoryFilter)
      : findings
    if (severityFilter !== 'all') {
      list = list.filter((f) => {
        if (severityFilter === 'PASS') return !!f.pqc_compliant
        if (severityFilter === 'FAIL') return !f.pqc_compliant && f.severity === 'ERROR'
        if (severityFilter === 'WARN') return !f.pqc_compliant && f.severity === 'WARNING'
        return true
      })
    }
    if (sortBy === 'severity') {
      const rank = { ERROR: 0, WARNING: 1, INFO: 2 }
      list = [...list].sort((a, b) => {
        const ar = a.pqc_compliant ? 3 : (rank as Record<string, number>)[a.severity] ?? 2
        const br = b.pqc_compliant ? 3 : (rank as Record<string, number>)[b.severity] ?? 2
        return ar - br
      })
    } else if (sortBy === 'standard') {
      list = [...list].sort((a, b) =>
        (a.nist_standard || '—').localeCompare(b.nist_standard || '—'))
    } else if (sortBy === 'file') {
      list = [...list].sort((a, b) => a.file.localeCompare(b.file))
    }
    return list
  }, [findings, categoryFilter, severityFilter, sortBy])
  const clean = totalIssues === 0 || (totalIssues > 0 && criticalIssues === 0 && warningIssues === 0)

  return (
    <Container maxW="container.xl" py={8}>
      <VStack spacing={8} align="stretch">
        <Flex align="center" justify="space-between" flexWrap="wrap" gap={3}>
          <BrandLockup />
          {/* Real backend health — never a hard-coded "all systems" light. */}
          <ConnectionStatus compact />
        </Flex>

        <motion.div initial={{ opacity: 0, y: -12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
          <Box
            position="relative"
            height={{ base: '340px', sm: '400px', md: '460px' }}
            borderRadius="2xl"
            overflow="hidden"
            border="1px solid"
            borderColor="ink.600"
            shadow="2xl"
          >
            <QuantumFlux headline="PIQUACHU" className="absolute inset-0" />
            <Flex
              position="absolute"
              inset={0}
              align="center"
              justify="center"
              pointerEvents="none"
            >
              <img src={logoWord} alt="PiQuaChu" className="brand-word-hero" />
            </Flex>
            <Flex
              direction="column"
              align="center"
              position="absolute"
              bottom={{ base: 4, md: 6 }}
              left={0}
              right={0}
              px={{ base: 4, md: 8 }}
              pointerEvents="none"
            >
              <Text
                fontSize={{ base: 'xs', md: 'sm' }}
                color="ink.200"
                textAlign="center"
                maxW="640px"
                textShadow="0 2px 12px rgba(0,0,0,0.8)"
              >
                Post-quantum discovery engine — map cryptography against the three
                finalized NIST PQC standards plus FN-DSA (FIPS 206, in development).
              </Text>
              <Flex gap={2} mt={3} flexWrap="wrap" justify="center">
                {STANDARD_INTRO.map((s) => (
                  <Tag
                    key={s.std}
                    size="sm"
                    variant="outline"
                    colorScheme={s.scheme}
                    borderRadius="full"
                    px={3}
                    bg="blackAlpha.600"
                    backdropFilter="blur(8px)"
                  >
                    <Box w="6px" h="6px" borderRadius="full" bg={`${s.scheme}.400`} mr={2} />
                    {s.alg} · {s.std}
                  </Tag>
                ))}
              </Flex>
            </Flex>
          </Box>
        </motion.div>

        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}>
          <Box
            {...getRootProps()}
            className="hero-dropzone"
            p={{ base: 6, sm: 8, md: 12 }}
            border="1px solid"
            borderColor={isDragActive ? 'cobalt.400' : 'ink.600'}
            borderRadius="2xl"
            bg={isDragActive ? 'cobalt.900' : 'ink.800'}
            textAlign="center"
            cursor="pointer"
            transition="all 0.3s cubic-bezier(.08,.52,.52,1)"
            _hover={{ bg: 'ink.700', transform: 'translateY(-2px)', shadow: 'lg' }}
          >
            <input {...getInputProps()} />
            <Icon as={UploadCloud} boxSize={12} color={isDragActive ? 'cobalt.300' : 'ink.400'} mb={4} />
            {isScanning ? (
              <VStack spacing={4}>
                <Spinner size="xl" thickness="4px" color="cobalt.400" emptyColor="ink.600" />
                <Text fontSize="lg" fontFamily="heading" fontWeight="medium" color="cobalt.300">
                  Running AST analysis engine…
                </Text>
                <Text fontSize="sm" color="ink.400">Semgrep rules engine · zero-trust local analysis</Text>
              </VStack>
            ) : (
              <VStack spacing={2}>
                <Text fontSize="xl" fontFamily="heading" fontWeight="semibold" color="ink.50">
                  {isDragActive ? 'Drop the .zip here to begin…' : 'Deploy Target Archive (.zip)'}
                </Text>
                <Text color="ink.300">Drag & drop your source code, or click to browse</Text>
                <Text fontSize="xs" color="ink.500">Python · Java · JavaScript/TypeScript · Go · C/C++</Text>
              </VStack>
            )}
          </Box>
        </motion.div>

        {!isScanning && (
          <Box bg="ink.800" border="1px solid" borderColor="ink.600" borderRadius="xl" p={5}>
            <Heading size="sm" fontFamily="heading" letterSpacing="tight" mb={1}>
              Baseline gate (optional)
            </Heading>
            <Text fontSize="xs" color="ink.400" mb={3}>
              Attach a committed baseline to report only what changed. Existing findings stop
              failing the build — the same policy the CLI and CI pipelines use.
            </Text>
            <Flex gap={3} flexWrap="wrap" align="center">
              <Button
                as="label"
                size="sm"
                variant="outline"
                colorScheme="ink"
                leftIcon={<FileText size={14} />}
                cursor="pointer"
                data-testid="baseline-attach"
              >
                {baselineFile ? baselineFile.name : 'Attach baseline.json'}
                <VisuallyHidden>
                  <input
                    type="file"
                    accept="application/json,.json"
                    aria-label="Baseline JSON file"
                    onChange={(e) => setBaselineFile(e.target.files?.[0] ?? null)}
                  />
                </VisuallyHidden>
              </Button>
              <Select
                size="sm"
                width="200px"
                bg="ink.900"
                borderColor="ink.600"
                aria-label="Gate policy"
                value={failOn}
                onChange={(e) => setFailOn(e.target.value)}
                isDisabled={!baselineFile}
              >
                <option value="new-error">Fail on: new error</option>
                <option value="new-high">Fail on: new high</option>
                <option value="new-warning">Fail on: new warning</option>
                <option value="changed-error">Fail on: changed error</option>
                <option value="none">Report only (no gate)</option>
              </Select>
              {baselineFile && (
                <Button size="sm" variant="ghost" colorScheme="ink" onClick={() => setBaselineFile(null)}>
                  Remove baseline
                </Button>
              )}
            </Flex>
          </Box>
        )}

        {!scanComplete && !isScanning && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.15 }}>
            <Box bg="ink.800" border="1px solid" borderColor="ink.600" borderRadius="xl" p={{ base: 5, md: 6 }}>
              <Heading size="sm" fontFamily="heading" letterSpacing="tight" mb={1}>
                How it works
              </Heading>
              <Text fontSize="sm" color="ink.400" mb={5}>
                Three steps to a standards-mapped discovery report — source analysis is
                local; optional AI receives anonymized metadata only.
              </Text>
              <SimpleGrid columns={{ base: 1, md: 3 }} spacing={4} mb={6}>
                {[
                  {
                    icon: FileArchive,
                    step: '01',
                    title: 'Drop your .zip',
                    body: 'Drag any source archive onto the dropzone above — Python, Java, JS/TS, Go, C/C++, Rust, PHP.',
                  },
                  {
                    icon: Radar,
                    step: '02',
                    title: 'Watch the AST scan',
                    body: 'Semantic rules map cryptography usage across FIPS 203 · 204 · 205 · 206 in real time.',
                  },
                  {
                    icon: ClipboardList,
                    step: '03',
                    title: 'Fix with one click',
                    body: 'Every legacy finding ships a drop-in migration plan; mechanical fixes are patchable automatically.',
                  },
                ].map((s, i) => (
                  <Flex key={s.step} gap={3} align="flex-start">
                    <Flex
                      w="44px" h="44px"
                      borderRadius="lg"
                      bg="ink.900"
                      border="1px solid"
                      borderColor="ink.600"
                      align="center"
                      justify="center"
                      flexShrink={0}
                      position="relative"
                    >
                      <Icon as={s.icon} boxSize={5} color="cobalt.300" />
                      <Text
                        position="absolute" top={-1} right={-1}
                        fontSize="2xs" fontFamily="mono" color="ink.500"
                        bg="ink.800" px={1} borderRadius="md"
                      >
                        {s.step}
                      </Text>
                    </Flex>
                    <Box>
                      <Text fontWeight="semibold" color="ink.50" fontSize="sm" mb={0.5}>
                        {i < 2 && <Text as="span" display={{ base: 'none', md: 'inline' }} color="ink.600" mr={2}>—</Text>}
                        {s.title}
                      </Text>
                      <Text fontSize="xs" color="ink.400">{s.body}</Text>
                    </Box>
                  </Flex>
                ))}
              </SimpleGrid>

              <Text fontSize="2xs" letterSpacing="0.14em" color="ink.400" textTransform="uppercase" mb={3}>
                What PiQuaChu checks
              </Text>
              <SimpleGrid columns={{ base: 1, sm: 2, lg: 4 }} spacing={3} mb={4}>
                {STANDARD_INTRO.map((s) => (
                  <Box key={s.std} bg="ink.900" border="1px solid" borderColor="ink.700" borderRadius="lg" p={4}>
                    <Badge colorScheme={s.scheme} fontSize="xs" mb={2} fontFamily="mono">{s.std}</Badge>
                    <Text fontWeight="bold" fontFamily="heading" color="ink.50" fontSize="md">{s.alg}</Text>
                    <Text fontSize="xs" color="ink.500">{s.role}</Text>
                  </Box>
                ))}
              </SimpleGrid>
              <UnorderedList fontSize="xs" color="ink.500" spacing={1}>
                <ListItem>AST-based detection (Semgrep) — 100+ rules across Python, Java, JS/TS, Go, C/C++, Rust, PHP</ListItem>
                <ListItem>Legacy RSA / ECDSA / MD5 / SHA-1 / DES usage flagged with exact FIPS migration targets</ListItem>
                <ListItem>AI-generated migration plans + automatic AST remediation patches (Python & Java)</ListItem>
                <ListItem>Weighted risk score (0–100) + NIST readiness score (0–100) per scan</ListItem>
              </UnorderedList>
            </Box>
          </motion.div>
        )}

        {(jobStatus === 'PENDING' || jobStatus === 'ANALYSING') && (
          <ProgressiveFluxLoader
            mode="indeterminate"
            label="Scan progress"
            statusText={
              jobStatus === 'PENDING'
                ? 'Queued — the API has not started analysis yet.'
                : 'Analysis in progress — the API reports no percentage.'
            }
            phases={[
              { id: 'queued', label: 'Queued' },
              { id: 'analysing', label: 'Analysing' },
            ]}
            activePhaseId={jobStatus === 'PENDING' ? 'queued' : 'analysing'}
          />
        )}
        {(jobStatus === 'PENDING' || jobStatus === 'ANALYSING' || logs.length > 0) && (
          <ScanLogs logs={logs} status={jobStatus} />
        )}

        {scanComplete && compliance && (
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }}>
            <VStack spacing={8} align="stretch">
              <Flex align="center" justify="space-between" flexWrap="wrap" gap={3}>
                <Box>
                  <Text fontSize="2xs" letterSpacing="0.14em" color="ink.400" textTransform="uppercase" mb={1}>
                    Results
                  </Text>
                  <Heading size="lg" fontFamily="heading" letterSpacing="tight">
                    Scan Results
                  </Heading>
                </Box>
                <Flex gap={2} flexWrap="wrap">
                  {scanId && <Tag size="sm" colorScheme="cobalt" variant="outline">scan #{scanId}</Tag>}
                  {engine && <Tag size="sm" colorScheme="ink" variant="outline">engine: {engine}</Tag>}
                </Flex>
              </Flex>

              {baselineDelta && (
                <Box
                  bg="ink.800"
                  border="1px solid"
                  borderColor={gate?.triggered ? 'crimson.600' : 'cobalt.600'}
                  borderRadius="xl"
                  p={5}
                  data-testid="baseline-gate"
                >
                  <Flex align="center" justify="space-between" flexWrap="wrap" gap={3}>
                    <Box>
                      <Text fontSize="2xs" letterSpacing="0.14em" color="ink.400" textTransform="uppercase" mb={1}>
                        Baseline gate
                      </Text>
                      <Flex gap={2} align="center" flexWrap="wrap">
                        <Badge colorScheme={gate ? (gate.triggered ? 'crimson' : 'cobalt') : 'ink'} fontFamily="mono">
                          {gate ? (gate.triggered ? 'BLOCKED' : 'PASSED') : 'DELTA ONLY'}
                        </Badge>
                        <Text fontSize="sm" color="ink.300" fontFamily="mono">
                          {gate?.policy ?? baselineDelta.mode}
                        </Text>
                      </Flex>
                    </Box>
                    <Flex gap={2} flexWrap="wrap" align="center">
                      <Tag size="sm" colorScheme={baselineDelta.counts.new > 0 ? 'amber' : 'ink'}>
                        new {baselineDelta.counts.new}
                      </Tag>
                      <Tag size="sm" colorScheme="ink">persistent {baselineDelta.counts.persistent}</Tag>
                      <Tag size="sm" colorScheme={baselineDelta.counts.changed > 0 ? 'violet' : 'ink'}>
                        changed {baselineDelta.counts.changed}
                      </Tag>
                      <Tag size="sm" colorScheme={baselineDelta.counts.resolved > 0 ? 'cobalt' : 'ink'}>
                        resolved {baselineDelta.counts.resolved}
                      </Tag>
                      <Tag size="sm" colorScheme="ink">suppressed {baselineDelta.counts.suppressed}</Tag>
                      <Button
                        size="sm"
                        variant="outline"
                        colorScheme="ink"
                        leftIcon={<Download size={14} />}
                        isLoading={sarifLoading}
                        loadingText="SARIF"
                        onClick={downloadSarif}
                        isDisabled={!scanId}
                      >
                        Download SARIF
                      </Button>
                    </Flex>
                  </Flex>
                  {baselineDelta.uncertain?.is_uncertain && (
                    <Alert status="warning" bg="amber.900" border="1px solid" borderColor="amber.700" borderRadius="lg" mt={4}>
                      <AlertIcon color="amber.300" />
                      <Box>
                        <AlertTitle color="ink.50" fontSize="sm">Comparison is best-effort</AlertTitle>
                        <AlertDescription fontSize="xs" color="ink.200">
                          {(baselineDelta.uncertain.reasons ?? []).slice(0, 3).join(' · ')
                            || 'Identity could not be fully preserved (renames, moves or probes).'}
                        </AlertDescription>
                      </Box>
                    </Alert>
                  )}
                  {gate?.triggered && (
                    <Box mt={4}>
                      <Text fontSize="2xs" color="ink.400" textTransform="uppercase" letterSpacing="0.1em" mb={2}>
                        Failing findings
                      </Text>
                      <UnorderedList fontSize="xs" color="ink.200" fontFamily="mono" spacing={1}>
                        {gate.failures.slice(0, 8).map((f) => (
                          <ListItem key={`${f.fingerprint ?? f.rule_id}-${f.file}-${f.line}`}>
                            {f.severity} · {f.rule_id} · {f.file}:{f.line}
                          </ListItem>
                        ))}
                      </UnorderedList>
                      {gate.failures.length > 8 && (
                        <Text fontSize="xs" color="ink.500" mt={1}>
                          +{gate.failures.length - 8} more — download SARIF for the full list
                        </Text>
                      )}
                    </Box>
                  )}
                </Box>
              )}

              {clean && (
                <Alert
                  status={compliance.verdict === 'not_assessed' ? 'info' : 'success'}
                  bg={compliance.verdict === 'not_assessed' ? 'ink.700' : 'cobalt.900'}
                  border="1px solid"
                  borderColor={compliance.verdict === 'not_assessed' ? 'ink.500' : 'cobalt.700'}
                  borderRadius="xl"
                >
                  <AlertIcon color={compliance.verdict === 'not_assessed' ? 'ink.300' : 'cobalt.300'} />
                  <Box>
                    <AlertTitle color="ink.50">
                      {compliance.verdict === 'not_assessed'
                        ? 'No matching cryptographic evidence observed'
                        : 'No PQC migration issues observed'}
                    </AlertTitle>
                    <AlertDescription fontSize="sm" color="ink.300">
                      {compliance.summary}
                    </AlertDescription>
                  </Box>
                </Alert>
              )}

              <SimpleGrid columns={{ base: 1, sm: 2, lg: 4 }} spacing={4}>
                <Card bg="ink.800" border="1px solid" borderColor="ink.600">
                  <CardBody>
                    <Text color="ink.400" fontSize="sm" fontWeight="medium" mb={2}>PQC Readiness Score</Text>
                    <ReadinessGauge
                      score={score}
                      subtitle={`Weighted risk ${compliance?.risk_score ?? '–'}/100 · ${compliance?.risk_level ?? 'n/a'}`}
                    />
                  </CardBody>
                </Card>
                <Card bg="ink.800" border="1px solid" borderColor="crimson.900">
                  <CardBody>
                    <Stat>
                      <Flex align="center" gap={2} mb={1}>
                        <Icon as={AlertTriangle} color="crimson.400" />
                        <StatLabel color="crimson.300" fontSize="md">Critical Exposures</StatLabel>
                      </Flex>
                      <StatNumber fontSize="4xl" fontFamily="heading" color="ink.50">{criticalIssues}</StatNumber>
                      <StatHelpText color="ink.400">Quantum-broken algos (RSA/ECC/DES)</StatHelpText>
                    </Stat>
                  </CardBody>
                </Card>
                <Card bg="ink.800" border="1px solid" borderColor="amber.900">
                  <CardBody>
                    <Stat>
                      <Flex align="center" gap={2} mb={1}>
                        <Icon as={ShieldCheck} color="amber.400" />
                        <StatLabel color="amber.300" fontSize="md">Weak Hashing / TLS</StatLabel>
                      </Flex>
                      <StatNumber fontSize="4xl" fontFamily="heading" color="ink.50">{warningIssues}</StatNumber>
                      <StatHelpText color="ink.400">MD5/SHA-1/TLS 1.0/1.1 upgrades</StatHelpText>
                    </Stat>
                  </CardBody>
                </Card>
                <Card bg="ink.800" border="1px solid" borderColor="cobalt.900">
                  <CardBody>
                    <Stat>
                      <Flex align="center" gap={2} mb={1}>
                        <Icon as={ShieldCheck} color="cobalt.400" />
                        <StatLabel color="cobalt.300" fontSize="md">PQC Evidence Detections</StatLabel>
                      </Flex>
                      <StatNumber fontSize="4xl" fontFamily="heading" color="ink.50">{compliantUses}</StatNumber>
                      <StatHelpText color="ink.400">Algorithm evidence — not a compliance certification</StatHelpText>
                    </Stat>
                  </CardBody>
                </Card>
              </SimpleGrid>

              <ComplianceMatrix compliance={compliance} />

              {totalIssues > 0 && <ThreatMap findings={findings} onSelect={setCategoryFilter} />}

              {visibleFindings.length > 0 && (
                <Box overflowX="auto" bg="ink.800" borderRadius="xl" border="1px solid" borderColor="ink.600" shadow="2xl">
                  <Flex p={6} borderBottom="1px solid" borderColor="ink.600" align="center" justify="space-between" flexWrap="wrap" gap={3}>
                    <Heading size="md" fontFamily="heading">Findings Report</Heading>
                    <Flex gap={2} flexWrap="wrap" align="center">
                      <Select
                        size="sm"
                        width="150px"
                        bg="ink.900"
                        borderColor="ink.600"
                        value={severityFilter}
                        onChange={(e) => setSeverityFilter(e.target.value)}
                        aria-label="Filter by verdict"
                      >
                        <option value="all">All verdicts</option>
                        <option value="FAIL">FAIL (critical)</option>
                        <option value="WARN">WARN (weak)</option>
                        <option value="PASS">PASS (compliant)</option>
                      </Select>
                      <Select
                        size="sm"
                        width="150px"
                        bg="ink.900"
                        borderColor="ink.600"
                        value={sortBy}
                        onChange={(e) => setSortBy(e.target.value)}
                        aria-label="Sort findings"
                      >
                        <option value="none">Sort: default</option>
                        <option value="severity">Sort: severity</option>
                        <option value="standard">Sort: standard</option>
                        <option value="file">Sort: file</option>
                      </Select>
                      {categoryFilter && (
                        <Tag size="sm" colorScheme="cobalt" onClick={() => setCategoryFilter(null)} cursor="pointer">
                          filter: {categoryFilter} ✕
                        </Tag>
                      )}
                      <Tag size="sm" colorScheme="ink">{visibleFindings.length} of {totalIssues}</Tag>
                    </Flex>
                  </Flex>
                  <Table variant="simple" size="md">
                    <Thead
                      bg="ink.900"
                      sx={{
                        position: 'sticky',
                        top: 0,
                        zIndex: 1,
                        boxShadow: '0 1px 0 0 var(--chakra-colors-ink-600)',
                      }}
                    >
                      <Tr>
                        <Th borderColor="ink.600" color="ink.400">Severity</Th>
                        <Th borderColor="ink.600" color="ink.400">Standard</Th>
                        <Th borderColor="ink.600" color="ink.400">Location</Th>
                        <Th borderColor="ink.600" color="ink.400">Vulnerability</Th>
                        <Th borderColor="ink.600" color="ink.400">PQC Migration Plan</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {visibleFindings.map((finding) => {
                        const rowKey = `${finding.file}:${finding.line}:${finding.vulnerability}`
                        const expanded = expandedRows.has(rowKey)
                        const plan = plans.find((p) => p.file === finding.file && p.line === finding.line)
                        return (
                          <React.Fragment key={rowKey}>
                            <Tr
                              onClick={() => toggleRow(rowKey)}
                              cursor={plan ? 'pointer' : 'default'}
                              _hover={{ bg: 'whiteAlpha.100' }}
                              transition="background 0.15s"
                              role={plan ? 'button' : undefined}
                              aria-expanded={plan ? expanded : undefined}
                            >
                              <Td borderColor="ink.700">
                                <Badge
                                  colorScheme={finding.pqc_compliant ? 'cobalt' : finding.severity === 'ERROR' ? 'crimson' : 'amber'}
                                  px={3} py={1} borderRadius="full"
                                  fontFamily="mono" fontSize="xs"
                                >
                                  {finding.pqc_compliant ? 'PASS' : finding.severity === 'ERROR' ? 'FAIL' : 'WARN'}
                                </Badge>
                              </Td>
                              <Td borderColor="ink.700">
                                <Badge
                                  colorScheme={
                                    finding.nist_standard === 'FIPS 203' ? 'cobalt'
                                    : finding.nist_standard === 'FIPS 204' ? 'violet'
                                    : finding.nist_standard === 'FIPS 205' ? 'amber'
                                    : finding.nist_standard === 'FIPS 206' ? 'ink'
                                    : 'ink'}
                                  fontSize="xs" fontFamily="mono"
                                >
                                  {finding.nist_standard || '—'}
                                </Badge>
                              </Td>
                              <Td borderColor="ink.700">
                                <Text fontWeight="bold" color="cobalt.300" fontFamily="mono" fontSize="sm" noOfLines={1}>
                                  {finding.file}
                                </Text>
                                <Text fontSize="sm" color="ink.500" fontFamily="mono">Line {finding.line}</Text>
                              </Td>
                              <Td borderColor="ink.700" fontFamily="mono" fontSize="sm" color="ink.100">
                                {finding.vulnerability}
                              </Td>
                              <Td borderColor="ink.700" color="ink.300" fontSize="sm">
                                <Text noOfLines={expanded ? undefined : 2} whiteSpace="pre-wrap">
                                  {finding.recommendation}
                                </Text>
                                {finding.target_algorithm && (
                                  <Tag size="sm" colorScheme="cobalt" mt={1}>
                                    → {finding.target_algorithm}
                                  </Tag>
                                )}
                                {plan && (
                                  <Text fontSize="xs" color={expanded ? 'ink.500' : 'cobalt.400'} mt={1} fontFamily="mono">
                                    {expanded ? '▴ hide remediation plan' : `▾ ${plan.plan.source} plan — click to preview`}
                                  </Text>
                                )}
                              </Td>
                            </Tr>
                            {plan && (
                              <Tr>
                                <Td colSpan={5} borderColor="ink.700" p={0} border={expanded ? undefined : 'none'}>
                                  <Collapse in={expanded} animateOpacity>
                                    <Box bg="ink.900" px={6} py={4} borderTop="1px solid" borderColor="ink.700">
                                      <SimpleGrid columns={{ base: 1, md: 3 }} spacing={4} mb={3}>
                                        <Box>
                                          <Text fontSize="2xs" color="ink.500" textTransform="uppercase" letterSpacing="0.1em" mb={1}>Risk if skipped</Text>
                                          <Badge colorScheme={plan.plan.risk === 'high' ? 'crimson' : plan.plan.risk === 'medium' ? 'amber' : 'cobalt'} fontFamily="mono">
                                            {plan.plan.risk}
                                          </Badge>
                                        </Box>
                                        <Box>
                                          <Text fontSize="2xs" color="ink.500" textTransform="uppercase" letterSpacing="0.1em" mb={1}>Dependencies</Text>
                                          <Text fontSize="xs" color="ink.300" fontFamily="mono">{plan.plan.dependencies}</Text>
                                        </Box>
                                        <Box>
                                          <Text fontSize="2xs" color="ink.500" textTransform="uppercase" letterSpacing="0.1em" mb={1}>Source</Text>
                                          <Badge colorScheme={plan.plan.source === 'groq' ? 'violet' : 'ink'} fontFamily="mono">{plan.plan.source}</Badge>
                                        </Box>
                                      </SimpleGrid>
                                      <Text fontSize="2xs" color="ink.500" textTransform="uppercase" letterSpacing="0.1em" mb={1}>Drop-in replacement</Text>
                                      <Box
                                        as="pre"
                                        bg="blackAlpha.600"
                                        border="1px solid"
                                        borderColor="ink.700"
                                        borderRadius="md"
                                        p={3}
                                        fontSize="xs"
                                        fontFamily="mono"
                                        color="cobalt.100"
                                        overflowX="auto"
                                        maxH="280px"
                                        overflowY="auto"
                                      >
                                        <code>{plan.plan.replacement_code}</code>
                                      </Box>
                                      <Text fontSize="xs" color="ink.400" mt={2}>
                                        {plan.plan.justification}
                                      </Text>
                                    </Box>
                                  </Collapse>
                                </Td>
                              </Tr>
                            )}
                          </React.Fragment>
                        )
                      })}
                    </Tbody>
                  </Table>
                </Box>
              )}

              {jobStatus && (
                <Flex align="center" gap={2} color="ink.400" fontSize="sm">
                  {jobStatus === 'ANALYSING' || jobStatus === 'PENDING' ? (
                    <>
                      <Loader2 size={16} className="spin" /> Generating remediation plans ({jobStatus.toLowerCase()})…
                    </>
                  ) : jobStatus === 'SUCCESS' ? (
                    <Text color="cobalt.300">✓ {plans.length} remediation plan(s) ready</Text>
                  ) : jobStatus === 'FAILED' ? (
                    <Text color="crimson.300">Remediation job failed</Text>
                  ) : jobStatus === 'TIMEOUT' ? (
                    <Text color="amber.300">Polling timed out — the job may still be running in the background.</Text>
                  ) : null}
                </Flex>
              )}

              <Flex gap={3} flexWrap="wrap">
                <Button leftIcon={<FileText size={16} />} colorScheme="cobalt" onClick={() => setReportOpen(true)}>
                  Executive Report
                </Button>
                <Button leftIcon={<Download size={16} />} variant="outline" colorScheme="ink" onClick={exportJson}>
                  Export JSON
                </Button>
                <Button
                  leftIcon={<History size={16} />}
                  variant="outline"
                  colorScheme="ink"
                  onClick={() => document.getElementById('timeline')?.scrollIntoView({ behavior: 'smooth' })}
                >
                  View History
                </Button>
              </Flex>

              <Box id="timeline">
                <TimelineChart history={history} />
              </Box>
            </VStack>
          </motion.div>
        )}
      </VStack>

      <Divider my={8} borderColor="ink.700" />
      <Text textAlign="center" fontSize="xs" color="ink.500">
        PiQuaChu v2 · Zero-trust local analysis — only anonymized algorithm telemetry leaves the host.
      </Text>

      <AssistantPanel apiBase={API_BASE_URL} apiKey={API_KEY} />
      <ReportModal isOpen={reportOpen} onClose={() => setReportOpen(false)} compliance={compliance} findings={findings} plans={plans} scanId={scanId} />
    </Container>
  )
}
