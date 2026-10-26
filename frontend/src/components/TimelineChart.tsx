// frontend/src/components/TimelineChart.tsx
import { Box, Heading, Text, Tooltip } from '@chakra-ui/react'
import { motion } from 'framer-motion'
import type { ScanHistoryItem } from '../types'

function dotColor(score: number) {
  if (score >= 70) return 'var(--chakra-colors-cobalt-400)'
  if (score >= 40) return 'var(--chakra-colors-amber-400)'
  return 'var(--chakra-colors-crimson-400)'
}

export default function TimelineChart({ history }: { history: ScanHistoryItem[] }) {
  if (history.length === 0) {
    return (
      <Box bg="ink.800" border="1px solid" borderColor="ink.600" borderRadius="xl" p={5}>
        <Text fontSize="2xs" letterSpacing="0.14em" color="ink.400" textTransform="uppercase" mb={1}>
          Trend
        </Text>
        <Heading size="md" fontFamily="heading" letterSpacing="tight" mb={1}>
          Time Machine — Readiness Evolution
        </Heading>
        <Text color="ink.400" fontSize="sm">
          No previous scans yet. Run a scan to start tracking PQC readiness over time.
        </Text>
      </Box>
    )
  }

  const W = 640
  const H = 180
  const PAD = 24
  const scores = history.map((h) => h.pqc_score).reverse()
  const maxScore = Math.max(100, ...scores)
  const minScore = Math.min(0, ...scores)
  const range = maxScore - minScore || 1
  const stepX = scores.length > 1 ? (W - PAD * 2) / (scores.length - 1) : 0
  const points = scores.map((s, i) => ({
    x: PAD + (scores.length > 1 ? i * stepX : 0),
    y: H - PAD - ((s - minScore) / range) * (H - PAD * 2),
    score: s,
    item: history[history.length - 1 - i],
  }))
  const path = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ')
  const areaPath = `${path} L ${points[points.length - 1].x.toFixed(1)} ${H - PAD} L ${points[0].x.toFixed(1)} ${H - PAD} Z`

  return (
    <Box bg="ink.800" border="1px solid" borderColor="ink.600" borderRadius="xl" p={{ base: 4, md: 5 }}>
      <Text fontSize="2xs" letterSpacing="0.14em" color="ink.400" textTransform="uppercase" mb={1}>
        Trend
      </Text>
      <Heading size="md" fontFamily="heading" letterSpacing="tight" mb={3}>
        Time Machine — Readiness Evolution
      </Heading>
      <Box overflowX="auto">
        <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ minWidth: '280px' }} role="img" aria-label="PQC readiness over time">
          <defs>
            <linearGradient id="areaFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--chakra-colors-cobalt-400)" stopOpacity="0.30" />
              <stop offset="100%" stopColor="var(--chakra-colors-cobalt-400)" stopOpacity="0.02" />
            </linearGradient>
            <linearGradient id="lineStroke" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="var(--chakra-colors-crimson-400)" />
              <stop offset="50%" stopColor="var(--chakra-colors-amber-400)" />
              <stop offset="100%" stopColor="var(--chakra-colors-cobalt-400)" />
            </linearGradient>
          </defs>
          {[0, 25, 50, 75, 100].map((v) => {
            const y = H - PAD - ((v - minScore) / range) * (H - PAD * 2)
            return (
              <g key={v}>
                <line x1={PAD} y1={y} x2={W - PAD} y2={y} stroke="var(--chakra-colors-ink-700)" strokeDasharray="4 4" strokeWidth="1" />
                <text x={PAD - 6} y={y + 3} textAnchor="end" fontSize="10" fill="var(--chakra-colors-ink-400)" fontFamily="monospace">
                  {v}
                </text>
              </g>
            )
          })}
          <path d={areaPath} fill="url(#areaFill)" />
          {/* Line draws itself in on load */}
          <motion.path
            d={path}
            fill="none"
            stroke="url(#lineStroke)"
            strokeWidth="2.5"
            strokeLinecap="round"
            initial={{ pathLength: 0 }}
            animate={{ pathLength: 1 }}
            transition={{ duration: 1.1, ease: 'easeInOut' }}
          />
          {points.map((p, i) => (
            <motion.g
              key={i}
              initial={{ opacity: 0, scale: 0 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.5 + i * 0.06, duration: 0.3 }}
              style={{ transformOrigin: `${p.x}px ${p.y}px` }}
            >
              <Tooltip
                label={`#${p.item.id} · score ${p.score} · ${p.item.timestamp.split('T')[0]}`}
                placement="top"
                hasArrow
              >
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={p.score < 70 ? 4.5 : 3.5}
                  fill={dotColor(p.score)}
                  stroke="var(--chakra-colors-ink-900)"
                  strokeWidth="1.5"
                  style={{ cursor: 'pointer' }}
                />
              </Tooltip>
            </motion.g>
          ))}
        </svg>
      </Box>
      <Text fontSize="xs" color="ink.400" mt={2} fontFamily="mono">
        {history.length} scan{history.length === 1 ? '' : 's'} recorded · latest: {history[0].filename} — score {history[0].pqc_score}
      </Text>
    </Box>
  )
}
