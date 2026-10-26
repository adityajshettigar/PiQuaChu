// frontend/src/components/ReadinessGauge.tsx
//
// The page's signature element. A semicircular dial running from crimson
// (quantum-vulnerable) through amber to cobalt (quantum-safe) — the score
// is a needle position on that spectrum, not just a number in a box.
import { Box, Text, VStack } from '@chakra-ui/react'
import { motion } from 'framer-motion'

const R = 80
const CX = 100
const CY = 100
const ARC_LEN = Math.PI * R // semicircle length

function tierColor(score: number) {
  if (score >= 70) return 'var(--chakra-colors-cobalt-300)'
  if (score >= 40) return 'var(--chakra-colors-amber-300)'
  return 'var(--chakra-colors-crimson-300)'
}

export default function ReadinessGauge({ score, subtitle }: { score: number; subtitle?: string }) {
  const clamped = Math.max(0, Math.min(100, score))
  const filled = (clamped / 100) * ARC_LEN
  const rotateDeg = 180 * (clamped / 100 - 1)

  return (
    <VStack spacing={1} w="100%">
      <Box position="relative" w="100%" maxW={{ base: '200px', sm: '240px' }}>
        <motion.div
          initial={{ opacity: 0, scale: 0.92 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        >
          <svg viewBox="0 0 200 116" width="100%" role="img" aria-label={`PQC readiness score ${clamped} of 100`}>
            <defs>
              <linearGradient id="gaugeGrad" x1="20" y1="100" x2="180" y2="100" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="var(--chakra-colors-crimson-500)" />
                <stop offset="50%" stopColor="var(--chakra-colors-amber-400)" />
                <stop offset="100%" stopColor="var(--chakra-colors-cobalt-400)" />
              </linearGradient>
              <filter id="gaugeGlow" x="-30%" y="-30%" width="160%" height="160%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {/* Track */}
            <path
              d={`M 20 ${CY} A ${R} ${R} 0 0 1 180 ${CY}`}
              fill="none"
              stroke="var(--chakra-colors-ink-600)"
              strokeWidth="10"
              strokeLinecap="round"
            />
            {/* Filled arc — soft glow keeps the dial on-brand with the hero */}
            <path
              d={`M 20 ${CY} A ${R} ${R} 0 0 1 180 ${CY}`}
              fill="none"
              stroke="url(#gaugeGrad)"
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={`${filled} ${ARC_LEN}`}
              filter="url(#gaugeGlow)"
              style={{ transition: 'stroke-dasharray 1s cubic-bezier(.16,1,.3,1)' }}
            />

            {/* Ticks */}
            {[0, 25, 50, 75, 100].map((t) => {
              const ang = Math.PI * (1 - t / 100)
              const x1 = CX + (R - 6) * Math.cos(ang)
              const y1 = CY - (R - 6) * Math.sin(ang)
              const x2 = CX + (R + 4) * Math.cos(ang)
              const y2 = CY - (R + 4) * Math.sin(ang)
              return <line key={t} x1={x1} y1={y1} x2={x2} y2={y2} stroke="var(--chakra-colors-ink-500)" strokeWidth="1.5" />
            })}

            {/* Needle */}
            <g className="gauge-needle" style={{ transform: `rotate(${rotateDeg}deg)` }}>
              <line x1={CX} y1={CY} x2={CX + R - 14} y2={CY} stroke="var(--chakra-colors-ink-50)" strokeWidth="2.5" strokeLinecap="round" />
              <circle cx={CX + R - 14} cy={CY} r="3" fill="var(--chakra-colors-ink-50)" />
            </g>
            <circle cx={CX} cy={CY} r="6" fill="var(--chakra-colors-ink-100)" stroke="var(--chakra-colors-ink-900)" strokeWidth="2" />
          </svg>

          <VStack
            spacing={0}
            position="absolute"
            left="50%"
            bottom="6%"
            transform="translateX(-50%)"
          >
            <Text fontFamily="mono" fontWeight={700} fontSize="4xl" lineHeight={1} color={tierColor(clamped)}>
              {clamped}
            </Text>
            <Text fontSize="2xs" letterSpacing="0.12em" color="ink.300" textTransform="uppercase" fontFamily="mono">
              / 100
            </Text>
          </VStack>
        </motion.div>
      </Box>
      {subtitle && (
        <Text fontSize="xs" color="ink.300" textAlign="center" fontFamily="mono">
          {subtitle}
        </Text>
      )}
    </VStack>
  )
}
