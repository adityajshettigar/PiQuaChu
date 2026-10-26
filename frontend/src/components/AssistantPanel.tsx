// frontend/src/components/AssistantPanel.tsx
import { useEffect, useRef, useState } from 'react'
import {
  Box, Button, Flex, IconButton, Input, Text, VStack, Spinner, useToast,
} from '@chakra-ui/react'
import { motion, AnimatePresence } from 'framer-motion'
import { Bot, Send, X, Sparkles } from 'lucide-react'
import type { AssistantResponse } from '../types'

interface Message {
  role: 'user' | 'assistant'
  content: string
  code?: string | null
}

const QUICK_PROMPTS = [
  'Show me all RSA findings in the last scan',
  'What is the recommended Dilithium parameter set?',
  'Generate an executive summary of our PQC readiness',
]

function MiniMarkdown({ text, code }: { text: string; code?: string | null }) {
  // Code fence blocks
  const segments = text.split(/```[a-z]*\n?/)
  return (
    <Box fontSize="sm" lineHeight="tall" wordBreak="break-word">
      {segments.map((seg, i) => (
        <Box key={i}>
          {i % 2 === 1 ? (
            <Box bg="blackAlpha.500" border="1px solid" borderColor="ink.600" borderRadius="md" p={2} fontFamily="mono" fontSize="xs" overflowX="auto" whiteSpace="pre">
              {seg}
            </Box>
          ) : (
            <>
              {seg.split('\n').map((line, j) => {
                if (line.trim().startsWith('- ')) {
                  return (
                    <Flex key={j} gap={2}>
                      <Text color="cobalt.300">•</Text>
                      <Text flex="1">{renderInline(line.trim().slice(2))}</Text>
                    </Flex>
                  )
                }
                return (
                  <Text key={j} color="ink.100">
                    {renderInline(line) || '\u00A0'}
                  </Text>
                )
              })}
            </>
          )}
        </Box>
      ))}
      {code && (
        <Box bg="blackAlpha.500" border="1px solid" borderColor="ink.600" borderRadius="md" p={2} mt={2} fontFamily="mono" fontSize="xs" overflowX="auto" whiteSpace="pre">
          {code}
        </Box>
      )}
    </Box>
  )
}

function renderInline(line: string) {
  // **bold** -> <strong>
  const parts = line.split(/\*\*(.+?)\*\*/g)
  return parts.map((part, i) =>
    i % 2 === 1 ? (
      <Text as="strong" key={i} color="cobalt.200">
        {part}
      </Text>
    ) : (
      <Text as="span" key={i}>
        {part}
      </Text>
    ),
  )
}

export default function AssistantPanel({ apiBase, apiKey }: { apiBase: string; apiKey: string }) {
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content:
        "I'm your virtual **DevSecOps engineer** for post-quantum migration. Ask me about the NIST standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA), your scan results, or recommended migration steps.",
    },
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)
  const toast = useToast()

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [messages, open])

  const send = async (text: string) => {
    const question = text.trim()
    if (!question || loading) return
    setMessages((m) => [...m, { role: 'user', content: question }])
    setInput('')
    setLoading(true)
    try {
      const res = await fetch(`${apiBase}/api/v1/assistant/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
        body: JSON.stringify({ question }),
      })
      const data = (await res.json()) as AssistantResponse & { error?: string }
      if (!res.ok) throw new Error(data.error || data.answer || 'Assistant request failed')
      setMessages((m) => [...m, { role: 'assistant', content: data.answer, code: data.code }])
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      setMessages((m) => [...m, { role: 'assistant', content: `⚠ ${message}` }])
      toast({ title: 'Assistant error', description: message, status: 'error', duration: 4000 })
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <motion.div
        style={{ position: 'fixed', bottom: 24, right: 24, zIndex: 50 }}
        initial={{ scale: 0 }}
        animate={{ scale: 1 }}
        transition={{ type: 'spring', stiffness: 260, damping: 20 }}
      >
        <IconButton
          aria-label="Open AI assistant"
          onClick={() => setOpen((o) => !o)}
          icon={open ? <X size={22} /> : <Bot size={22} />}
          size="lg"
          borderRadius="full"
          bg="cobalt.500"
          color="ink.50"
          _hover={{ bg: 'cobalt.400', transform: 'scale(1.06)' }}
          shadow="0 8px 30px rgba(52, 85, 206, 0.4)"
          transition="all 0.2s"
        />
      </motion.div>

      <AnimatePresence>
        {open && (
          <motion.div
            style={{
              position: 'fixed',
              bottom: 88,
              right: 24,
              zIndex: 49,
              width: 'min(420px, calc(100vw - 48px))',
              height: 'min(560px, calc(100vh - 120px))',
              display: 'flex',
              flexDirection: 'column',
            }}
            initial={{ opacity: 0, y: 24, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 24, scale: 0.96 }}
            transition={{ duration: 0.22, ease: 'easeOut' }}
          >
            <Box
              bg="ink.800"
              border="1px solid"
              borderColor="ink.600"
              borderRadius="2xl"
              shadow="2xl"
              display="flex"
              flexDir="column"
              overflow="hidden"
              height="100%"
            >
              <Flex align="center" gap={3} px={4} py={3} bg="ink.700" borderBottom="1px solid" borderColor="ink.600">
                <Box bg="cobalt.500" borderRadius="full" p={1.5}>
                  <Sparkles size={16} color="var(--chakra-colors-ink-50)" />
                </Box>
                <Box flex="1">
                  <Text fontFamily="heading" fontWeight="bold" fontSize="sm" color="ink.50">
                    PQC Sentinel Assistant
                  </Text>
                  <Text fontSize="xs" color="ink.400">
                    DevSecOps engineer · RAG over your scans
                  </Text>
                </Box>
              </Flex>

              <Box ref={scrollRef} flex="1" overflowY="auto" p={4} bg="ink.900">
                <VStack spacing={3} align="stretch">
                  {messages.map((m, i) => (
                    <Flex key={i} justify={m.role === 'user' ? 'flex-end' : 'flex-start'}>
                      <Box
                        maxW="88%"
                        bg={m.role === 'user' ? 'cobalt.900' : 'ink.800'}
                        border="1px solid"
                        borderColor={m.role === 'user' ? 'cobalt.700' : 'ink.600'}
                        borderRadius="lg"
                        px={3}
                        py={2}
                      >
                        <MiniMarkdown text={m.content} code={m.code} />
                      </Box>
                    </Flex>
                  ))}
                  {loading && (
                    <Flex justify="flex-start">
                      <Box bg="ink.800" borderRadius="lg" px={4} py={3}>
                        <Spinner size="sm" color="cobalt.400" speed="0.7s" />
                      </Box>
                    </Flex>
                  )}
                </VStack>
              </Box>

              <Box p={3} borderTop="1px solid" borderColor="ink.600" bg="ink.700">
                <Flex gap={1.5} mb={2} overflowX="auto" pb={1}>
                  {QUICK_PROMPTS.map((q) => (
                    <Button
                      key={q}
                      size="xs"
                      variant="outline"
                      colorScheme="ink"
                      whiteSpace="nowrap"
                      onClick={() => send(q)}
                      disabled={loading}
                    >
                      {q.length > 28 ? q.slice(0, 28) + '…' : q}
                    </Button>
                  ))}
                </Flex>
                <Flex gap={2}>
                  <Input
                    placeholder="Ask about your PQC readiness…"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && send(input)}
                    bg="ink.900"
                    borderColor="ink.500"
                    size="md"
                  />
                  <IconButton aria-label="Send" icon={<Send size={18} />} onClick={() => send(input)} disabled={loading || !input.trim()} colorScheme="cobalt" />
                </Flex>
              </Box>
            </Box>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}