// frontend/src/theme.ts
// Chakra theme — kept only for the legacy classic console (Chakra v2).
// Mirrors the Financial design system tokens in index.css: dark navy ground,
// warm orange actions, pale gold values, hairline boundaries, Michroma
// headings and IBM Plex faces.

import { extendTheme, type ThemeConfig } from '@chakra-ui/react'

const config: ThemeConfig = {
  initialColorMode: 'dark',
  useSystemColorMode: false,
}

const colors = {
  background: '#07090e',
  groundTint: '#101522',
  panel: '#10141c',
  foreground: '#f4f5f7',
  mutedForeground: '#c9ced8',
  border: '#303139',
  borderStrong: '#444652',
  primary: '#ff951f',
  primaryForeground: '#0a0c12',
  primarySubtle: 'rgba(255, 149, 31, 0.13)',
  value: '#edcd8c',
  success: '#7fd3a8',
  successSubtle: 'rgba(127, 211, 168, 0.13)',
  warning: '#ffc266',
  warningSubtle: 'rgba(255, 194, 102, 0.13)',
  danger: '#ff8a7a',
  dangerSubtle: 'rgba(255, 138, 122, 0.14)',
  info: '#9db6e0',
  infoSubtle: 'rgba(157, 182, 224, 0.13)',
}

const fonts = {
  heading: `'Michroma', 'IBM Plex Sans', system-ui, sans-serif`,
  body: `'IBM Plex Sans', system-ui, sans-serif`,
  mono: `'IBM Plex Mono', ui-monospace, monospace`,
}

const shadows = {
  outline: '0 0 0 1px rgba(255, 149, 31, 0.30)',
  sm: '0 1px 2px rgba(0, 0, 0, 0.40)',
  md: '0 2px 8px rgba(0, 0, 0, 0.40)',
  lg: '0 8px 18px rgba(0, 0, 0, 0.42)',
  xl: '0 18px 38px rgba(0, 0, 0, 0.50)',
}

// No global element styles here on purpose. Chakra injects them unlayered,
// which would outrank the Tailwind layers and pin the page to one theme. The
// document background, faces and focus ring are owned by index.css.
const styles = {}

const controlRadius = '40px'
const panelRadius = '5px'

const components = {
  Button: {
    baseStyle: {
      fontFamily: `'IBM Plex Sans', system-ui, sans-serif`,
      fontWeight: 500,
      borderRadius: controlRadius,
      letterSpacing: '0',
    },
  },
  Badge: {
    baseStyle: {
      fontFamily: `'IBM Plex Mono', monospace`,
      borderRadius: panelRadius,
      letterSpacing: '0.08em',
    },
  },
  Heading: {
    baseStyle: {
      fontFamily: `'Michroma', 'IBM Plex Sans', system-ui, sans-serif`,
      fontWeight: 400,
      letterSpacing: '-0.02em',
      lineHeight: '1.08',
    },
  },
  Input: {
    baseStyle: {
      field: {
        fontFamily: `'IBM Plex Sans', system-ui, sans-serif`,
        fontSize: '16px',
        borderRadius: controlRadius,
        background: '#10141c',
        border: '1px solid #303139',
        color: '#f4f5f7',
        _placeholder: { color: '#c9ced8' },
        _focus: {
          borderColor: '#ff951f',
          boxShadow: '0 0 0 1px #ff951f',
        },
        _disabled: { opacity: 0.5 },
      },
    },
  },
  Select: {
    baseStyle: {
      field: {
        fontFamily: `'IBM Plex Sans', system-ui, sans-serif`,
        fontSize: '16px',
        borderRadius: controlRadius,
        background: '#10141c',
        border: '1px solid #303139',
        color: '#f4f5f7',
        _focus: {
          borderColor: '#ff951f',
          boxShadow: '0 0 0 1px #ff951f',
        },
      },
    },
  },
  Table: {
    variants: {
      simple: {
        th: {
          fontFamily: `'IBM Plex Mono', monospace`,
          letterSpacing: '0.08em',
          color: '#c9ced8',
          borderColor: '#303139',
        },
        td: {
          borderColor: '#303139',
        },
      },
    },
  },
}

const theme = extendTheme({
  config,
  colors,
  fonts,
  styles,
  components,
  shadows,
})

export default theme
