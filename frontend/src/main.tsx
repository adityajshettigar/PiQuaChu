// frontend/src/main.tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { ChakraProvider } from '@chakra-ui/react'
import App from './App.tsx'
import theme from './theme'
import { ThemeProvider } from './components/app-shell/theme-provider'

// Financial design system faces, self-hosted (no remote font CDN).
// Michroma carries titles and headings, IBM Plex Sans carries statement and
// reading text, IBM Plex Mono carries data and metadata such as scan ids,
// timestamps and readiness scores.
import '@fontsource/michroma/400.css'
import '@fontsource/ibm-plex-sans/400.css'
import '@fontsource/ibm-plex-sans/500.css'
import '@fontsource/ibm-plex-sans/600.css'
import '@fontsource/ibm-plex-mono/400.css'
import '@fontsource/ibm-plex-mono/500.css'

import './index.css'

// ChakraProvider remains during the migration: the classic scan console is
// still Chakra-based. New surfaces use the Tailwind tokens in index.css.
//
// resetCSS is off on purpose: Chakra's reset is injected as unlayered CSS, and
// unlayered rules outrank every Tailwind layer, so it silently overrode heading
// sizes, button fills and spacing across the whole app. Tailwind's preflight
// (in @layer base) now provides the reset, and utilities win over it normally.
ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ThemeProvider>
      <BrowserRouter>
        <ChakraProvider theme={theme} resetCSS={false}>
          <App />
        </ChakraProvider>
      </BrowserRouter>
    </ThemeProvider>
  </React.StrictMode>,
)
