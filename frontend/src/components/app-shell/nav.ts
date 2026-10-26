// frontend/src/components/app-shell/nav.ts
//
// The navigation model. Only destinations that exist in this build appear
// here — no placeholder routes and no inert links.
import {
  Activity,
  BookOpen,
  History,
  House,
  ScanLine,
  type LucideIcon,
} from 'lucide-react'

export interface NavItem {
  to: string
  label: string
  description: string
  icon: LucideIcon
  /** Match the path exactly (used for the index route). */
  end?: boolean
}

export const NAV_ITEMS: NavItem[] = [
  {
    to: '/',
    label: 'Home',
    description: 'Start here: what the scanner found, and what to do next',
    icon: House,
    end: true,
  },
  {
    to: '/scan',
    label: 'Scan',
    description: 'Upload a source archive and run the scanner',
    icon: ScanLine,
  },
  {
    to: '/history',
    label: 'History',
    description: 'Every scan stored for this tenant',
    icon: History,
  },
  {
    to: '/standards',
    label: 'Standards',
    description: 'NIST PQC standards and their lifecycle',
    icon: BookOpen,
  },
  {
    to: '/reliability',
    label: 'Reliability',
    description: 'Measured detection quality and its limits',
    icon: Activity,
  },
]

/**
 * The nav entry whose section a path belongs to. Result workspaces belong to
 * the Scan section even though they live under /results.
 */
export function navItemForPath(pathname: string): NavItem {
  if (pathname.startsWith('/results')) {
    return NAV_ITEMS.find((item) => item.to === '/scan') ?? NAV_ITEMS[0]
  }
  const match = NAV_ITEMS.find((item) =>
    item.end ? pathname === item.to : pathname.startsWith(item.to),
  )
  return match ?? NAV_ITEMS[0]
}
