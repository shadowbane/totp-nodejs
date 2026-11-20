// GENERATED from devhelper-fe/theme v1.0.1 - do not edit; change devhelper-fe/theme and run sync.mjs
import { useEffect, useState } from 'react'

/** The three choices; "system" follows the device setting. */
export type ThemeChoice = 'light' | 'dark' | 'system'
export type ResolvedTheme = 'light' | 'dark'

interface DhTheme {
  get(): ThemeChoice
  resolved(): ResolvedTheme
  set(choice: ThemeChoice): void
  subscribe(fn: (choice: ThemeChoice, resolved: ResolvedTheme) => void): () => void
  scope: 'shared' | 'local'
}

declare global {
  interface Window { dhTheme?: DhTheme }
}

/**
 * The DevHelper theme (public/devhelper-theme.js, loaded in <head>). The
 * choice is shared by every DevHelper site through one cookie, unless the
 * script tag says data-scope="local".
 */
export function useTheme() {
  const api = typeof window !== 'undefined' ? window.dhTheme : undefined
  const [state, setState] = useState(() => ({
    choice: (api?.get() ?? 'system') as ThemeChoice,
    resolved: (api?.resolved() ?? 'light') as ResolvedTheme,
  }))
  useEffect(() => api?.subscribe((choice, resolved) => setState({ choice, resolved })), [api])
  const set = (choice: ThemeChoice) => api?.set(choice)
  return { ...state, set }
}
