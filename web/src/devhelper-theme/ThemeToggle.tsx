// GENERATED from devhelper-fe/theme v1.0.1 - do not edit; change devhelper-fe/theme and run sync.mjs
import { useTheme, type ThemeChoice } from './useTheme'

const ICONS: Record<ThemeChoice, JSX.Element> = {
  light: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
      <circle cx="8" cy="8" r="3" />
      <path d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1.06 1.06M11.54 11.54l1.06 1.06M3.4 12.6l1.06-1.06M11.54 4.46l1.06-1.06" />
    </svg>
  ),
  dark: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" aria-hidden="true">
      <path d="M13.5 9.6A5.5 5.5 0 0 1 6.4 2.5a5.5 5.5 0 1 0 7.1 7.1Z" />
    </svg>
  ),
  system: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" aria-hidden="true">
      <rect x="2" y="3" width="12" height="8" rx="1.5" />
      <path d="M6 13.5h4" strokeLinecap="round" />
    </svg>
  ),
}

const LABELS: Record<ThemeChoice, string> = { light: 'Light', dark: 'Dark', system: 'System' }

/** Light / dark / system. The choice reaches every DevHelper site. */
export function ThemeToggle({ className = '' }: { className?: string }) {
  const { choice, set } = useTheme()
  return (
    <div className={`dh-theme ${className}`} role="group" aria-label="Theme">
      {(['light', 'dark', 'system'] as ThemeChoice[]).map(c => (
        <button
          key={c}
          type="button"
          className="dh-theme-opt"
          aria-pressed={choice === c}
          aria-label={`${LABELS[c]} theme`}
          title={`${LABELS[c]} theme`}
          onClick={() => set(c)}
        >
          {ICONS[c]}
        </button>
      ))}
    </div>
  )
}
