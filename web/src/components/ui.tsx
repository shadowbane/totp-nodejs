import { useEffect, useState, type ReactNode } from 'react'

export const REPO_URL = 'https://github.com/shadowbane/totp-nodejs'
export const DEVHELPER_URL = 'https://devhelper.my.id'
export const CONTACT_EMAIL = 'hello@devhelper.my.id'

/* ── Icons ─────────────────────────────────────────────────────────── */

function Svg({ children, size = 16 }: { children: ReactNode; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {children}
    </svg>
  )
}
export const CopyIcon = () => <Svg size={15}><rect x="8" y="8" width="12" height="12" rx="2" /><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" /></Svg>
export const CheckIcon = ({ size = 15 }: { size?: number }) => <Svg size={size}><path d="m5 12 4.5 4.5L19 7" /></Svg>
export const EyeIcon = () => <Svg size={15}><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z" /><circle cx="12" cy="12" r="3" /></Svg>
export const EyeOffIcon = () => <Svg size={15}><path d="M3 3l18 18M10.6 5.1A10.7 10.7 0 0 1 12 5c6.5 0 10 7 10 7a17.6 17.6 0 0 1-3.2 4.2M6.6 6.6A17.4 17.4 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.4-1.6" /><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" /></Svg>
export const LockIcon = () => <Svg size={15}><rect x="4" y="11" width="16" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></Svg>
export const TrashIcon = () => <Svg size={15}><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3" /></Svg>
export const DownloadIcon = () => <Svg size={15}><path d="M12 4v11M7 10l5 5 5-5M5 20h14" /></Svg>
export const UploadIcon = () => <Svg size={15}><path d="M12 20V9M7 14l5-5 5 5M5 4h14" /></Svg>
export const ArrowUpRightIcon = () => <Svg size={14}><path d="M7 17 17 7M8 7h9v9" /></Svg>
export const GitHubIcon = ({ size = 15 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <path d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.89 1.53 2.34 1.09 2.91.83.09-.65.35-1.09.63-1.34-2.22-.25-4.56-1.11-4.56-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.02a9.56 9.56 0 0 1 5 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.38.2 2.4.1 2.65.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.69-4.57 4.93.36.31.68.92.68 1.85v2.74c0 .27.18.58.69.48A10 10 0 0 0 12 2Z" />
  </svg>
)

/* ── Marks ─────────────────────────────────────────────────────────── */

/** Tick mark: a countdown ring three-quarters full, violet centre. */
export function TickMark({ size = 28 }: { size?: number }) {
  return (
    <span className="grid shrink-0 place-items-center rounded-lg bg-[var(--btn-bg)]" style={{ width: size, height: size }} aria-hidden="true">
      <svg viewBox="0 0 32 32" width={size * 0.78} height={size * 0.78}>
        <circle cx="16" cy="16" r="8.5" fill="none" stroke="var(--btn-fg)" strokeOpacity="0.28" strokeWidth="2.8" />
        <path d="M16 7.5a8.5 8.5 0 1 1-8.5 8.5" fill="none" stroke="var(--btn-fg)" strokeWidth="2.8" strokeLinecap="round" />
        <circle cx="16" cy="16" r="2.8" fill="var(--brand)" />
      </svg>
    </span>
  )
}

/* ── Theme ─────────────────────────────────────────────────────────── */

// Light / dark / system (src/devhelper-theme). Tick keeps its own choice: data-scope="local".
export { ThemeToggle } from '../devhelper-theme/ThemeToggle'

/* ── Small pieces ──────────────────────────────────────────────────── */

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

/** Copy button that confirms for 1.5 s. */
export function CopyButton({ text, label = 'Copy', className = 'btn btn-secondary btn-sm', disabled }: {
  text: string; label?: string; className?: string; disabled?: boolean
}) {
  const [state, setState] = useState<'idle' | 'done' | 'fail'>('idle')
  useEffect(() => {
    if (state === 'idle') return
    const t = setTimeout(() => setState('idle'), 1500)
    return () => clearTimeout(t)
  }, [state])
  return (
    <button type="button" disabled={disabled} className={className} onClick={async () => setState((await copyText(text)) ? 'done' : 'fail')}>
      {state === 'done' ? <CheckIcon /> : <CopyIcon />}
      <span aria-live="polite">{state === 'done' ? 'Copied' : state === 'fail' ? 'Copy failed' : label}</span>
    </button>
  )
}

/** Countdown ring. `left` and `period` in seconds. */
export function Ring({ left, period, size = 44 }: { left: number; period: number; size?: number }) {
  const r = 18
  const c = 2 * Math.PI * r
  const frac = Math.max(0, Math.min(1, left / period))
  const low = left <= 5
  return (
    <span className="relative grid shrink-0 place-items-center" style={{ width: size, height: size }}>
      <svg viewBox="0 0 44 44" width={size} height={size} className="-rotate-90" aria-hidden="true">
        <circle cx="22" cy="22" r={r} fill="none" stroke="var(--rule-2)" strokeWidth="3" />
        <circle cx="22" cy="22" r={r} fill="none" stroke={low ? 'var(--warn)' : 'var(--brand)'} strokeWidth="3" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * (1 - frac)} className="transition-[stroke-dashoffset] duration-1000 ease-linear" />
      </svg>
      <span className={`absolute font-mono text-[12px] tabular-nums ${low ? 'text-warn' : 'text-ink-2'}`}>{Math.ceil(left)}</span>
    </span>
  )
}

/** Segmented control for a few fixed options. */
export function Segmented<T extends string | number>({ label, value, options, onChange }: {
  label: string; value: T; options: readonly T[]; onChange: (v: T) => void
}) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded-lg border border-rule-2 bg-surface p-0.5">
      {options.map(o => (
        <button
          key={String(o)}
          type="button"
          role="radio"
          aria-checked={o === value}
          onClick={() => onChange(o)}
          className={`h-8 rounded-md px-3 font-mono text-[12px] transition-colors duration-150 ${o === value ? 'bg-frame text-ink shadow-[0_1px_2px_oklch(0_0_0/0.12)]' : 'text-ink-3 hover:text-ink'}`}
        >
          {o}
        </button>
      ))}
    </div>
  )
}

/** A numbered section under a full-width ink rule (Lens marketing style). */
export function Section({ id, n, label, title, lead, aside, children }: {
  id?: string; n: string; label: string; title: ReactNode; lead?: ReactNode; aside?: ReactNode; children: ReactNode
}) {
  return (
    <section id={id} className="mt-20 scroll-mt-24 border-t border-rule-ink pt-4 sm:mt-24">
      <div className="grid gap-x-8 gap-y-3 md:grid-cols-[200px_1fr]">
        <p className="eyebrow"><span className="text-brand-ink">{n}</span> &nbsp;{label}</p>
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h2 className="max-w-[640px] font-display text-[32px] leading-[1.08] tracking-[-0.015em] sm:text-[40px]">{title}</h2>
            {lead && <p className="mt-3 max-w-[560px] text-[15px] leading-relaxed text-ink-2">{lead}</p>}
          </div>
          {aside}
        </div>
      </div>
      <div className="mt-10">{children}</div>
    </section>
  )
}

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`rounded-2xl border border-rule bg-frame p-5 shadow-frame sm:p-6 ${className}`}>{children}</div>
}
