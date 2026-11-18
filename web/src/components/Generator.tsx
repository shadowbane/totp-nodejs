import { useEffect, useMemo, useState } from 'react'
import { checkSecret } from '../lib/base32'
import { useTotp } from '../lib/hooks'
import { buildOtpauth, parseOtpauth, type Account } from '../lib/otpauth'
import { ALGORITHMS, DIGIT_OPTIONS, clampPeriod, groupCode, type TotpParams } from '../lib/totp'
import { Qr } from './Qr'
import { Card, CheckIcon, CopyButton, EyeIcon, EyeOffIcon, Ring, Segmented } from './ui'

export function Generator({ value, onChange, now }: {
  value: Account; onChange: (a: Account) => void; now: number
}) {
  const [masked, setMasked] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const [periodText, setPeriodText] = useState(String(value.period))
  const [showQr, setShowQr] = useState(false)

  useEffect(() => { setPeriodText(String(value.period)) }, [value.period])
  useEffect(() => {
    if (!notice) return
    const t = setTimeout(() => setNotice(null), 4000)
    return () => clearTimeout(t)
  }, [notice])

  const check = useMemo(() => checkSecret(value.secret), [value.secret])
  const key = check.ok ? check.bytes : null
  const params: TotpParams = { algorithm: value.algorithm, digits: value.digits, period: value.period }
  const live = useTotp(key, params, now)
  const set = (patch: Partial<Account>) => onChange({ ...value, ...patch })

  const onSecretInput = (text: string) => {
    const parsed = parseOtpauth(text)
    if (parsed) {
      onChange(parsed)
      setNotice('Filled in from the otpauth link.')
    } else {
      set({ secret: text })
    }
  }

  const empty = value.secret.trim() === ''
  const rows = Math.min(6, Math.max(2, Math.ceil(value.secret.length / 34)))
  const uri = check.ok ? buildOtpauth({ ...value, secret: check.secret }) : ''

  return (
    <div className="grid gap-5 lg:grid-cols-[1.15fr_1fr]">
      {/* ── Input ─────────────────────────────────────────── */}
      <Card>
        <div className="flex items-center justify-between gap-3">
          <label htmlFor="secret" className="field-label !mb-0">Secret key</label>
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => setMasked(m => !m)} aria-pressed={masked}>
            {masked ? <EyeIcon /> : <EyeOffIcon />} {masked ? 'Show' : 'Hide'}
          </button>
        </div>
        <textarea
          id="secret"
          value={value.secret}
          onChange={e => onSecretInput(e.target.value)}
          rows={rows}
          spellCheck={false}
          autoCapitalize="characters"
          autoComplete="off"
          autoCorrect="off"
          placeholder="JBSW Y3DP EHPK 3PXP …  or an otpauth:// link"
          aria-invalid={!empty && !check.ok}
          aria-describedby="secret-status"
          className={`input secret-field mt-2 resize-none font-mono text-[14px] leading-relaxed ${masked ? 'secret-masked' : ''}`}
        />
        <p id="secret-status" className="mt-2 min-h-[20px] text-[13px]" aria-live="polite">
          {notice ? (
            <span className="inline-flex items-center gap-1.5 text-positive"><CheckIcon size={14} /> {notice}</span>
          ) : empty ? (
            <span className="text-ink-3">Paste the key from the site's 2FA setup, or its otpauth:// link. Spaces and lowercase are fine, and long keys work.</span>
          ) : check.ok ? (
            <span className="inline-flex items-center gap-1.5 text-positive">
              <CheckIcon size={14} /> Valid key · {check.secret.length} characters · {check.bytes.length * 8}-bit
            </span>
          ) : (
            <span className="text-negative">{check.error}</span>
          )}
        </p>

        <div className="mt-6 grid gap-5 sm:grid-cols-2">
          <div>
            <p className="field-label">Algorithm</p>
            <Segmented label="Algorithm" value={value.algorithm} options={ALGORITHMS} onChange={algorithm => set({ algorithm })} />
            <p className="mt-1.5 text-[12px] text-ink-3">Most sites use SHA-1. Change it only if the site says so.</p>
          </div>
          <div className="flex gap-5">
            <div>
              <p className="field-label">Digits</p>
              <Segmented label="Digits" value={value.digits} options={DIGIT_OPTIONS} onChange={digits => set({ digits })} />
            </div>
            <div className="w-[92px]">
              <label htmlFor="period" className="field-label">Period</label>
              <div className="relative">
                <input
                  id="period"
                  inputMode="numeric"
                  value={periodText}
                  onChange={e => setPeriodText(e.target.value.replace(/\D/g, '').slice(0, 3))}
                  onBlur={() => { const p = clampPeriod(periodText); setPeriodText(String(p)); set({ period: p }) }}
                  className="input !h-9 pr-7 font-mono text-[13px]"
                />
                <span className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 font-mono text-[12px] text-ink-3">s</span>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-6 grid gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor="issuer" className="field-label">Issuer <span className="font-normal text-ink-3">(optional)</span></label>
            <input id="issuer" value={value.issuer} onChange={e => set({ issuer: e.target.value })} placeholder="e.g. Meta" className="input" autoComplete="off" />
          </div>
          <div>
            <label htmlFor="account" className="field-label">Account <span className="font-normal text-ink-3">(optional)</span></label>
            <input id="account" value={value.account} onChange={e => set({ account: e.target.value })} placeholder="e.g. jane@example.com" className="input" autoComplete="off" />
          </div>
        </div>
      </Card>

      {/* ── Output ────────────────────────────────────────── */}
      <Card className="flex flex-col">
        <div className="flex items-center justify-between">
          <p className="eyebrow">Current code</p>
          <p className="eyebrow">{value.algorithm} · {value.digits} digits · {value.period}s</p>
        </div>

        <div className="mt-5 flex items-center justify-between gap-4">
          <p className={`font-mono text-[44px] font-medium leading-none tracking-[0.04em] tabular-nums sm:text-[52px] ${live.code ? 'text-ink' : 'text-ink-3/50'}`} aria-live="off">
            {live.code ? groupCode(live.code) : groupCode('–'.repeat(value.digits))}
          </p>
          {live.code && <Ring left={live.left} period={value.period} />}
        </div>
        <div className="mt-3 flex min-h-[20px] items-center justify-between gap-3 font-mono text-[12px] text-ink-3">
          {live.next ? <span>Next <span className="text-ink-2">{groupCode(live.next)}</span></span> : <span>Enter a valid key to see codes</span>}
        </div>

        <div className="mt-5 flex flex-wrap gap-2.5">
          <CopyButton text={live.code ?? ''} label="Copy code" className="btn btn-primary" disabled={!live.code} />
        </div>

        <div className="mt-auto pt-7">
          <div className="rounded-xl border border-rule bg-surface">
            <button
              type="button"
              onClick={() => setShowQr(s => !s)}
              aria-expanded={showQr}
              disabled={!check.ok}
              className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left text-[14px] font-medium disabled:cursor-not-allowed disabled:text-ink-3"
            >
              Add to an authenticator app
              <span className="font-mono text-[12px] text-ink-3">{showQr ? 'Hide QR' : 'Show QR'}</span>
            </button>
            {showQr && check.ok && (
              <div className="border-t border-rule px-4 pb-4 pt-4">
                <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
                  <Qr text={uri} size={176} />
                  <div className="min-w-0 flex-1 text-[13px] text-ink-2">
                    <p>Scan with Google Authenticator, Microsoft Authenticator, 1Password or any TOTP app.</p>
                    <p className="mt-2 text-ink-3">Anyone who sees this code can make your codes. Hide it when you're done.</p>
                    <div className="mt-3"><CopyButton text={uri} label="Copy otpauth link" /></div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </Card>
    </div>
  )
}
