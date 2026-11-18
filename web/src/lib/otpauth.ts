import { normalizeSecret } from './base32'
import { clampDigits, clampPeriod, toAlgorithm, type TotpParams } from './totp'

export interface Account extends TotpParams {
  secret: string
  issuer: string
  account: string
}

/**
 * Parses an otpauth://totp/ URI, as found behind most 2FA QR codes:
 * otpauth://totp/Issuer:account?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30
 * Returns null when the text is not a TOTP URI with a secret.
 */
export function parseOtpauth(text: string): Account | null {
  const raw = text.trim()
  if (!/^otpauth:\/\//i.test(raw)) return null
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return null
  }
  if (url.hostname.toLowerCase() !== 'totp') return null
  const q = url.searchParams
  const secret = normalizeSecret(q.get('secret') ?? '')
  if (!secret) return null

  let label = ''
  try {
    label = decodeURIComponent(url.pathname.replace(/^\//, ''))
  } catch {
    label = url.pathname.replace(/^\//, '')
  }
  let labelIssuer = ''
  let account = label
  const colon = label.indexOf(':')
  if (colon >= 0) {
    labelIssuer = label.slice(0, colon).trim()
    account = label.slice(colon + 1).trim()
  }

  return {
    secret,
    issuer: (q.get('issuer') ?? labelIssuer).trim(),
    account: account.trim(),
    algorithm: toAlgorithm(q.get('algorithm') ?? 'SHA1'),
    digits: clampDigits(q.get('digits') ?? 6),
    period: clampPeriod(q.get('period') ?? 30),
  }
}

/** Builds the otpauth:// URI for a QR code. Omits defaults most apps assume. */
export function buildOtpauth(a: Account): string {
  const issuer = a.issuer.trim()
  const account = a.account.trim() || 'account'
  const label = issuer ? `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}` : encodeURIComponent(account)
  const q = new URLSearchParams({ secret: normalizeSecret(a.secret) })
  if (issuer) q.set('issuer', issuer)
  q.set('algorithm', a.algorithm.replace('-', ''))
  q.set('digits', String(a.digits))
  q.set('period', String(a.period))
  return `otpauth://totp/${label}?${q.toString()}`
}
