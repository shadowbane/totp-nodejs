export type Algorithm = 'SHA-1' | 'SHA-256' | 'SHA-512'

export const ALGORITHMS: Algorithm[] = ['SHA-1', 'SHA-256', 'SHA-512']
export const DIGIT_OPTIONS = [6, 7, 8] as const

export interface TotpParams {
  algorithm: Algorithm
  digits: number
  period: number
}

export const DEFAULT_PARAMS: TotpParams = { algorithm: 'SHA-1', digits: 6, period: 30 }

export function clampDigits(n: unknown): number {
  const v = Math.round(Number(n))
  return Number.isFinite(v) ? Math.min(8, Math.max(6, v)) : 6
}

export function clampPeriod(n: unknown): number {
  const v = Math.round(Number(n))
  return Number.isFinite(v) && v > 0 ? Math.min(300, Math.max(5, v)) : 30
}

export function toAlgorithm(v: unknown): Algorithm {
  const s = String(v ?? '').toUpperCase().replace(/^SHA-?/, 'SHA-')
  return (ALGORITHMS as string[]).includes(s) ? (s as Algorithm) : 'SHA-1'
}

/**
 * HOTP (RFC 4226) for one counter value, via WebCrypto.
 * The key must not be empty; WebCrypto rejects a zero-length HMAC key.
 */
export async function hotp(key: Uint8Array, counter: number, algorithm: Algorithm, digits: number): Promise<string> {
  if (key.length === 0) throw new Error('Empty key')
  const msg = new Uint8Array(8)
  let c = counter
  for (let i = 7; i >= 0; i--) {
    msg[i] = c & 0xff
    c = Math.floor(c / 256)
  }
  const cryptoKey = await crypto.subtle.importKey('raw', key as BufferSource, { name: 'HMAC', hash: algorithm }, false, ['sign'])
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, msg))
  const offset = mac[mac.length - 1] & 0x0f
  const bin =
    ((mac[offset] & 0x7f) << 24) |
    (mac[offset + 1] << 16) |
    (mac[offset + 2] << 8) |
    mac[offset + 3]
  return String(bin % 10 ** digits).padStart(digits, '0')
}

/** TOTP (RFC 6238) at a given time in milliseconds. */
export function totp(key: Uint8Array, params: TotpParams, nowMs = Date.now()): Promise<string> {
  const counter = Math.floor(nowMs / 1000 / params.period)
  return hotp(key, counter, params.algorithm, params.digits)
}

/** Seconds left before the current code changes. */
export function secondsLeft(period: number, nowMs = Date.now()): number {
  const s = nowMs / 1000
  return period - (s % period)
}

/** "123456" -> "123 456", "12345678" -> "1234 5678", "1234567" -> "123 4567". */
export function groupCode(code: string): string {
  const mid = Math.floor(code.length / 2)
  return `${code.slice(0, mid)} ${code.slice(mid)}`
}
