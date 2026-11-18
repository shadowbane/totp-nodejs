import { checkSecret } from './base32'
import { clampPeriod, toAlgorithm } from './totp'
import { newId, type SavedEntry } from './vault'

/**
 * The old TOTP page (same origin) kept secrets in plaintext localStorage.
 * These helpers find them so Tick can move them into the encrypted vault,
 * keeping each entry's own algorithm, digits and period.
 */

const SAVED_KEY = 'totp_saved_configs'
const SINGLE_KEYS = ['totp_secret', 'totp_algorithm', 'totp_timestep', 'totp_digits', 'totp_issuer', 'totp_account']
/** The old page's built-in example secret; not a real account. */
const SAMPLE_SECRET = 'JBSWY3DPEHPK3PXP'

function legacyDigits(v: unknown): number {
  const n = Math.round(Number(v ?? 6))
  return Number.isFinite(n) && n >= 1 && n <= 10 ? n : 6
}

function entryFrom(o: Record<string, unknown>, fallbackName: string): SavedEntry | null {
  const check = checkSecret(String(o.secret ?? ''))
  if (!check.ok || check.secret === SAMPLE_SECRET) return null
  const issuer = String(o.issuer ?? '').trim()
  const account = String(o.account ?? '').trim()
  return {
    id: newId(),
    name: String(o.name ?? '').trim() || [issuer, account].filter(Boolean).join(' · ') || fallbackName,
    secret: check.secret,
    issuer: issuer === 'MyApp' ? '' : issuer,
    account: account === 'user@example.com' ? '' : account,
    // The old page defaulted to SHA-256, so a missing value means SHA-256 here.
    algorithm: toAlgorithm(o.algorithm ?? 'SHA-256'),
    // Keep the old digit count as is (the old page allowed any); clamping would give wrong codes.
    digits: legacyDigits(o.digits),
    period: clampPeriod(o.timestep ?? 30),
    createdAt: new Date().toISOString(),
  }
}

export function readLegacy(storage: Storage): SavedEntry[] {
  const out: SavedEntry[] = []
  try {
    const list = JSON.parse(storage.getItem(SAVED_KEY) ?? '[]')
    if (Array.isArray(list)) {
      for (const o of list) {
        const e = o && typeof o === 'object' ? entryFrom(o, 'Imported key') : null
        if (e) out.push(e)
      }
    }
  } catch {
    /* unreadable list: nothing to migrate */
  }
  try {
    const single = entryFrom(
      {
        secret: storage.getItem('totp_secret'),
        algorithm: storage.getItem('totp_algorithm') ?? undefined,
        timestep: storage.getItem('totp_timestep') ?? undefined,
        digits: storage.getItem('totp_digits') ?? undefined,
        issuer: storage.getItem('totp_issuer') ?? undefined,
        account: storage.getItem('totp_account') ?? undefined,
      },
      'Last used key',
    )
    if (single && !out.some(e => e.secret === single.secret)) out.push(single)
  } catch {
    /* storage blocked */
  }
  return out
}

export function hasLegacy(storage: Storage): boolean {
  try {
    return [SAVED_KEY, ...SINGLE_KEYS].some(k => storage.getItem(k) !== null)
  } catch {
    return false
  }
}

export function clearLegacy(storage: Storage): void {
  for (const k of [SAVED_KEY, ...SINGLE_KEYS]) {
    try {
      storage.removeItem(k)
    } catch {
      /* ignore */
    }
  }
}
