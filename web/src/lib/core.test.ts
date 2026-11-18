import { describe, expect, it } from 'vitest'
import { checkSecret, decodeBase32, encodeBase32, groupSecret, normalizeSecret } from './base32'
import { groupCode, hotp, totp, type Algorithm } from './totp'
import { buildOtpauth, parseOtpauth } from './otpauth'
import { createVault, seal, unlock, WrongPassphraseError, mergeEntries, type SavedEntry } from './vault'
import { clearLegacy, hasLegacy, readLegacy } from './legacy'

const ascii = (s: string) => new TextEncoder().encode(s)

// RFC 6238 Appendix B. Each algorithm has its own seed length.
const SEEDS: Record<Algorithm, Uint8Array> = {
  'SHA-1': ascii('12345678901234567890'),
  'SHA-256': ascii('12345678901234567890123456789012'),
  'SHA-512': ascii('1234567890123456789012345678901234567890123456789012345678901234'),
}
const VECTORS: [number, string, string, string][] = [
  [59, '94287082', '46119246', '90693936'],
  [1111111109, '07081804', '68084774', '25091201'],
  [1111111111, '14050471', '67062674', '99943326'],
  [1234567890, '89005924', '91819424', '93441116'],
  [2000000000, '69279037', '90698825', '38618901'],
  [20000000000, '65353130', '77737706', '47863826'],
]

describe('RFC 6238 test vectors', () => {
  for (const [t, s1, s256, s512] of VECTORS) {
    it(`T=${t}`, async () => {
      const at = t * 1000
      expect(await totp(SEEDS['SHA-1'], { algorithm: 'SHA-1', digits: 8, period: 30 }, at)).toBe(s1)
      expect(await totp(SEEDS['SHA-256'], { algorithm: 'SHA-256', digits: 8, period: 30 }, at)).toBe(s256)
      expect(await totp(SEEDS['SHA-512'], { algorithm: 'SHA-512', digits: 8, period: 30 }, at)).toBe(s512)
    })
  }
})

describe('RFC 4226 HOTP vectors', () => {
  const codes = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489']
  codes.forEach((code, counter) => {
    it(`counter ${counter}`, async () => {
      expect(await hotp(SEEDS['SHA-1'], counter, 'SHA-1', 6)).toBe(code)
    })
  })
  it('rejects an empty key', async () => {
    await expect(hotp(new Uint8Array(), 0, 'SHA-1', 6)).rejects.toThrow()
  })
})

describe('base32', () => {
  it('round-trips', () => {
    const bytes = ascii('12345678901234567890')
    expect(encodeBase32(bytes)).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
    expect(decodeBase32('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')).toEqual(bytes)
  })
  it('normalizes pasted secrets', () => {
    expect(normalizeSecret(' gezd gnbv-gy3t\nqojq== ')).toBe('GEZDGNBVGY3TQOJQ')
  })
  it('decodes lengths that are not a multiple of 8', () => {
    expect(decodeBase32('MZXW6')).toEqual(ascii('foo'))
    expect(decodeBase32('MZXW6YQ')).toEqual(ascii('foob'))
  })
  it('handles a long, spaced secret (64+ chars)', async () => {
    const long = encodeBase32(SEEDS['SHA-512']) // 103 chars
    expect(long.length).toBeGreaterThan(64)
    const spaced = groupSecret(long).toLowerCase()
    const check = checkSecret(spaced)
    expect(check.ok).toBe(true)
    if (!check.ok) return
    expect(check.bytes).toEqual(SEEDS['SHA-512'])
    expect(await totp(check.bytes, { algorithm: 'SHA-512', digits: 8, period: 30 }, 59_000)).toBe('90693936')
  })
  it('explains bad characters', () => {
    const check = checkSecret('ABC0EFGH')
    expect(check.ok).toBe(false)
    if (check.ok) return
    expect(check.error).toContain('letter O')
  })
  it('rejects empty input', () => {
    expect(checkSecret('  - = ').ok).toBe(false)
    expect(checkSecret('A').ok).toBe(false)
  })
})

describe('code grouping', () => {
  it('groups 6, 7 and 8 digits', () => {
    expect(groupCode('123456')).toBe('123 456')
    expect(groupCode('1234567')).toBe('123 4567')
    expect(groupCode('12345678')).toBe('1234 5678')
  })
})

describe('otpauth', () => {
  it('parses a full URI', () => {
    const a = parseOtpauth('otpauth://totp/ACME%20Co:jane%40example.com?secret=gezd%20gnbv&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60')
    expect(a).toEqual({ secret: 'GEZDGNBV', issuer: 'ACME Co', account: 'jane@example.com', algorithm: 'SHA-256', digits: 8, period: 60 })
  })
  it('defaults missing params to SHA-1, 6 digits, 30s', () => {
    const a = parseOtpauth('otpauth://totp/jane?secret=GEZDGNBV')
    expect(a).toMatchObject({ issuer: '', account: 'jane', algorithm: 'SHA-1', digits: 6, period: 30 })
  })
  it('clamps digits to 6-8', () => {
    expect(parseOtpauth('otpauth://totp/x?secret=GEZDGNBV&digits=10')?.digits).toBe(8)
  })
  it('rejects non-TOTP text', () => {
    expect(parseOtpauth('GEZDGNBV')).toBeNull()
    expect(parseOtpauth('otpauth://hotp/x?secret=GEZDGNBV&counter=1')).toBeNull()
    expect(parseOtpauth('otpauth://totp/x')).toBeNull()
  })
  it('round-trips through build and parse', () => {
    const a = { secret: 'GEZDGNBVGY3TQOJQ', issuer: 'Meta', account: 'jane doe', algorithm: 'SHA-1' as const, digits: 6, period: 30 }
    expect(parseOtpauth(buildOtpauth(a))).toEqual(a)
  })
})

const entry = (secret: string): SavedEntry => ({
  id: secret, name: secret, secret, issuer: '', account: '', algorithm: 'SHA-1', digits: 6, period: 30, createdAt: '2026-11-18T00:00:00Z',
})

describe('vault', () => {
  it('seals and unlocks', async () => {
    const vault = await createVault('correct horse battery', 100_000)
    const blob = await seal(vault, [entry('GEZDGNBV')])
    expect(blob.data).not.toContain('GEZDGNBV')
    const { entries } = await unlock(blob, 'correct horse battery')
    expect(entries).toEqual([entry('GEZDGNBV')])
  })
  it('uses a fresh IV on every write', async () => {
    const vault = await createVault('correct horse battery', 100_000)
    const a = await seal(vault, [])
    const b = await seal(vault, [])
    expect(a.cipher.iv).not.toBe(b.cipher.iv)
  })
  it('rejects a wrong passphrase', async () => {
    const vault = await createVault('correct horse battery', 100_000)
    const blob = await seal(vault, [])
    await expect(unlock(blob, 'wrong passphrase!!')).rejects.toBeInstanceOf(WrongPassphraseError)
  })
  it('skips duplicate secrets on merge', () => {
    const { merged, added } = mergeEntries([entry('AAAA')], [entry('AAAA'), entry('BBBB')])
    expect(added).toBe(1)
    expect(merged.map(e => e.secret)).toEqual(['AAAA', 'BBBB'])
  })
})

class MemoryStorage implements Storage {
  private m = new Map<string, string>()
  get length() { return this.m.size }
  clear() { this.m.clear() }
  getItem(k: string) { return this.m.has(k) ? this.m.get(k)! : null }
  key(i: number) { return [...this.m.keys()][i] ?? null }
  removeItem(k: string) { this.m.delete(k) }
  setItem(k: string, v: string) { this.m.set(k, String(v)) }
}

describe('legacy migration', () => {
  it('keeps each entry\'s own algorithm, digits and period', () => {
    const s = new MemoryStorage()
    s.setItem('totp_saved_configs', JSON.stringify([
      { id: '1', name: 'Work', secret: 'gezd gnbv', algorithm: 'SHA-256', timestep: '60', digits: '8', issuer: 'ACME', account: 'jane' },
    ]))
    s.setItem('totp_secret', 'MZXW6YQ')
    s.setItem('totp_algorithm', 'SHA-512')
    const out = readLegacy(s)
    expect(out).toHaveLength(2)
    expect(out[0]).toMatchObject({ name: 'Work', secret: 'GEZDGNBV', algorithm: 'SHA-256', digits: 8, period: 60, issuer: 'ACME', account: 'jane' })
    expect(out[1]).toMatchObject({ secret: 'MZXW6YQ', algorithm: 'SHA-512', digits: 6, period: 30 })
  })
  it('keeps a legacy digit count outside 6-8 instead of clamping it', () => {
    const s = new MemoryStorage()
    s.setItem('totp_secret', 'MZXW6YQ')
    s.setItem('totp_digits', '10')
    expect(readLegacy(s)[0].digits).toBe(10)
  })
  it('treats a missing algorithm as the old SHA-256 default', () => {
    const s = new MemoryStorage()
    s.setItem('totp_secret', 'MZXW6YQ')
    expect(readLegacy(s)[0].algorithm).toBe('SHA-256')
  })
  it('ignores the old sample secret and placeholder labels', () => {
    const s = new MemoryStorage()
    s.setItem('totp_secret', 'JBSWY3DPEHPK3PXP')
    s.setItem('totp_issuer', 'MyApp')
    expect(readLegacy(s)).toHaveLength(0)
  })
  it('clears every legacy key', () => {
    const s = new MemoryStorage()
    s.setItem('totp_saved_configs', '[]')
    s.setItem('totp_secret', 'X')
    s.setItem('totp_account', 'Y')
    s.setItem('tick_vault', 'keep')
    expect(hasLegacy(s)).toBe(true)
    clearLegacy(s)
    expect(hasLegacy(s)).toBe(false)
    expect(s.getItem('tick_vault')).toBe('keep')
  })
})
