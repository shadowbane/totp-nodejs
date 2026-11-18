const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/** Digits people type when the secret shows a similar-looking letter. */
const LOOKALIKES: Record<string, string> = { '0': 'O', '1': 'I', '8': 'B' }

/**
 * Cleans a secret the way people paste it: drops whitespace, dashes and
 * padding, and uppercases. "abcd efgh-ijkl====" becomes "ABCDEFGHIJKL".
 */
export function normalizeSecret(input: string): string {
  return input.replace(/[\s\-=]/g, '').toUpperCase()
}

export type SecretCheck =
  | { ok: true; secret: string; bytes: Uint8Array }
  | { ok: false; secret: string; error: string }

/** Normalizes and decodes a secret, with an error people can act on. */
export function checkSecret(input: string): SecretCheck {
  const secret = normalizeSecret(input)
  if (!secret) return { ok: false, secret, error: 'Enter a secret key.' }
  const bad = [...secret].find(c => !ALPHABET.includes(c))
  if (bad) {
    const hint = LOOKALIKES[bad] ? ` Did you mean the letter ${LOOKALIKES[bad]}?` : ''
    return { ok: false, secret, error: `"${bad}" is not allowed in a secret. Use A to Z and 2 to 7.${hint}` }
  }
  const bytes = decodeBase32(secret)
  if (bytes.length === 0) return { ok: false, secret, error: 'This secret is too short to use.' }
  return { ok: true, secret, bytes }
}

/**
 * RFC 4648 base32 decode. Lenient: any length works, padding is optional,
 * and trailing bits that do not fill a byte are dropped.
 * Expects a normalized secret; throws on characters outside the alphabet.
 */
export function decodeBase32(secret: string): Uint8Array {
  const out: number[] = []
  let buffer = 0
  let bits = 0
  for (const c of secret) {
    const v = ALPHABET.indexOf(c)
    if (v < 0) throw new Error(`Invalid base32 character: ${c}`)
    buffer = (buffer << 5) | v
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((buffer >>> bits) & 0xff)
    }
    buffer &= (1 << bits) - 1
  }
  return new Uint8Array(out)
}

export function encodeBase32(bytes: Uint8Array): string {
  let out = ''
  let buffer = 0
  let bits = 0
  for (const b of bytes) {
    buffer = (buffer << 8) | b
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += ALPHABET[(buffer >>> bits) & 31]
    }
    buffer &= (1 << bits) - 1
  }
  if (bits > 0) out += ALPHABET[(buffer << (5 - bits)) & 31]
  return out
}

/** Groups a secret in blocks of 4 for reading: "ABCD EFGH IJKL". */
export function groupSecret(secret: string): string {
  return secret.replace(/(.{4})(?=.)/g, '$1 ')
}
