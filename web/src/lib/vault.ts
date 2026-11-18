import type { Algorithm } from './totp'

/**
 * The vault: saved accounts, encrypted with a key made from the user's
 * passphrase. The key never leaves memory; only the encrypted blob is stored.
 *
 *   passphrase --PBKDF2-SHA256 (600k, random salt)--> AES-256-GCM key
 *   entries JSON --AES-GCM (fresh 12-byte IV per write)--> blob.data
 */

export interface SavedEntry {
  id: string
  name: string
  secret: string
  issuer: string
  account: string
  algorithm: Algorithm
  digits: number
  period: number
  createdAt: string
}

export interface VaultBlob {
  app: 'tick'
  v: 1
  kdf: { name: 'PBKDF2'; hash: 'SHA-256'; iterations: number; salt: string }
  cipher: { name: 'AES-GCM'; iv: string }
  data: string
}

export interface OpenVault {
  key: CryptoKey
  kdf: VaultBlob['kdf']
}

export const VAULT_KEY = 'tick_vault'
export const ITERATIONS = 600_000
export const MIN_PASSPHRASE = 12

export class WrongPassphraseError extends Error {
  constructor() {
    super('That passphrase does not open this vault.')
  }
}

export class BadBackupError extends Error {
  constructor(msg = 'This file is not a Tick backup.') {
    super(msg)
  }
}

const enc = new TextEncoder()
const dec = new TextDecoder()

function toB64(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

function fromB64(b64: string): Uint8Array {
  const s = atob(b64)
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}

async function deriveKey(passphrase: string, kdf: VaultBlob['kdf']): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: kdf.hash, iterations: kdf.iterations, salt: fromB64(kdf.salt) as BufferSource },
    base,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable
    ['encrypt', 'decrypt'],
  )
}

/** Encrypts entries with an open vault's key. Every call uses a fresh IV. */
export async function seal(vault: OpenVault, entries: SavedEntry[]): Promise<VaultBlob> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const data = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, vault.key, enc.encode(JSON.stringify(entries))),
  )
  return { app: 'tick', v: 1, kdf: vault.kdf, cipher: { name: 'AES-GCM', iv: toB64(iv) }, data: toB64(data) }
}

/** Makes a new vault with a random salt. */
export async function createVault(passphrase: string, iterations = ITERATIONS): Promise<OpenVault> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const kdf: VaultBlob['kdf'] = { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: toB64(salt) }
  return { key: await deriveKey(passphrase, kdf), kdf }
}

export function isVaultBlob(x: unknown): x is VaultBlob {
  const b = x as VaultBlob
  return (
    !!b && b.app === 'tick' && b.v === 1 &&
    b.kdf?.name === 'PBKDF2' && b.kdf.hash === 'SHA-256' &&
    Number.isInteger(b.kdf.iterations) && b.kdf.iterations >= 100_000 &&
    typeof b.kdf.salt === 'string' &&
    b.cipher?.name === 'AES-GCM' && typeof b.cipher.iv === 'string' &&
    typeof b.data === 'string'
  )
}

/** Opens a blob with a passphrase. Throws WrongPassphraseError on a bad passphrase. */
export async function unlock(blob: VaultBlob, passphrase: string): Promise<{ vault: OpenVault; entries: SavedEntry[] }> {
  if (!isVaultBlob(blob)) throw new BadBackupError()
  const key = await deriveKey(passphrase, blob.kdf)
  let plain: ArrayBuffer
  try {
    plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(blob.cipher.iv) as BufferSource }, key, fromB64(blob.data) as BufferSource)
  } catch {
    throw new WrongPassphraseError()
  }
  let entries: unknown
  try {
    entries = JSON.parse(dec.decode(plain))
  } catch {
    throw new BadBackupError('This backup is damaged.')
  }
  if (!Array.isArray(entries)) throw new BadBackupError('This backup is damaged.')
  return { vault: { key, kdf: blob.kdf }, entries }
}

export function loadBlob(storage: Storage): VaultBlob | null {
  try {
    const raw = storage.getItem(VAULT_KEY)
    if (!raw) return null
    const blob = JSON.parse(raw)
    return isVaultBlob(blob) ? blob : null
  } catch {
    return null
  }
}

export function saveBlob(storage: Storage, blob: VaultBlob): void {
  storage.setItem(VAULT_KEY, JSON.stringify(blob))
}

/** Same account if the secret matches; used to skip duplicates on import. */
export function mergeEntries(current: SavedEntry[], incoming: SavedEntry[]): { merged: SavedEntry[]; added: number } {
  const seen = new Set(current.map(e => e.secret))
  const fresh = incoming.filter(e => e && typeof e.secret === 'string' && !seen.has(e.secret))
  return { merged: [...current, ...fresh], added: fresh.length }
}

export function newId(): string {
  return crypto.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`
}
