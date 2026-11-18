import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { clearLegacy, hasLegacy, readLegacy } from './legacy'
import {
  BadBackupError, createVault, isVaultBlob, loadBlob, mergeEntries, saveBlob, seal, unlock, VAULT_KEY,
  type OpenVault, type SavedEntry, type VaultBlob,
} from './vault'

export const IDLE_LOCK_MS = 5 * 60 * 1000

function getStorage(): Storage | null {
  try {
    const s = window.localStorage
    const probe = '__tick_probe__'
    s.setItem(probe, '1')
    s.removeItem(probe)
    return s
  } catch {
    return null
  }
}

export type VaultStatus = 'unavailable' | 'none' | 'locked' | 'open'

/**
 * Vault state. The derived key and the decrypted entries live only in this
 * hook's memory; localStorage only ever holds the encrypted blob.
 */
export function useVault() {
  const storage = useMemo(getStorage, [])
  const [blob, setBlob] = useState<VaultBlob | null>(() => (storage ? loadBlob(storage) : null))
  const [vault, setVault] = useState<OpenVault | null>(null)
  const [entries, setEntries] = useState<SavedEntry[]>([])
  const [legacy, setLegacy] = useState<SavedEntry[]>(() => (storage ? readLegacy(storage) : []))
  const [legacyPresent, setLegacyPresent] = useState(() => (storage ? hasLegacy(storage) : false))
  const [message, setMessage] = useState<string | null>(null)

  const status: VaultStatus = !storage ? 'unavailable' : vault ? 'open' : blob ? 'locked' : 'none'

  const persist = useCallback(async (v: OpenVault, next: SavedEntry[]) => {
    if (!storage) return
    const b = await seal(v, next)
    saveBlob(storage, b)
    setBlob(b)
    setEntries(next)
  }, [storage])

  /** Moves the old page's plaintext keys into an open vault, then deletes them. */
  const absorbLegacy = useCallback(async (v: OpenVault, current: SavedEntry[]) => {
    if (!storage || !hasLegacy(storage)) return current
    const { merged, added } = mergeEntries(current, readLegacy(storage))
    if (added > 0) await persist(v, merged)
    clearLegacy(storage)
    setLegacy([])
    setLegacyPresent(false)
    if (added > 0) setMessage(`Moved ${added} key${added === 1 ? '' : 's'} from the old TOTP page into your vault and deleted the unencrypted copies.`)
    return merged
  }, [storage, persist])

  const lock = useCallback(() => {
    setVault(null)
    setEntries([])
  }, [])

  const create = useCallback(async (passphrase: string) => {
    const v = await createVault(passphrase)
    await persist(v, [])
    setVault(v)
    await absorbLegacy(v, [])
  }, [persist, absorbLegacy])

  const open = useCallback(async (passphrase: string) => {
    if (!blob) return
    const { vault: v, entries: list } = await unlock(blob, passphrase)
    setVault(v)
    setEntries(list)
    await absorbLegacy(v, list)
  }, [blob, absorbLegacy])

  const add = useCallback(async (entry: SavedEntry) => {
    if (vault) await persist(vault, [...entries, entry])
  }, [vault, entries, persist])

  const remove = useCallback(async (id: string) => {
    if (vault) await persist(vault, entries.filter(e => e.id !== id))
  }, [vault, entries, persist])

  /** Deletes the vault for good (forgotten passphrase). */
  const reset = useCallback(() => {
    storage?.removeItem(VAULT_KEY)
    setBlob(null)
    lock()
  }, [storage, lock])

  const discardLegacy = useCallback(() => {
    if (!storage) return
    clearLegacy(storage)
    setLegacy([])
    setLegacyPresent(false)
  }, [storage])

  /** An encrypted backup file: the same blob, freshly sealed. */
  const exportBackup = useCallback(async () => {
    if (!vault) return
    const b = await seal(vault, entries)
    const file = new Blob([JSON.stringify(b, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(file)
    a.download = `tick-backup-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    setTimeout(() => URL.revokeObjectURL(a.href), 1000)
  }, [vault, entries])

  /** Reads a backup file. Merges into an open vault, or becomes the vault if there is none. */
  const importBackup = useCallback(async (text: string, passphrase: string) => {
    let parsed: unknown
    try {
      parsed = JSON.parse(text)
    } catch {
      throw new BadBackupError()
    }
    if (!isVaultBlob(parsed)) throw new BadBackupError()
    const { vault: bv, entries: incoming } = await unlock(parsed, passphrase)
    if (vault) {
      const { merged, added } = mergeEntries(entries, incoming)
      await persist(vault, merged)
      setMessage(added ? `Added ${added} key${added === 1 ? '' : 's'} from the backup.` : 'Every key in that backup is already saved.')
    } else {
      // No vault yet: the backup becomes the vault, with the backup's passphrase.
      await persist(bv, incoming)
      setVault(bv)
      setMessage(`Restored ${incoming.length} key${incoming.length === 1 ? '' : 's'} from the backup.`)
      await absorbLegacy(bv, incoming)
    }
  }, [vault, entries, persist, absorbLegacy])

  // Lock after 5 minutes without input.
  const lastActive = useRef(Date.now())
  useEffect(() => {
    if (!vault) return
    const bump = () => { lastActive.current = Date.now() }
    bump()
    const events = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const
    events.forEach(e => window.addEventListener(e, bump, { passive: true }))
    const t = setInterval(() => {
      if (Date.now() - lastActive.current > IDLE_LOCK_MS) {
        lock()
        setMessage('Locked after 5 minutes without activity.')
      }
    }, 5000)
    return () => {
      events.forEach(e => window.removeEventListener(e, bump))
      clearInterval(t)
    }
  }, [vault, lock])

  // Another tab changed the vault: reload it and lock, so this tab never overwrites newer data.
  useEffect(() => {
    if (!storage) return
    const onStorage = (e: StorageEvent) => {
      if (e.key !== VAULT_KEY) return
      setBlob(loadBlob(storage))
      lock()
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [storage, lock])

  return {
    status, entries, legacyCount: legacy.length, legacyPresent, message, setMessage,
    create, open, lock, add, remove, reset, discardLegacy, exportBackup, importBackup,
  }
}

export type VaultApi = ReturnType<typeof useVault>
