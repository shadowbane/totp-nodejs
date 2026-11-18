import { useMemo, useRef, useState, type FormEvent } from 'react'
import { checkSecret } from '../lib/base32'
import { useTotp } from '../lib/hooks'
import type { Account } from '../lib/otpauth'
import { groupCode } from '../lib/totp'
import type { VaultApi } from '../lib/useVault'
import { BadBackupError, MIN_PASSPHRASE, newId, WrongPassphraseError, type SavedEntry } from '../lib/vault'
import { Card, CopyButton, DownloadIcon, LockIcon, Ring, TrashIcon, UploadIcon } from './ui'

function errorText(e: unknown): string {
  if (e instanceof WrongPassphraseError || e instanceof BadBackupError) return e.message
  return 'Something went wrong. Nothing was changed.'
}

/* ── Passphrase forms ──────────────────────────────────────────────── */

function CreateForm({ onCreate }: { onCreate: (p: string) => Promise<void> }) {
  const [p1, setP1] = useState('')
  const [p2, setP2] = useState('')
  const [ack, setAck] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const tooShort = p1.length > 0 && p1.length < MIN_PASSPHRASE
  const mismatch = p2.length > 0 && p1 !== p2
  const ready = p1.length >= MIN_PASSPHRASE && p1 === p2 && ack && !busy

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!ready) return
    setBusy(true)
    setError(null)
    try {
      await onCreate(p1)
    } catch (err) {
      setError(errorText(err))
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="grid gap-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label htmlFor="p1" className="field-label">Passphrase</label>
          <input id="p1" type="password" autoComplete="new-password" value={p1} onChange={e => setP1(e.target.value)} className="input" aria-describedby="p1-hint" />
          <p id="p1-hint" className={`mt-1.5 text-[12px] ${tooShort ? 'text-negative' : 'text-ink-3'}`}>
            At least {MIN_PASSPHRASE} characters. Four random words work well.
          </p>
        </div>
        <div>
          <label htmlFor="p2" className="field-label">Type it again</label>
          <input id="p2" type="password" autoComplete="new-password" value={p2} onChange={e => setP2(e.target.value)} className="input" />
          {mismatch && <p className="field-error">The two passphrases don't match.</p>}
        </div>
      </div>
      <label className="flex items-start gap-2.5 text-[13px] text-ink-2">
        <input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} className="mt-0.5 h-4 w-4 accent-[var(--brand)]" />
        <span>I understand that nobody can recover a forgotten passphrase. If I lose it, the saved keys are gone.</span>
      </label>
      {error && <p className="alert-error">{error}</p>}
      <div>
        <button type="submit" disabled={!ready} className="btn btn-primary">
          <LockIcon /> {busy ? 'Creating…' : 'Create encrypted vault'}
        </button>
      </div>
    </form>
  )
}

function PassphraseForm({ id, label, action, busyLabel, onSubmit }: {
  id: string; label: string; action: string; busyLabel: string; onSubmit: (p: string) => Promise<void>
}) {
  const [p, setP] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!p || busy) return
    setBusy(true)
    setError(null)
    try {
      await onSubmit(p)
    } catch (err) {
      setError(errorText(err))
      setBusy(false)
    }
  }
  return (
    <form onSubmit={submit}>
      <label htmlFor={id} className="field-label">{label}</label>
      <div className="flex flex-wrap gap-2.5">
        <input id={id} type="password" autoComplete="current-password" value={p} onChange={e => setP(e.target.value)} className="input max-w-[340px] flex-1" autoFocus />
        <button type="submit" disabled={!p || busy} className="btn btn-primary !h-10">{busy ? busyLabel : action}</button>
      </div>
      {error && <p className="field-error">{error}</p>}
    </form>
  )
}

/* ── Backup import ─────────────────────────────────────────────────── */

function ImportBackup({ vault, compact }: { vault: VaultApi; compact?: boolean }) {
  const input = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<{ name: string; text: string } | null>(null)
  const [error, setError] = useState<string | null>(null)

  const pick = async (f: File | undefined) => {
    setError(null)
    if (!f) return
    if (f.size > 2_000_000) return setError('That file is too big to be a Tick backup.')
    setFile({ name: f.name, text: await f.text() })
  }

  return (
    <div>
      <input ref={input} type="file" accept="application/json,.json" className="hidden" onChange={e => { pick(e.target.files?.[0]); e.target.value = '' }} />
      {!file ? (
        <button type="button" className={compact ? 'btn btn-secondary btn-sm' : 'btn btn-ghost btn-sm !px-0 underline underline-offset-4 hover:!bg-transparent'} onClick={() => input.current?.click()}>
          {compact && <UploadIcon />} {compact ? 'Import backup' : 'Restore from a backup file'}
        </button>
      ) : (
        <div className="mt-2 rounded-xl border border-rule bg-surface p-4">
          <p className="mb-3 text-[13px] text-ink-2">Backup: <span className="font-mono text-ink">{file.name}</span></p>
          <PassphraseForm id="backup-pass" label="Passphrase this backup was made with" action="Import" busyLabel="Decrypting…" onSubmit={async p => { await vault.importBackup(file.text, p); setFile(null) }} />
          <button type="button" className="btn btn-ghost btn-sm mt-2" onClick={() => setFile(null)}>Cancel</button>
        </div>
      )}
      {error && <p className="field-error">{error}</p>}
    </div>
  )
}

/* ── Saved entries ─────────────────────────────────────────────────── */

function EntryRow({ entry, now, onUse, onDelete }: {
  entry: SavedEntry; now: number; onUse: () => void; onDelete: () => void
}) {
  const key = useMemo(() => { const c = checkSecret(entry.secret); return c.ok ? c.bytes : null }, [entry.secret])
  const live = useTotp(key, entry, now)
  const [confirm, setConfirm] = useState(false)
  const sub = [entry.issuer, entry.account].filter(Boolean).join(' · ')
  const nonDefault = entry.algorithm !== 'SHA-1' || entry.digits !== 6 || entry.period !== 30

  return (
    <li className="flex flex-wrap items-center gap-x-4 gap-y-3 px-4 py-3.5 sm:px-5">
      <div className="min-w-0 flex-1 basis-[180px]">
        <p className="truncate text-[15px] font-medium">{entry.name}</p>
        <p className="truncate text-[12px] text-ink-3">
          {sub || 'No issuer or account'}
          {nonDefault && <span className="font-mono"> · {entry.algorithm} · {entry.digits}d · {entry.period}s</span>}
        </p>
      </div>
      <div className="flex items-center gap-3">
        <span className="font-mono text-[22px] font-medium tabular-nums tracking-[0.04em]">{live.code ? groupCode(live.code) : '–'}</span>
        {live.code && <Ring left={live.left} period={entry.period} size={32} />}
      </div>
      <div className="flex items-center gap-1.5">
        <CopyButton text={live.code ?? ''} disabled={!live.code} />
        <button type="button" className="btn btn-ghost btn-sm" onClick={onUse}>Open</button>
        {confirm ? (
          <>
            <button type="button" className="btn btn-danger btn-sm" onClick={onDelete}>Delete</button>
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setConfirm(false)}>Keep</button>
          </>
        ) : (
          <button type="button" className="btn btn-ghost btn-sm !w-8 !px-0" onClick={() => setConfirm(true)} aria-label={`Delete ${entry.name}`} title="Delete">
            <TrashIcon />
          </button>
        )}
      </div>
    </li>
  )
}

function SaveCurrent({ current, vault }: { current: Account; vault: VaultApi }) {
  const check = useMemo(() => checkSecret(current.secret), [current.secret])
  const suggested = [current.issuer.trim(), current.account.trim()].filter(Boolean).join(' · ')
  const [name, setName] = useState('')
  const duplicate = check.ok && vault.entries.some(e => e.secret === check.secret)
  const can = check.ok && !duplicate

  const save = async (e: FormEvent) => {
    e.preventDefault()
    if (!check.ok || duplicate) return
    await vault.add({
      id: newId(),
      name: name.trim() || suggested || `Key ${vault.entries.length + 1}`,
      secret: check.secret,
      issuer: current.issuer.trim(),
      account: current.account.trim(),
      algorithm: current.algorithm,
      digits: current.digits,
      period: current.period,
      createdAt: new Date().toISOString(),
    })
    setName('')
    vault.setMessage('Saved.')
  }

  return (
    <form onSubmit={save} className="flex flex-wrap items-end gap-2.5">
      <div className="min-w-[200px] flex-1">
        <label htmlFor="save-name" className="field-label">Save the key above as</label>
        <input id="save-name" value={name} onChange={e => setName(e.target.value)} placeholder={suggested || 'Name, e.g. Work email'} className="input" disabled={!check.ok} />
      </div>
      <button type="submit" className="btn btn-primary !h-10" disabled={!can}>Save key</button>
      {duplicate && <p className="w-full text-[12px] text-ink-3">This key is already in your vault.</p>}
      {!check.ok && <p className="w-full text-[12px] text-ink-3">Enter a valid key above to save it.</p>}
    </form>
  )
}

/* ── Panel ─────────────────────────────────────────────────────────── */

export function VaultPanel({ vault, current, onUse, now }: {
  vault: VaultApi; current: Account; onUse: (e: SavedEntry) => void; now: number
}) {
  const [confirmReset, setConfirmReset] = useState(false)

  const legacyNote = vault.legacyPresent && vault.status !== 'open' && (
    <div className="mb-5 rounded-xl border border-warn bg-warn-wash px-4 py-3 text-[13px] text-ink">
      {vault.legacyCount > 0 ? (
        <p>
          This browser still holds <strong>{vault.legacyCount} key{vault.legacyCount === 1 ? '' : 's'}</strong> from the old TOTP page, stored <strong>unencrypted</strong>.
          {vault.status === 'none' ? ' Create a vault and they move in automatically.' : ' Unlock your vault and they move in automatically.'} The unencrypted copies are deleted afterwards.
        </p>
      ) : (
        <p>The old TOTP page left some unencrypted settings in this browser. They hold no usable key.</p>
      )}
      <button type="button" className="btn btn-ghost btn-sm mt-2 !px-0 text-negative underline underline-offset-4 hover:!bg-transparent" onClick={vault.discardLegacy}>
        Delete them now instead
      </button>
    </div>
  )

  const message = vault.message && (
    <div className="mb-5 flex items-start justify-between gap-3 rounded-xl border border-rule bg-surface px-4 py-3 text-[13px] text-ink-2" role="status">
      <span>{vault.message}</span>
      <button type="button" className="font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3 hover:text-ink" onClick={() => vault.setMessage(null)}>Dismiss</button>
    </div>
  )

  if (vault.status === 'unavailable') {
    return <Card><p className="text-[14px] text-ink-2">This browser blocks storage for this page (private mode or strict settings), so keys can't be saved here. The generator above still works.</p></Card>
  }

  if (vault.status === 'none') {
    return (
      <Card>
        {message}
        {legacyNote}
        <h3 className="text-[17px] font-semibold tracking-tight">Create a vault to save keys</h3>
        <p className="mt-1.5 max-w-[620px] text-[14px] leading-relaxed text-ink-2">
          Saved keys are encrypted with your passphrase (AES-256) and kept only in this browser. Tick never sees them and cannot recover them.
        </p>
        <div className="mt-5"><CreateForm onCreate={vault.create} /></div>
        <div className="mt-5 border-t border-rule pt-4"><ImportBackup vault={vault} /></div>
      </Card>
    )
  }

  if (vault.status === 'locked') {
    return (
      <Card>
        {message}
        {legacyNote}
        <div className="flex items-center gap-2.5"><LockIcon /><h3 className="text-[17px] font-semibold tracking-tight">Vault locked</h3></div>
        <p className="mt-1.5 text-[14px] text-ink-2">Enter your passphrase to see your saved keys.</p>
        <div className="mt-4"><PassphraseForm id="unlock" label="Passphrase" action="Unlock" busyLabel="Unlocking…" onSubmit={vault.open} /></div>
        <div className="mt-6 border-t border-rule pt-4 text-[13px] text-ink-3">
          {confirmReset ? (
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="text-negative">Delete the vault and every saved key in it? This can't be undone.</span>
              <button type="button" className="btn btn-danger btn-sm" onClick={() => { vault.reset(); setConfirmReset(false) }}>Delete vault</button>
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => setConfirmReset(false)}>Cancel</button>
            </div>
          ) : (
            <button type="button" className="underline underline-offset-4 hover:text-ink" onClick={() => setConfirmReset(true)}>Forgot the passphrase? Start over</button>
          )}
        </div>
      </Card>
    )
  }

  return (
    <div className="grid gap-5">
      {message}
      <Card>
        <SaveCurrent current={current} vault={vault} />
      </Card>
      <div className="overflow-hidden rounded-2xl border border-rule bg-frame shadow-frame">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-rule px-4 py-3 sm:px-5">
          <p className="eyebrow">{vault.entries.length} saved key{vault.entries.length === 1 ? '' : 's'} · locks after 5 min idle</p>
          <div className="flex flex-wrap gap-1.5">
            <button type="button" className="btn btn-secondary btn-sm" onClick={vault.exportBackup} disabled={vault.entries.length === 0}><DownloadIcon /> Export backup</button>
            <ImportBackup vault={vault} compact />
            <button type="button" className="btn btn-primary btn-sm" onClick={vault.lock}><LockIcon /> Lock</button>
          </div>
        </div>
        {vault.entries.length === 0 ? (
          <p className="px-5 py-8 text-center text-[14px] text-ink-3">No saved keys yet. Enter a key above and save it.</p>
        ) : (
          <ul className="divide-y divide-rule">
            {vault.entries.map(e => (
              <EntryRow key={e.id} entry={e} now={now} onUse={() => onUse(e)} onDelete={() => vault.remove(e.id)} />
            ))}
          </ul>
        )}
      </div>
      <p className="text-[12px] text-ink-3">Backups are encrypted with the passphrase in use when you export them. Keep the file and the passphrase somewhere safe.</p>
    </div>
  )
}
