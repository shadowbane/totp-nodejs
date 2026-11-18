import { useEffect, useState } from 'react'
import { secondsLeft, totp, type TotpParams } from './totp'

/** Current time, refreshed `every` ms. One timer per caller. */
export function useNow(every = 250): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), every)
    return () => clearInterval(t)
  }, [every])
  return now
}

export interface LiveCode {
  code: string | null
  next: string | null
  left: number
}

/** Current and next TOTP code for a key; recomputed when the time step changes. */
export function useTotp(key: Uint8Array | null, params: TotpParams, now: number): LiveCode {
  const step = Math.floor(now / 1000 / params.period)
  const [codes, setCodes] = useState<{ code: string | null; next: string | null }>({ code: null, next: null })

  useEffect(() => {
    let cancelled = false
    if (!key || key.length === 0) {
      setCodes({ code: null, next: null })
      return
    }
    const at = step * params.period * 1000
    Promise.all([totp(key, params, at), totp(key, params, at + params.period * 1000)])
      .then(([code, next]) => { if (!cancelled) setCodes({ code, next }) })
      .catch(() => { if (!cancelled) setCodes({ code: null, next: null }) })
    return () => { cancelled = true }
  }, [key, params.algorithm, params.digits, params.period, step]) // eslint-disable-line react-hooks/exhaustive-deps

  return { ...codes, left: secondsLeft(params.period, now) }
}
