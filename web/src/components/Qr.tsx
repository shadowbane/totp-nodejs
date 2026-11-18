import { useMemo } from 'react'
import QRCode from 'qrcode'

/**
 * Draws a QR code as inline SVG from the module matrix. No canvas, no
 * data: URL and no innerHTML, so it works under a strict CSP.
 */
export function Qr({ text, size = 208 }: { text: string; size?: number }) {
  const qr = useMemo(() => {
    try {
      const { modules } = QRCode.create(text, { errorCorrectionLevel: 'M' })
      const n = modules.size
      let d = ''
      for (let y = 0; y < n; y++) {
        for (let x = 0; x < n; x++) {
          if (modules.get(x, y)) d += `M${x} ${y}h1v1h-1z`
        }
      }
      return { n, d }
    } catch {
      return null
    }
  }, [text])

  if (!qr) {
    return <p className="text-[13px] text-negative">This key is too long to fit in a QR code. Copy the link instead.</p>
  }
  const quiet = 4
  return (
    <svg
      viewBox={`${-quiet} ${-quiet} ${qr.n + quiet * 2} ${qr.n + quiet * 2}`}
      width={size}
      height={size}
      shapeRendering="crispEdges"
      role="img"
      aria-label="QR code for an authenticator app"
      className="rounded-lg"
    >
      {/* Always dark on white, whatever the theme, so every camera can read it. */}
      <rect x={-quiet} y={-quiet} width={qr.n + quiet * 2} height={qr.n + quiet * 2} fill="#ffffff" />
      <path d={qr.d} fill="#111418" />
    </svg>
  )
}
