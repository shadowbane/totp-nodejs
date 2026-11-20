#!/usr/bin/env node
// GENERATED from devhelper-fe/theme v1.0.1 - do not edit; change devhelper-fe/theme and run sync.mjs
// Fails when any file of this vendored DevHelper theme was changed by hand.
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
const dir = dirname(fileURLToPath(import.meta.url))
const m = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'))
let bad = 0
for (const [file, sum] of Object.entries(m.files)) {
  let got = ''
  try { got = createHash('sha256').update(readFileSync(join(dir, file))).digest('hex') } catch { got = 'missing' }
  if (got !== sum) { console.error('devhelper-theme: ' + file + ' differs from v' + m.version); bad++ }
}
if (bad) { console.error('Re-run devhelper-fe/theme/sync.mjs instead of editing these files.'); process.exit(1) }
console.log('devhelper-theme v' + m.version + ' (' + m.product + '): ' + Object.keys(m.files).length + ' files OK')
