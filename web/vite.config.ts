/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// 5173 = lens-fe, 5180 = publish-fe, 5190 = devhelper-fe.
export default defineConfig({
  plugins: [react()],
  server: { port: 5195 },
  preview: { port: 5196 },
  build: {
    // The CSP allows fonts and images from 'self' only, so never inline assets as data: URIs.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
  test: { environment: 'node' },
})
