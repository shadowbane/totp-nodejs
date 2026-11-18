/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      // Every color is a CSS variable defined in src/styles/globals.css,
      // so light and dark themes need no per-component classes.
      colors: {
        bg: 'var(--bg)',
        surface: 'var(--surface)',
        frame: 'var(--frame)',
        ink: { DEFAULT: 'var(--ink)', 2: 'var(--ink-2)', 3: 'var(--ink-3)' },
        rule: { DEFAULT: 'var(--rule)', 2: 'var(--rule-2)', ink: 'var(--rule-ink)' },
        brand: { DEFAULT: 'var(--brand)', ink: 'var(--brand-ink)', wash: 'var(--brand-wash)' },
        positive: { DEFAULT: 'var(--positive)', wash: 'var(--positive-wash)' },
        negative: { DEFAULT: 'var(--negative)', wash: 'var(--negative-wash)' },
        warn: { DEFAULT: 'var(--warn)', wash: 'var(--warn-wash)' },
        info: 'var(--info)',
        violet: 'var(--violet)',
      },
      fontFamily: {
        sans: ['"Geist Variable"', 'Geist', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"Geist Mono Variable"', '"Geist Mono"', 'ui-monospace', '"SF Mono"', 'Menlo', 'Consolas', 'monospace'],
        display: ['"Instrument Serif"', 'ui-serif', 'Georgia', 'serif'],
      },
      boxShadow: {
        frame: 'var(--shadow-frame)',
        pill: 'var(--pill-shadow)',
      },
    },
  },
  plugins: [],
}
