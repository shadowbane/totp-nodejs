import devhelper from './src/devhelper-theme/tailwind-preset.js'

/** @type {import('tailwindcss').Config} */
export default {
  // Colours, fonts and shadows: the DevHelper theme (generated, see src/devhelper-theme).
  presets: [devhelper],
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  plugins: [],
}
