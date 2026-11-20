// GENERATED from devhelper-fe/theme v1.0.1 - do not edit; change devhelper-fe/theme and run sync.mjs
/** Tailwind preset: every colour is a DevHelper CSS variable (theme.css). */
export default {
  "theme": {
    "extend": {
      "colors": {
        "bg": "var(--bg)",
        "surface": "var(--surface)",
        "frame": "var(--frame)",
        "ink": {
          "2": "var(--ink-2)",
          "3": "var(--ink-3)",
          "DEFAULT": "var(--ink)"
        },
        "rule": {
          "2": "var(--rule-2)",
          "DEFAULT": "var(--rule)",
          "ink": "var(--rule-ink)"
        },
        "brand": {
          "DEFAULT": "var(--brand)",
          "ink": "var(--brand-ink)",
          "wash": "var(--brand-wash)"
        },
        "positive": {
          "DEFAULT": "var(--positive)",
          "wash": "var(--positive-wash)"
        },
        "negative": {
          "DEFAULT": "var(--negative)",
          "wash": "var(--negative-wash)"
        },
        "warn": {
          "DEFAULT": "var(--warn)",
          "wash": "var(--warn-wash)"
        },
        "lens": {
          "DEFAULT": "var(--lens)",
          "ink": "var(--lens-ink)",
          "wash": "var(--lens-wash)"
        },
        "tick": {
          "DEFAULT": "var(--tick)",
          "ink": "var(--tick-ink)",
          "wash": "var(--tick-wash)"
        },
        "publish": {
          "DEFAULT": "var(--publish)",
          "ink": "var(--publish-ink)",
          "wash": "var(--publish-wash)"
        },
        "info": "var(--info)",
        "violet": "var(--violet)"
      },
      "fontFamily": {
        "sans": [
          "Geist",
          "ui-sans-serif",
          "system-ui",
          "sans-serif"
        ],
        "mono": [
          "\"Geist Mono\"",
          "ui-monospace",
          "\"SF Mono\"",
          "Menlo",
          "Consolas",
          "monospace"
        ],
        "display": [
          "\"Instrument Serif\"",
          "ui-serif",
          "Georgia",
          "serif"
        ]
      },
      "boxShadow": {
        "frame": "var(--shadow-frame)",
        "pill": "var(--pill-shadow)"
      }
    }
  }
}
