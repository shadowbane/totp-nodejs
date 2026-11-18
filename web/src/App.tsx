import { useEffect, useState } from 'react'
import { Generator } from './components/Generator'
import { Privacy, Terms } from './components/Legal'
import { PromoCard } from './components/Promo'
import { VaultPanel } from './components/Vault'
import { ArrowUpRightIcon, DEVHELPER_URL, GitHubIcon, REPO_URL, Section, ThemeToggle, TickMark } from './components/ui'
import { useNow } from './lib/hooks'
import type { Account } from './lib/otpauth'
import { DEFAULT_PARAMS } from './lib/totp'
import { useVault } from './lib/useVault'

const EMPTY: Account = { secret: '', issuer: '', account: '', ...DEFAULT_PARAMS }

type Page = 'home' | 'terms' | 'privacy' | 'notfound'

function pageFromPath(path: string): Page {
  const p = path.replace(/\/+$/, '')
  if (p === '' || p === '/index.html') return 'home'
  return p === '/terms' ? 'terms' : p === '/privacy' ? 'privacy' : 'notfound'
}

const TITLES: Record<Page, string> = {
  home: 'Tick: TOTP codes in your browser',
  terms: 'Terms of use · Tick',
  privacy: 'Privacy · Tick',
  notfound: 'Not found · Tick',
}

function NotFound() {
  return (
    <section className="pt-14 sm:pt-20">
      <p className="eyebrow"><span className="text-brand-ink">404</span> &nbsp;Not found</p>
      <h1 className="mt-4 font-display text-[44px] leading-[1.02] tracking-[-0.02em] sm:text-[56px]">Nothing lives here.</h1>
      <p className="mt-4 text-base text-ink-2">The page you asked for doesn't exist.</p>
      <a href="/" className="btn btn-primary btn-lg mt-8">Back to Tick</a>
    </section>
  )
}

const pillStyle = { background: 'var(--pill-bg)', borderColor: 'var(--pill-border)' }

function TopNav({ page }: { page: Page }) {
  const home = page === 'home' ? '' : '/'
  return (
    <header className="sticky top-0 z-30 px-3 pt-3 sm:px-4">
      <nav className="mx-auto flex h-[52px] max-w-[980px] items-center gap-2 rounded-full border pl-3 pr-2 shadow-pill backdrop-blur-md" style={pillStyle} aria-label="Main">
        <a href="/" className="inline-flex items-center gap-2.5 rounded-lg" aria-label="Tick home">
          <TickMark />
          <span className="text-[17px] font-semibold tracking-tight text-ink">Tick</span>
        </a>
        <div className="ml-4 hidden items-center gap-1 sm:flex">
          <a href={`${home}#generator`} className="rounded-full px-3 py-1.5 text-sm text-ink-2 transition-colors duration-150 hover:text-ink">Generator</a>
          <a href={`${home}#saved`} className="rounded-full px-3 py-1.5 text-sm text-ink-2 transition-colors duration-150 hover:text-ink">Saved keys</a>
        </div>
        <div className="ml-auto flex items-center gap-1">
          <ThemeToggle />
          <a href={REPO_URL} className="btn btn-ghost btn-sm !rounded-full" rel="noopener noreferrer" aria-label="Source code on GitHub">
            <GitHubIcon /> <span className="hidden sm:inline">Source</span>
          </a>
        </div>
      </nav>
    </header>
  )
}

function Home() {
  const now = useNow(250)
  const vault = useVault()
  const [current, setCurrent] = useState<Account>(EMPTY)

  return (
    <>
      <section className="pt-14 sm:pt-20">
        <p className="eyebrow"><span className="text-brand-ink">Tick</span> &nbsp;TOTP generator · by DevHelper</p>
        <h1 className="mt-4 max-w-[820px] font-display text-[44px] leading-[1.02] tracking-[-0.02em] sm:text-[64px]">
          Two-factor codes, <span className="underline decoration-brand decoration-[3px] underline-offset-[8px]">right here</span> in your browser.
        </h1>
        <p className="mt-5 max-w-[600px] text-base leading-relaxed text-ink-2">
          Paste a secret key or an otpauth:// link and get the current code. Long keys work. Nothing you type leaves this page.
        </p>
        <PromoCard />
      </section>

      <Section id="generator" n="01" label="Generator" title="Make a code.">
        <Generator value={current} onChange={setCurrent} now={now} />
      </Section>

      <Section
        id="saved"
        n="02"
        label="Saved keys"
        title="Keep the keys you use."
        lead="Optional. Saved keys are encrypted with your passphrase and stay in this browser. Nothing is saved unless you create a vault."
      >
        <VaultPanel
          vault={vault}
          current={current}
          now={now}
          onUse={e => {
            setCurrent({ secret: e.secret, issuer: e.issuer, account: e.account, algorithm: e.algorithm, digits: e.digits, period: e.period })
            document.getElementById('generator')?.scrollIntoView({ behavior: 'smooth' })
          }}
        />
      </Section>

      <Section id="how" n="03" label="How it works" title="Small, local, open.">
        <div className="grid gap-px overflow-hidden rounded-2xl border border-rule bg-rule md:grid-cols-3">
          {[
            { t: 'Nothing leaves the page', b: 'Codes are made with your browser\'s own crypto. The page is not allowed to connect to any server once it has loaded.' },
            { t: 'Encrypted when saved', b: 'Saved keys are sealed with AES-256 under a key made from your passphrase. Without the passphrase, the vault is unreadable.' },
            { t: 'Open source', b: 'MIT licensed. Read the code, run it yourself, or send a fix.' },
          ].map((p, i) => (
            <div key={p.t} className="bg-frame p-6">
              <p className="eyebrow"><span className="text-brand-ink">{String.fromCharCode(97 + i)}</span></p>
              <h3 className="mt-3 text-[16px] font-semibold tracking-tight">{p.t}</h3>
              <p className="mt-2 text-[14px] leading-relaxed text-ink-2">{p.b}</p>
            </div>
          ))}
        </div>
      </Section>
    </>
  )
}

export default function App() {
  const [page] = useState<Page>(() => pageFromPath(window.location.pathname))
  useEffect(() => {
    document.title = TITLES[page]
    if (page === 'notfound') {
      const m = document.createElement('meta')
      m.name = 'robots'
      m.content = 'noindex'
      document.head.appendChild(m)
    }
  }, [page])

  return (
    <div className="min-h-screen bg-bg text-ink">
      <TopNav page={page} />
      <main className="mx-auto max-w-[1040px] px-4 sm:px-8">
        {page === 'terms' ? <Terms /> : page === 'privacy' ? <Privacy /> : page === 'notfound' ? <NotFound /> : <Home />}
      </main>

      <footer className="mx-auto mt-24 max-w-[1040px] px-4 pb-10 sm:px-8">
        <div className="flex flex-wrap items-start justify-between gap-8 border-t border-rule-ink pt-8">
          <div className="max-w-[320px]">
            <a href="/" className="inline-flex items-center gap-2.5" aria-label="Tick home">
              <TickMark size={24} />
              <span className="text-[15px] font-semibold tracking-tight">Tick</span>
            </a>
            <p className="mt-3 text-[13px] leading-relaxed text-ink-3">
              Free TOTP codes in your browser. Part of <a href={DEVHELPER_URL} className="text-ink-2 underline decoration-rule-2 underline-offset-4 hover:text-ink">DevHelper</a>.
            </p>
          </div>
          <nav aria-label="Footer" className="flex flex-wrap gap-x-14 gap-y-8">
            <div>
              <p className="eyebrow mb-3">Tick</p>
              <ul className="space-y-2 text-[13px]">
                <li><a href="/#generator" className="text-ink-2 hover:text-ink">Generator</a></li>
                <li><a href="/#saved" className="text-ink-2 hover:text-ink">Saved keys</a></li>
              </ul>
            </div>
            <div>
              <p className="eyebrow mb-3">Open source</p>
              <ul className="space-y-2 text-[13px]">
                <li><a href={REPO_URL} rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-ink-2 hover:text-ink"><GitHubIcon size={13} /> Source code</a></li>
                <li><a href={`${REPO_URL}/blob/master/LICENSE`} rel="noopener noreferrer" className="text-ink-2 hover:text-ink">MIT License</a></li>
                <li><a href={`${REPO_URL}/blob/master/CHANGELOG.md`} rel="noopener noreferrer" className="text-ink-2 hover:text-ink">Changelog</a></li>
              </ul>
            </div>
            <div>
              <p className="eyebrow mb-3">Legal</p>
              <ul className="space-y-2 text-[13px]">
                <li><a href="/terms" className="text-ink-2 hover:text-ink">Terms</a></li>
                <li><a href="/privacy" className="text-ink-2 hover:text-ink">Privacy</a></li>
              </ul>
            </div>
          </nav>
        </div>
        <div className="mt-10 flex flex-wrap items-center justify-between gap-3 font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">
          <span>© {new Date().getFullYear()} DevHelper · No warranty, no support</span>
          <a href={DEVHELPER_URL} className="inline-flex items-center gap-1 hover:text-ink">More tools <ArrowUpRightIcon /></a>
        </div>
      </footer>
    </div>
  )
}
