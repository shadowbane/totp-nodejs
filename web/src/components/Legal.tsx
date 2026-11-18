import type { ReactNode } from 'react'
import { CONTACT_EMAIL, REPO_URL } from './ui'

const UPDATED = '18 November 2026'

function LegalPage({ eyebrow, title, lead, children }: { eyebrow: string; title: string; lead: ReactNode; children: ReactNode }) {
  return (
    <article className="pt-14 sm:pt-20">
      <p className="eyebrow"><span className="text-brand-ink">Tick</span> &nbsp;{eyebrow}</p>
      <h1 className="mt-4 font-display text-[44px] leading-[1.02] tracking-[-0.02em] sm:text-[56px]">{title}</h1>
      <p className="mt-4 max-w-[640px] text-base leading-relaxed text-ink-2">{lead}</p>
      <p className="mt-3 font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">Last updated {UPDATED}</p>
      <div className="mt-10 max-w-[720px] border-t border-rule-ink">{children}</div>
    </article>
  )
}

function Clause({ n, title, children }: { n: string; title: string; children: ReactNode }) {
  return (
    <section className="grid gap-x-8 gap-y-2 border-b border-rule py-6 md:grid-cols-[160px_1fr]">
      <h2 className="eyebrow pt-1"><span className="text-brand-ink">{n}</span> &nbsp;{title}</h2>
      <div className="space-y-3 text-[15px] leading-relaxed text-ink-2 [&_strong]:font-medium [&_strong]:text-ink">{children}</div>
    </section>
  )
}

const A = ({ href, children }: { href: string; children: ReactNode }) => (
  <a href={href} className="text-ink underline decoration-rule-2 underline-offset-4 hover:decoration-brand" rel="noopener noreferrer">{children}</a>
)

export function Terms() {
  return (
    <LegalPage
      eyebrow="Terms of use"
      title="Terms of use"
      lead="Tick is a free tool. These terms are short, but please read them: they say what Tick does not promise, and who is responsible for your data."
    >
      <Clause n="01" title="What Tick is">
        <p>Tick (totp.devhelper.my.id) generates time-based one-time passwords (TOTP) in your web browser. It is part of DevHelper. Using Tick means you accept these terms. If you don't accept them, don't use Tick.</p>
      </Clause>
      <Clause n="02" title="Free, as is">
        <p>Tick is free and is provided <strong>"as is" and "as available", without any warranty</strong>, express or implied. That includes, without limit, warranties of merchantability, fitness for a particular purpose, non-infringement, accuracy of the codes it shows, and availability of the site.</p>
      </Clause>
      <Clause n="03" title="No support">
        <p><strong>We do not offer support.</strong> There is no help desk, no guaranteed reply and no service level. We may change Tick, or stop running it, at any time and without notice.</p>
      </Clause>
      <Clause n="04" title="Your data">
        <p>Your secret keys stay in your browser. We never receive them, so we cannot see, recover, restore or reset them.</p>
        <p><strong>Loss of data is not our responsibility.</strong> Saved keys can be lost by clearing browser data, a forgotten passphrase, a lost or reset device, a browser change, or a fault in Tick. Keep your own backups: the recovery codes each site gives you, and Tick's encrypted backup file.</p>
      </Clause>
      <Clause n="05" title="Liability">
        <p>To the fullest extent the law allows, DevHelper and the people behind it are <strong>not liable for any loss or damage</strong> from using, or being unable to use, Tick. That includes being locked out of an account, lost or exposed keys, lost data, and any indirect or consequential loss.</p>
      </Clause>
      <Clause n="06" title="Fair use">
        <p>Use Tick only for accounts you are allowed to access. You are responsible for keeping your device, browser and passphrase secure.</p>
      </Clause>
      <Clause n="07" title="Open source">
        <p>Tick's code is open source under the MIT License, at <A href={REPO_URL}>github.com/shadowbane/totp-nodejs</A>. The license covers the code. These terms cover this hosted site.</p>
      </Clause>
      <Clause n="08" title="Changes">
        <p>We may update these terms. The date at the top shows the latest version. Using Tick after a change means you accept the new terms.</p>
      </Clause>
      <Clause n="09" title="Contact">
        <p>You can write to <A href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</A>. We read messages, but cannot promise a reply.</p>
      </Clause>
    </LegalPage>
  )
}

export function Privacy() {
  return (
    <LegalPage
      eyebrow="Privacy"
      title="Privacy"
      lead="Short version: Tick has no accounts, no analytics and no server that receives your data. Your keys never leave your browser."
    >
      <Clause n="01" title="Your keys">
        <p>Everything Tick does happens in your browser: decoding keys, making codes and drawing QR codes. The secret keys you type are <strong>never sent anywhere</strong>.</p>
        <p>The page sets a Content Security Policy that blocks it from connecting to any server after it loads, and every font and script is served from this site. No third parties are involved.</p>
      </Clause>
      <Clause n="02" title="What is stored">
        <p>Keys typed into the generator are not stored. Close the tab and they are gone.</p>
        <p>Keys you choose to save go into a vault in this browser's local storage, <strong>encrypted with your passphrase</strong> (PBKDF2 with 600,000 rounds, then AES-256-GCM). The passphrase and the key made from it are kept only in memory while the vault is unlocked.</p>
        <p>Tick also remembers your light or dark theme choice.</p>
      </Clause>
      <Clause n="03" title="What encryption covers">
        <p>The vault protects saved keys at rest, for example from someone who copies your browser's files. It <strong>does not protect against</strong> malware, a compromised device, or browser extensions that can read pages while the vault is unlocked.</p>
        <p>A forgotten passphrase cannot be recovered by anyone, including us.</p>
      </Clause>
      <Clause n="04" title="The host">
        <p>The site is served by Cloudflare. Like any website, delivering the page involves standard request data such as your IP address and browser type, which Cloudflare processes under its own <A href="https://www.cloudflare.com/privacypolicy/">privacy policy</A>. Tick adds no cookies, tracking or analytics.</p>
      </Clause>
      <Clause n="05" title="Changes">
        <p>If this policy changes, the date at the top will change with it.</p>
      </Clause>
      <Clause n="06" title="Contact">
        <p>Questions about privacy: <A href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</A>.</p>
      </Clause>
    </LegalPage>
  )
}
