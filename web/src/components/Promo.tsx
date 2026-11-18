const ZAPYAP_URL = 'https://zapyap.com/?utm_source=tick&utm_medium=referral&utm_campaign=tick_card'

/**
 * Referral card for our partner ZapYap, shown between the hero and the generator.
 */
export function PromoCard() {
  return (
    <aside aria-label="Recommendation" className="mt-10 flex flex-wrap items-center gap-x-6 gap-y-4 rounded-2xl border border-rule bg-surface p-5 sm:p-6">
      <div className="min-w-0 flex-1 basis-[300px]">
        <p className="text-[15px] font-medium text-ink">Need your codes on every device?</p>
        <p className="mt-1 text-[14px] leading-relaxed text-ink-2">
          Our partner ZapYap is a zero-knowledge password manager and authenticator that works across all your devices.
        </p>
      </div>
      <a href={ZAPYAP_URL} target="_blank" rel="noopener sponsored" className="btn btn-secondary shrink-0">
        Try ZapYap
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M7 17 17 7M8 7h9v9" /></svg>
      </a>
    </aside>
  )
}
