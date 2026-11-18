// Apply the saved (or system) theme before first paint to avoid a flash.
// A file, not an inline script, so the CSP can stay script-src 'self'.
(function () {
  var t = null
  try { t = localStorage.getItem('theme') } catch (e) {}
  if (t !== 'light' && t !== 'dark') {
    t = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  }
  document.documentElement.setAttribute('data-theme', t)
})()
