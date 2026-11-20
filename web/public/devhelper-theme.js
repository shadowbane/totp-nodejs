/* GENERATED from devhelper-fe/theme v1.0.1 - do not edit; change devhelper-fe/theme and run sync.mjs */
/* DevHelper theme: light / dark / system, applied before first paint.
 *
 * Load it as a file in <head>, before any stylesheet that depends on it:
 *   <script src="/devhelper-theme.js"></script>                    shared choice
 *   <script src="/devhelper-theme.js" data-scope="local"></script>  this site only
 *
 * Shared scope: the choice is the cookie dh_theme (light | dark | system) on
 * .devhelper.my.id, so every DevHelper site (and DevHelper ID's server) sees
 * the same one. No cookie until the person chooses; no choice = system.
 * Local scope (Tick): the choice stays in this site's localStorage, no cookie.
 *
 * Sets <html data-theme="light|dark"> (the resolved theme) and
 * data-theme-choice="light|dark|system". API: window.dhTheme.get(),
 * .resolved(), .set(choice), .subscribe(fn) -> unsubscribe.
 */
(function () {
  'use strict'
  var NAME = 'dh_theme'
  var LEGACY = 'theme' // what the apps stored before the shared theme
  var YEAR = 31536000
  var script = document.currentScript
  var scope = script && script.getAttribute('data-scope') === 'local' ? 'local' : 'shared'
  var root = document.documentElement
  var mq = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null
  var listeners = []
  var choice = 'system'

  function valid(v) { return v === 'light' || v === 'dark' || v === 'system' }

  function store(v) { // per-origin copy; v undefined = read
    try {
      if (v === undefined) return localStorage.getItem(NAME)
      localStorage.setItem(NAME, v)
    } catch (e) { /* private mode: the cookie alone carries it */ }
    return null
  }

  function legacy() {
    try {
      var v = localStorage.getItem(LEGACY)
      if (v !== null) localStorage.removeItem(LEGACY)
      return v === 'light' || v === 'dark' ? v : null
    } catch (e) { return null }
  }

  function readCookie() {
    var m = document.cookie.match(/(?:^|;\s*)dh_theme=(light|dark|system)(?:;|$)/)
    return m ? m[1] : null
  }

  // Domain=devhelper.my.id only on devhelper.my.id and its subdomains; a
  // host-only cookie elsewhere (localhost, previews). A host-only dh_theme
  // next to the shared one would make reads random, so it is removed first.
  function writeCookie(v) {
    var h = location.hostname
    var shared = h === 'devhelper.my.id' || /\.devhelper\.my\.id$/.test(h)
    var attrs = '; Path=/; SameSite=Lax' + (location.protocol === 'https:' ? '; Secure' : '')
    if (shared) document.cookie = NAME + '=; Max-Age=0' + attrs
    document.cookie = NAME + '=' + v + '; Max-Age=' + YEAR + attrs + (shared ? '; Domain=devhelper.my.id' : '')
  }

  function current() {
    if (scope === 'local') {
      var l = store()
      return valid(l) ? l : null
    }
    var c = readCookie()
    if (c) return c
    // No cookie: never chosen, or Safari dropped it (script cookies live at
    // most 7 days there). This site's last known choice restores it.
    var s = store()
    return valid(s) ? s : null
  }

  function resolved() {
    if (choice === 'light' || choice === 'dark') return choice
    return mq && mq.matches ? 'dark' : 'light'
  }

  function apply() {
    root.setAttribute('data-theme', resolved())
    root.setAttribute('data-theme-choice', choice)
  }

  function notify() {
    for (var i = 0; i < listeners.length; i++) {
      try { listeners[i](choice, resolved()) } catch (e) { /* a listener's bug is its own */ }
    }
  }

  function persist(v) {
    store(v)
    if (scope === 'shared') writeCookie(v)
  }

  // A choice seen here (read or made) is written back, which also renews the
  // cookie past Safari's 7-day cap on every visit.
  function load() {
    var v = current()
    var old = legacy() // always removed; used only when there is no choice yet
    if (!v) {
      v = old
      if (v) persist(v) // migrate the old per-site setting once
    } else if (scope === 'shared') {
      persist(v)
    }
    choice = v || 'system'
  }

  function refresh() {
    var before = choice
    var beforeResolved = resolved()
    var v = current()
    choice = v || 'system'
    if (v && scope === 'shared') store(v)
    if (choice !== before || resolved() !== beforeResolved) {
      apply()
      notify()
    }
  }

  var channel = null
  try { channel = new BroadcastChannel(NAME) } catch (e) { /* old browser: focus fallback */ }

  window.dhTheme = {
    get: function () { return choice },
    resolved: resolved,
    scope: scope,
    set: function (v) {
      if (!valid(v)) return
      choice = v
      persist(v)
      apply()
      notify()
      if (channel) channel.postMessage(v)
    },
    subscribe: function (fn) {
      listeners.push(fn)
      return function () {
        var i = listeners.indexOf(fn)
        if (i >= 0) listeners.splice(i, 1)
      }
    },
  }

  load()
  apply()

  // Follow the system while on "system".
  if (mq) {
    var onSystem = function () { if (choice === 'system') { apply(); notify() } }
    if (mq.addEventListener) mq.addEventListener('change', onSystem)
    else if (mq.addListener) mq.addListener(onSystem)
  }
  // Other tabs: same site at once (BroadcastChannel, storage); other
  // DevHelper sites through the Cookie Store API where it exists, else when
  // this tab is looked at again. No polling.
  if (channel) channel.onmessage = refresh
  window.addEventListener('storage', function (e) { if (e.key === NAME) refresh() })
  if (scope === 'shared' && window.cookieStore && window.cookieStore.addEventListener) {
    window.cookieStore.addEventListener('change', function (e) {
      var all = (e.changed || []).concat(e.deleted || [])
      for (var i = 0; i < all.length; i++) if (all[i].name === NAME) { refresh(); return }
    })
  }
  document.addEventListener('visibilitychange', function () { if (!document.hidden) refresh() })
  window.addEventListener('focus', refresh)
  window.addEventListener('pageshow', refresh)
})()
