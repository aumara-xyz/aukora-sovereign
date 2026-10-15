// SPDX-License-Identifier: AGPL-3.0-or-later
window.__ModuleLoader__.load({
  id: '@aukora/face-organs',
  factory: require => {
    const { createElement: h, useEffect, useRef, useState } = require('react')
    const ORGANS = [
      ['aura', 'Aura', 'Signed record'],
      ['kira', 'Kira', 'Recorded memory'],
      ['aumlok', 'Aumlok', 'Owner identity'],
      ['nostr', 'Nostr', 'Public identity and witness'],
      ['verifier', 'Verifier', 'Independent record verification'],
      ['wasm', 'WASM core', 'Pinned proposal module'],
    ]
    const PANES = ['approvals', 'aumlok', 'aura', 'memory', 'model', 'nostr']
    const SYSTEM_PANES = { approvals: 'approvals', aura: 'aura', kira: 'memory', aumlok: 'aumlok', nostr: 'nostr', verifier: 'aura', wasm: 'aura' }
    const APPROVALS = ['approvals', 'Approvals', 'Pending owner decisions']
    const classes = {
      panel: 'JS6p6q_panel', close: 'JS6p6q_close',
      header: 'JS6p6q_header', title: 'JS6p6q_title',
      menu: 'JS6p6q_menuItem', active: 'JS6p6q_menuItemActive', copy: 'JS6p6q_systemMenuCopy',
    }

    function ownerOrigin(value) {
      try {
        const url = new URL(value)
        return typeof value === 'string' && value.length <= 2048 && url.protocol === 'https:'
          && url.origin === value ? value : null
      } catch { return null }
    }

    async function loadOrgans() {
      const response = await fetch('/api/sovereign/organs', { credentials: 'same-origin', cache: 'no-store', redirect: 'error' })
      if (!response.ok) throw new Error('organs unavailable')
      return response.json()
    }

    function ownerFrameSrc(data, pane) {
      const origin = ownerOrigin(data?.owner_origin)
      return origin && PANES.includes(pane) ? `${origin}/#/embed/${pane}` : null
    }

    function validDecision(event, origin, frameWindow) {
      const data = event.data
      return origin !== null && event.origin === origin && frameWindow != null && event.source === frameWindow
        && data !== null && typeof data === 'object' && !Array.isArray(data)
        && Object.keys(data).sort().join(',') === 'event,kind,pending'
        && data.kind === 'aukora-owner' && data.event === 'decided'
        && Number.isSafeInteger(data.pending) && data.pending >= 0
    }

    function createOwnerController({ load = loadOrgans, schedule = setTimeout, cancel = clearTimeout } = {}) {
      let snapshot = { data: null, error: false, pane: null }
      let previousCount = 0
      let decision = 0
      let stopPolling = null
      const listeners = new Set()
      const publish = patch => {
        snapshot = { ...snapshot, ...patch }
        listeners.forEach(listener => listener(snapshot))
      }
      const controller = {
        getSnapshot: () => snapshot,
        subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener) },
        open(pane) { if (PANES.includes(pane)) publish({ pane }) },
        close() { publish({ pane: null }) },
        handleMessage(event, frameWindow) {
          if (!snapshot.pane || !validDecision(event, ownerOrigin(snapshot.data?.owner_origin), frameWindow)) return
          decision += 1
          previousCount = event.data.pending
          publish({ data: { ...snapshot.data, approvals_pending: event.data.pending },
            ...(event.data.pending === 0 ? { pane: null } : {}) })
        },
        start() {
          if (stopPolling) return () => {}
          let live = true
          let timer
          const poll = async () => {
            const issuedDecision = decision
            try {
              const data = await load()
              if (!live || issuedDecision !== decision) return
              const count = data.approvals_pending
              if (!Number.isSafeInteger(count) || count < 0) throw new Error('guest:organs-invalid-count')
              const rise = count > previousCount && count > 0
              previousCount = count
              publish({ data, error: false, ...(rise ? { pane: 'approvals' } : {}) })
            } catch {
              if (live) publish({ error: true })
            } finally {
              if (live) timer = schedule(poll, 5000)
            }
          }
          stopPolling = () => { live = false; cancel(timer); stopPolling = null }
          void poll()
          return stopPolling
        },
      }
      return controller
    }

    function useOwnerState(controller) {
      const [state, setState] = useState(controller.getSnapshot)
      useEffect(() => {
        const unsubscribe = controller.subscribe(setState)
        setState(controller.getSnapshot())
        return unsubscribe
      }, [controller])
      return state
    }

    function OrganMenu({ organ, controller }) {
      const [id, label, description] = organ
      const state = useOwnerState(controller)
      const pane = SYSTEM_PANES[id]
      const active = state.pane === pane
      return h('button', {
        type: 'button', className: `${classes.menu}${active ? ` ${classes.active}` : ''}`,
        'aria-current': active ? 'page' : undefined, 'data-organ-entry': id,
        onClick: () => controller.open(pane),
      }, h('span', { className: classes.copy }, h('strong', null, label), h('span', null, description)),
      id === 'approvals' ? h('span', { 'data-approvals-badge': true, 'aria-label': 'Pending approvals',
        style: { borderRadius: '999px', padding: '2px 8px', background: 'var(--dsw-alias-bg-layer-2)', color: 'var(--aukora-gold, var(--dsw-alias-label-primary))' } },
      state.data?.approvals_pending ?? '–') : null)
    }

    function OwnerSheet({ state, controller, frameRef }) {
      const dialog = useRef(null)
      const loadTimer = useRef(null)
      const [failed, setFailed] = useState(false)
      const src = ownerFrameSrc(state.data, state.pane)
      useEffect(() => {
        setFailed(false)
        if (!src) return
        loadTimer.current = setTimeout(() => setFailed(true), 15000)
        return () => clearTimeout(loadTimer.current)
      }, [src])
      useEffect(() => {
        const element = dialog.current
        if (!element) return
        element.showModal()
        return () => element.close()
      }, [])
      const label = state.pane === 'approvals' ? 'Approvals' : 'Owner · ' + state.pane
      return h('dialog', {
        ref: dialog, 'aria-label': label, 'data-owner-sheet': state.pane,
        onCancel: event => { event.preventDefault(); controller.close() },
        onClick: event => { if (event.target === event.currentTarget) controller.close() },
        style: { padding: 0, width: 'min(1100px, calc(100vw - 48px))', height: 'min(820px, calc(100dvh - 48px))',
          maxWidth: 'none', maxHeight: 'none', border: '1px solid var(--dsw-alias-border-l1)', borderRadius: '20px',
          background: 'var(--dsw-alias-bg-layer-2)', color: 'var(--dsw-alias-label-primary)', boxShadow: 'var(--dsw-shadow-lv1)', backdropFilter: 'blur(24px)' },
      }, h('style', null, 'dialog[data-owner-sheet]::backdrop{background:rgba(0,0,0,.38);backdrop-filter:blur(8px)}'),
      h('div', { className: classes.panel, style: { width: '100%', height: '100%', margin: 0, display: 'flex', flexDirection: 'column' } },
        h('header', { className: classes.header, style: { padding: '16px 24px', display: 'flex', justifyContent: 'space-between' } },
          h('strong', { className: classes.title }, label),
          h('button', { type: 'button', className: classes.close, onClick: () => controller.close(), 'aria-label': 'Close owner panel' }, '×')),
        src ? h('iframe', {
          key: src, ref: frameRef, title: label, src,
          allow: 'publickey-credentials-get; publickey-credentials-create',
          sandbox: 'allow-scripts allow-same-origin allow-forms allow-popups', referrerPolicy: 'no-referrer',
          onLoad: () => clearTimeout(loadTimer.current),
          onError: () => setFailed(true),
          style: { flex: 1, width: '100%', border: 0, minHeight: 0 },
        }) : h('p', { role: 'status' }, state.error ? 'Owner panel unavailable' : 'Loading owner panel'),
        src && failed ? h('p', { role: 'status', style: { padding: '0 24px' } }, 'Panel could not load. ',
          h('a', { href: src, target: '_blank', rel: 'noopener noreferrer', referrerPolicy: 'no-referrer', style: { color: 'inherit' } }, 'Open owner page')) : null,
      ))
    }

    function OwnerRoot({ controller }) {
      const state = useOwnerState(controller)
      const frameRef = useRef(null)
      useEffect(() => controller.start(), [controller])
      useEffect(() => {
        const listener = event => controller.handleMessage(event, frameRef.current?.contentWindow)
        window.addEventListener('message', listener)
        return () => window.removeEventListener('message', listener)
      }, [controller])
      return state.pane ? h(OwnerSheet, { state, controller, frameRef }) : null
    }

    function enabledPlugins(snapshot) {
      return Array.isArray(snapshot?.entries) ? snapshot.entries.filter(row => row.enabled === true) : []
    }

    function PluginsSection({ list }) {
      const [state, setState] = useState({ rows: null, error: false })
      useEffect(() => {
        let live = true
        list().then(snapshot => { if (live) setState({ rows: enabledPlugins(snapshot), error: false }) }, () => { if (live) setState({ rows: null, error: true }) })
        return () => { live = false }
      }, [list])
      return h('div', null, h('p', null, 'Plugins enabled on this node'),
        state.rows ? h('ul', null, ...state.rows.map(row => h('li', { key: row.entryId, 'data-plugin-entry': row.entryId }, row.moduleName)))
          : h('p', { role: 'status' }, state.error ? 'Plugin inventory unavailable' : 'Loading plugins'))
    }

    function apply(ctx) {
      const controller = createOwnerController()
      ;[APPROVALS, ...ORGANS].forEach((organ, index) => {
        ctx.slots.inject('shell.menu.system', () => ctx.slots.register({
          name: 'shell.menu.system', id: `organ-${organ[0]}`, order: -31 + index, inject: () => ({ organ, controller }),
        }, OrganMenu))
      })
      ctx.slots.inject('shell.overlay', () => ctx.slots.register({
        name: 'shell.overlay', id: 'owner-sheet', order: 100, inject: () => ({ controller }),
      }, OwnerRoot))
      const list = async () => {
        const result = await ctx.remote.pluginInventory.list()
        if (!result.ok) throw new Error('plugin inventory unavailable')
        return result.value
      }
      ctx.slots.inject('settings.section', () => ctx.slots.register({
        name: 'settings.section', id: 'plugins', label: 'Plugins', order: 15, inject: () => ({ list }),
      }, PluginsSection))
    }

    return { inject: ['slots', 'remote', 'remote.pluginInventory'], apply, ORGANS, ownerOrigin,
      loadOrgans, OrganMenu, OwnerRoot, OwnerSheet, ownerFrameSrc, validDecision, createOwnerController, SYSTEM_PANES, PANES, enabledPlugins, PluginsSection }
  },
})
