/* ============================================================================
 * Privacy Sentinel — Interactive WebUI Controller (Vanilla JS, Zero Bloat)
 * ============================================================================ */

(() => {
  /* Bitmask constants matching native/include/sentinel_protocol.h */
  const CAT = {
    NETWORK:   1 << 0,
    DATA:      1 << 1,
    AUTOSTART: 1 << 2,
    DANGER:    1 << 3,
    IPC:       1 << 4,
    SANDBOX:   1 << 5,
    PROXY:     1 << 6
  };

  const POL = {
    EXEMPT_ZERO_TOUCH:   1 << 0,
    BLOCK_NETWORK:       1 << 1,
    SLEEP_SELECTED:      1 << 2,
    BLOCK_BG_IPC:        1 << 3,
    BLOCK_AUTOSTART:     1 << 4,
    IPC_REJECT_EXPLICIT: 1 << 5,
    SANDBOX_FS_L1:       1 << 6,
    SANDBOX_KERNEL_L2:   1 << 7,
    ASK_INTERACTIVE:     1 << 8,
    SPOOF_DETERMINISTIC: 1 << 9,
    SPOOF_EPHEMERAL:     1 << 10,
    SPOOF_CUSTOM:        1 << 11,
    ANTISPY_BG_MIC_CAM:  1 << 12,
    ANTISPY_BG_CLIP:     1 << 13,
    TRAP_ROOT_SCAN:      1 << 14,
    ROUTE_PROXY:         1 << 15,
    STRICT_KILLSWITCH:   1 << 16
  };

  const state = {
    lang: localStorage.getItem('sentinel_lang') || 'ru',
    design: localStorage.getItem('sentinel_design') || 'obsidian',
    activeTab: 'dashboard',
    activeCategory: 0, // 0 = All
    searchQuery: '',
    status: null,
    snapshot: null,
    sparkTotal: [8, 11, 10, 13, 14, 16, 15, 18, 19, 21, 22, 24],
    sparkBlocked: [3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11],
    lastTotalEvents: 0,
    lastBlockedEvents: 0,
    openDrawerUid: null,
    activePromptId: null
  };

  const t = (key) => (window.SentinelI18n[state.lang] && window.SentinelI18n[state.lang][key]) || key;

  function escHtml(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function showToast(msg) {
    const el = document.getElementById('toast-banner');
    if (!el) return;
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(showToast._tid);
    showToast._tid = setTimeout(() => el.classList.remove('show'), 2200);
  }

  /* ---- Static SVG Slot Mounting ---- */
  function mountStaticIllustrations() {
    document.getElementById('brand-crest-slot').innerHTML = SentinelSVG.brandCrest();
    document.getElementById('hero-radar-slot').innerHTML = SentinelSVG.tacticalRadar();
    document.getElementById('sleep-art-slot').innerHTML = SentinelSVG.deepSleepWave();
    document.getElementById('antispy-art-slot').innerHTML = SentinelSVG.antiSpyShutter();
    document.getElementById('device-garnet-slot').innerHTML = SentinelSVG.deviceGarnet();

    document.getElementById('nav-ic-radar').innerHTML = SentinelSVG.navRadar();
    document.getElementById('nav-ic-fw').innerHTML = SentinelSVG.navFirewall();
    document.getElementById('nav-ic-spoof').innerHTML = SentinelSVG.navSpoof();
    document.getElementById('nav-ic-sys').innerHTML = SentinelSVG.navSystem();
  }

  function applyDesignAndLanguage() {
    document.documentElement.setAttribute('data-design', state.design);
    document.documentElement.setAttribute('lang', state.lang);

    document.querySelectorAll('[data-theme-pick]').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.themePick === state.design);
    });
    document.querySelectorAll('[data-lang-pick]').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.langPick === state.lang);
    });

    document.querySelectorAll('[data-i18n]').forEach((el) => {
      el.textContent = t(el.dataset.i18n);
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
      el.placeholder = t(el.dataset.i18nPlaceholder);
    });

    renderCategoryPills();
    if (state.snapshot) renderAll();
  }

  function renderCategoryPills() {
    const pills = [
      { id: 0, label: t('filterAll'), svg: SentinelSVG.navRadar() },
      { id: CAT.NETWORK, label: t('filterNetwork'), svg: SentinelSVG.catNetwork() },
      { id: CAT.DATA, label: t('filterData'), svg: SentinelSVG.catData() },
      { id: CAT.AUTOSTART, label: t('filterAutostart'), svg: SentinelSVG.catAutostart() },
      { id: CAT.IPC, label: t('filterIpc'), svg: SentinelSVG.catIpc() },
      { id: CAT.DANGER, label: t('filterDanger'), svg: SentinelSVG.catDanger() },
      { id: CAT.SANDBOX, label: t('filterSandbox'), svg: SentinelSVG.catSandbox() }
    ];
    const container = document.getElementById('category-pills');
    container.innerHTML = pills.map((p) => `
      <button class="filter-pill ${state.activeCategory === p.id ? 'active' : ''}" data-cat="${p.id}">
        ${p.svg}
        <span>${escHtml(p.label)}</span>
      </button>
    `).join('');

    container.querySelectorAll('.filter-pill').forEach((btn) => {
      btn.addEventListener('click', () => {
        state.activeCategory = Number(btn.dataset.cat);
        renderCategoryPills();
        renderAppsList();
        renderEventStream();
      });
    });
  }

  /* ---- Renderers ---- */
  function renderHeroAndSubsystems() {
    const snap = state.snapshot;
    if (!snap) return;

    document.getElementById('kpi-events').textContent = snap.total_events.toLocaleString();
    document.getElementById('kpi-blocked').textContent = snap.total_blocked.toLocaleString();
    document.getElementById('kpi-spoofed').textContent = snap.total_spoofed.toLocaleString();
    document.getElementById('kpi-ring').textContent = `${snap.ring_used} / ${(snap.ring_capacity / 1000).toFixed(0)}k`;

    /* Update sparkline history on new telemetry */
    if (snap.total_events !== state.lastTotalEvents) {
      const dTot = Math.max(1, snap.total_events - state.lastTotalEvents);
      const dBlk = Math.max(0, snap.total_blocked - state.lastBlockedEvents);
      state.lastTotalEvents = snap.total_events;
      state.lastBlockedEvents = snap.total_blocked;
      state.sparkTotal.push(Math.min(40, 8 + dTot * 3));
      state.sparkBlocked.push(Math.min(32, 3 + dBlk * 3));
      if (state.sparkTotal.length > 18) state.sparkTotal.shift();
      if (state.sparkBlocked.length > 18) state.sparkBlocked.shift();
    }
    document.getElementById('sparkline-slot').innerHTML =
      SentinelSVG.sparkline(state.sparkTotal, state.sparkBlocked);

    /* Topbar toggles sync */
    document.querySelectorAll('[data-profile]').forEach((b) => {
      b.classList.toggle('active', Number(b.dataset.profile) === snap.global_profile);
    });
    const sleepBtn = document.getElementById('btn-toggle-sleep');
    const sleepLbl = document.getElementById('sleep-btn-label');
    sleepBtn.classList.toggle('btn-primary', !!snap.screen_sleeping);
    sleepLbl.textContent = snap.screen_sleeping ? t('btnSleepSimOn') : t('btnSleepSimOff');
    document.getElementById('chk-system-apps').checked = !!snap.show_system_apps;

    const proxyOn = state.status && state.status.proxy && state.status.proxy.enabled;
    const subSlot = document.getElementById('subsystem-tiles-slot');
    subSlot.innerHTML = `
      <div class="sub-tile">
        <div class="sub-top">${SentinelSVG.catNetwork()}<span class="status-dot">${escHtml(t('stateActive'))}</span></div>
        <div class="sub-name">${escHtml(t('subNetfilter'))}</div>
        <div class="sub-meta">SENTINEL_OUT + SOCK_DESTROY</div>
      </div>
      <div class="sub-tile">
        <div class="sub-top">${SentinelSVG.catSandbox()}<span class="status-dot">${escHtml(t('stateActive'))}</span></div>
        <div class="sub-name">${escHtml(t('subZygisk'))}</div>
        <div class="sub-meta">PLT Hooks • Mount NS • PIF Safe</div>
      </div>
      <div class="sub-tile">
        <div class="sub-top">${SentinelSVG.catIpc()}<span class="status-dot">${escHtml(t('stateActive'))}</span></div>
        <div class="sub-name">${escHtml(t('subVector'))}</div>
        <div class="sub-meta">AMS IPC + IFW + Zero-PCM Mic</div>
      </div>
      <div class="sub-tile">
        <div class="sub-top">${SentinelSVG.catProxy()}<span class="status-dot ${proxyOn ? '' : 'standby'}">${escHtml(proxyOn ? t('stateActive') : t('stateStandby'))}</span></div>
        <div class="sub-name">${escHtml(t('subProxy'))}</div>
        <div class="sub-meta">${proxyOn ? escHtml(`${state.status.proxy.socks5_host}:${state.status.proxy.socks5_port}`) : '127.0.0.1:9050 (:19040)'}</div>
      </div>
    `;
  }

  function appMatchesFilter(app) {
    if (state.searchQuery) {
      const q = state.searchQuery.toLowerCase();
      const hit = app.package_name.toLowerCase().includes(q)
        || app.label.toLowerCase().includes(q)
        || String(app.uid).includes(q);
      if (!hit) return false;
    }
    const c = app.counts || {};
    switch (state.activeCategory) {
      case CAT.NETWORK:   return c.network > 0 || (app.flags & POL.BLOCK_NETWORK);
      case CAT.DATA:      return c.data > 0;
      case CAT.AUTOSTART: return c.autostart > 0 || (app.flags & POL.BLOCK_AUTOSTART);
      case CAT.IPC:       return c.ipc > 0 || (app.flags & POL.BLOCK_BG_IPC);
      case CAT.DANGER:    return c.danger > 0;
      case CAT.SANDBOX:   return (app.flags & (POL.SANDBOX_FS_L1 | POL.SANDBOX_KERNEL_L2)) !== 0;
      default:            return true;
    }
  }

  function renderAppsList() {
    const snap = state.snapshot;
    if (!snap) return;
    const container = document.getElementById('apps-list-container');
    const apps = (snap.apps || []).filter(appMatchesFilter);

    container.innerHTML = apps.map((app) => {
      const isZeroTouch = (app.flags & POL.EXEMPT_ZERO_TOUCH) !== 0;
      const c = app.counts || {};
      const isSandboxed = (app.flags & (POL.SANDBOX_FS_L1 | POL.SANDBOX_KERNEL_L2)) !== 0;
      const isProxied = (app.flags & POL.ROUTE_PROXY) !== 0;

      const plaques = isZeroTouch
        ? `<span class="threat-plaque sandbox hot">${SentinelSVG.zeroTouchSeal()}<span>${escHtml(t('zeroTouchBadge'))}</span></span>`
        : `
          <span class="threat-plaque net ${c.network > 0 ? 'hot' : ''}">${SentinelSVG.catNetwork()}<span>${escHtml(t('badgeNet'))}</span><span class="p-count">${c.network || 0}</span></span>
          <span class="threat-plaque data ${c.data > 0 ? 'hot' : ''}">${SentinelSVG.catData()}<span>${escHtml(t('badgeData'))}</span><span class="p-count">${c.data || 0}</span></span>
          <span class="threat-plaque auto ${c.autostart > 0 ? 'hot' : ''}">${SentinelSVG.catAutostart()}<span>${escHtml(t('badgeAuto'))}</span><span class="p-count">${c.autostart || 0}</span></span>
          <span class="threat-plaque ipc ${c.ipc > 0 ? 'hot' : ''}">${SentinelSVG.catIpc()}<span>${escHtml(t('badgeIpc'))}</span><span class="p-count">${c.ipc || 0}</span></span>
          <span class="threat-plaque danger ${c.danger > 0 ? 'hot' : ''}">${SentinelSVG.catDanger()}<span>${escHtml(t('badgeDanger'))}</span><span class="p-count">${c.danger || 0}</span></span>
          ${isSandboxed ? `<span class="threat-plaque sandbox hot">${SentinelSVG.catSandbox()}<span>${escHtml(t('badgeSandbox'))}</span></span>` : ''}
          ${isProxied ? `<span class="threat-plaque proxy hot">${SentinelSVG.catProxy()}<span>${escHtml(t('badgeProxy'))}</span></span>` : ''}
        `;

      return `
        <article class="app-card" data-uid="${app.uid}">
          <div class="app-head">
            <div class="app-id-group">
              ${SentinelSVG.appAvatar(app.package_name, app.label, isZeroTouch)}
              <div>
                <div class="app-title-row">
                  <span class="app-name">${escHtml(app.label)}</span>
                  <span class="uid-chip">UID ${app.uid}</span>
                  <span class="proc-chip ${app.proc_state === 'FG' ? 'fg' : ''}">${escHtml(app.proc_state)}</span>
                </div>
                <div class="app-pkg">${escHtml(app.package_name)}</div>
              </div>
            </div>
            ${!isZeroTouch ? `<button class="btn" data-open-dossier="${app.uid}">${escHtml(t('btnConfigureApp'))}</button>` : ''}
          </div>

          <div class="plaque-row">${plaques}</div>

          ${!isZeroTouch ? `
          <div class="app-actions">
            <div class="quick-toggles">
              <label class="switch-label">
                <input type="checkbox" class="switch-input" data-quick-flag="${POL.BLOCK_NETWORK}" data-uid="${app.uid}" ${(app.flags & POL.BLOCK_NETWORK) ? 'checked' : ''} />
                <span>${escHtml(t('quickNetBlock'))}</span>
              </label>
              <label class="switch-label">
                <input type="checkbox" class="switch-input" data-quick-flag="${POL.ASK_INTERACTIVE}" data-uid="${app.uid}" ${(app.flags & POL.ASK_INTERACTIVE) ? 'checked' : ''} />
                <span>${escHtml(t('quickAskMode'))}</span>
              </label>
            </div>
            <button class="btn btn-danger" data-kill-sock="${app.uid}">${escHtml(t('btnSeverSockets'))}</button>
          </div>` : ''}
        </article>
      `;
    }).join('');

    container.querySelectorAll('[data-open-dossier]').forEach((btn) => {
      btn.addEventListener('click', () => openAppDossier(Number(btn.dataset.openDossier)));
    });

    container.querySelectorAll('[data-quick-flag]').forEach((chk) => {
      chk.addEventListener('change', async () => {
        const uid = Number(chk.dataset.uid);
        const bit = Number(chk.dataset.quickFlag);
        const app = state.snapshot.apps.find((a) => a.uid === uid);
        if (!app) return;
        const nextFlags = chk.checked ? (app.flags | bit) : (app.flags & ~bit);
        await SentinelBridge.rpc('update_app', { uid, flags: nextFlags });
        showToast(t('toastSaved'));
        await refreshSnapshot();
      });
    });

    container.querySelectorAll('[data-kill-sock]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const uid = Number(btn.dataset.killSock);
        const r = await SentinelBridge.rpc('kill_sockets', { uid });
        showToast(`NETLINK_SOCK_DIAG: closed ${r.sockets_killed ?? 0} socket(s)`);
        await refreshSnapshot();
      });
    });
  }

  function categoryIcon(catMask) {
    if (catMask & CAT.DANGER)    return SentinelSVG.catDanger();
    if (catMask & CAT.IPC)       return SentinelSVG.catIpc();
    if (catMask & CAT.DATA)      return SentinelSVG.catData();
    if (catMask & CAT.AUTOSTART) return SentinelSVG.catAutostart();
    if (catMask & CAT.PROXY)     return SentinelSVG.catProxy();
    if (catMask & CAT.SANDBOX)   return SentinelSVG.catSandbox();
    return SentinelSVG.catNetwork();
  }

  function actionMeta(actionCode) {
    switch (actionCode) {
      case 1: return { cls: 'drop', label: t('actSilentDrop') };
      case 2: return { cls: 'drop', label: t('actRejectErr') };
      case 3: return { cls: 'spoof', label: t('actSpoofed') };
      case 4: return { cls: 'proxy', label: t('actProxied') };
      case 5: return { cls: 'drop', label: t('actSocketKilled') };
      case 6: return { cls: 'allow', label: t('actPromptAllowed') };
      case 7: return { cls: 'drop', label: t('actPromptDenied') };
      default: return { cls: 'allow', label: t('actObserved') };
    }
  }

  function renderEventStream() {
    const snap = state.snapshot;
    if (!snap) return;
    const feed = document.getElementById('live-event-feed');
    const events = (snap.events || []).filter((ev) => {
      if (state.activeCategory && !(ev.category & state.activeCategory)) return false;
      if (state.searchQuery) {
        const q = state.searchQuery.toLowerCase();
        return ev.pkg.toLowerCase().includes(q) || ev.target.toLowerCase().includes(q) || String(ev.uid).includes(q);
      }
      return true;
    });

    feed.innerHTML = events.slice(0, 45).map((ev) => {
      const act = actionMeta(ev.action);
      const dt = new Date(ev.ts).toLocaleTimeString();
      return `
        <div class="event-item" data-ev-uid="${ev.uid}">
          <div class="ev-top">
            <span class="ev-type">${categoryIcon(ev.category)}<span>${escHtml(ev.type)}</span></span>
            <span class="ev-act ${act.cls}">${escHtml(act.label)}</span>
          </div>
          <div class="ev-target">${escHtml(ev.target)}</div>
          <div class="ev-meta">
            <span>${escHtml(ev.pkg)} (UID ${ev.uid}${ev.is_bg ? ' • BG' : ''})</span>
            <span class="mono">#${ev.seq} • ${dt}</span>
          </div>
        </div>
      `;
    }).join('');

    feed.querySelectorAll('[data-ev-uid]').forEach((row) => {
      row.addEventListener('click', () => {
        const uid = Number(row.dataset.evUid);
        const app = state.snapshot.apps.find((a) => a.uid === uid);
        if (app && !(app.flags & POL.EXEMPT_ZERO_TOUCH)) openAppDossier(uid);
      });
    });
  }

  function renderFirewallAndIpcTab() {
    const snap = state.snapshot;
    if (!snap) return;

    document.getElementById('sel-sleep-mode').value = String(snap.sleep_mode);
    document.getElementById('sel-sleep-grace').value = String(snap.sleep_grace_sec || 15);

    const sleepGrid = document.getElementById('sleep-apps-checklist');
    const userApps = (snap.apps || []).filter((a) => !a.is_system && !(a.flags & POL.EXEMPT_ZERO_TOUCH));
    sleepGrid.innerHTML = userApps.map((a) => `
      <label class="check-tile">
        <span><strong>${escHtml(a.label)}</strong> <small class="mono">(${a.uid})</small></span>
        <input type="checkbox" class="switch-input" data-sleep-uid="${a.uid}" ${(a.flags & POL.SLEEP_SELECTED) ? 'checked' : ''} />
      </label>
    `).join('');

    sleepGrid.querySelectorAll('[data-sleep-uid]').forEach((chk) => {
      chk.addEventListener('change', async () => {
        const uid = Number(chk.dataset.sleepUid);
        const app = snap.apps.find((x) => x.uid === uid);
        if (!app) return;
        const nextFlags = chk.checked ? (app.flags | POL.SLEEP_SELECTED) : (app.flags & ~POL.SLEEP_SELECTED);
        await SentinelBridge.rpc('update_app', { uid, flags: nextFlags });
        showToast(t('toastSaved'));
        await refreshSnapshot();
      });
    });

    const tbody = document.getElementById('ipc-rules-tbody');
    tbody.innerHTML = (snap.ipc_rules || []).map((r) => `
      <tr>
        <td class="mono">${escHtml(r.caller_pkg)}</td>
        <td class="mono">${escHtml(r.target_pkg)}</td>
        <td class="mono">${escHtml(r.component_type)} • ${escHtml(r.action_glob)}</td>
        <td><button class="btn btn-danger" data-del-ipc="${escHtml(r.id)}">&times;</button></td>
      </tr>
    `).join('');

    tbody.querySelectorAll('[data-del-ipc]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        await SentinelBridge.rpc('delete_ipc_rule', { id: btn.dataset.delIpc });
        await refreshSnapshot();
      });
    });
  }

  function renderSpoofAndProxyTab() {
    const snap = state.snapshot;
    if (!snap) return;

    if (state.status) {
      document.getElementById('seed-badge').textContent =
        `Master Seed: 0x${Number(state.status.master_seed || 0).toString(16).toUpperCase()}`;
      const p = state.status.proxy || {};
      document.getElementById('chk-proxy-enable').checked = !!p.enabled;
      document.getElementById('inp-proxy-host').value = p.socks5_host || '127.0.0.1';
      document.getElementById('inp-proxy-port').value = p.socks5_port || 9050;
      document.getElementById('chk-proxy-quic').checked = p.block_quic !== false;
      document.getElementById('chk-proxy-ipv6').checked = p.block_ipv6 !== false;
    }

    const userApps = (snap.apps || []).filter((a) => !a.is_system && !(a.flags & POL.EXEMPT_ZERO_TOUCH));
    const spoofList = document.getElementById('spoof-apps-list');

    spoofList.innerHTML = userApps.map((a) => {
      let curMode = 'off';
      if (a.flags & POL.SPOOF_CUSTOM) curMode = 'custom';
      else if (a.flags & POL.SPOOF_EPHEMERAL) curMode = 'ephemeral';
      else if (a.flags & POL.SPOOF_DETERMINISTIC) curMode = 'deterministic';

      return `
        <div class="check-tile" style="flex-wrap:wrap;gap:10px;">
          <div>
            <strong>${escHtml(a.label)}</strong>
            <div class="app-pkg">${escHtml(a.package_name)}</div>
          </div>
          <select class="input" data-spoof-sel="${a.uid}">
            <option value="off" ${curMode === 'off' ? 'selected' : ''}>${escHtml(t('spoofModeOff'))}</option>
            <option value="deterministic" ${curMode === 'deterministic' ? 'selected' : ''}>${escHtml(t('spoofModeDet'))}</option>
            <option value="ephemeral" ${curMode === 'ephemeral' ? 'selected' : ''}>${escHtml(t('spoofModeEph'))}</option>
            <option value="custom" ${curMode === 'custom' ? 'selected' : ''}>${escHtml(t('spoofModeCustom'))}</option>
          </select>
        </div>
      `;
    }).join('');

    spoofList.querySelectorAll('[data-spoof-sel]').forEach((sel) => {
      sel.addEventListener('change', async () => {
        const uid = Number(sel.dataset.spoofSel);
        const app = snap.apps.find((x) => x.uid === uid);
        if (!app) return;
        let fl = app.flags & ~(POL.SPOOF_DETERMINISTIC | POL.SPOOF_EPHEMERAL | POL.SPOOF_CUSTOM);
        if (sel.value === 'deterministic') fl |= POL.SPOOF_DETERMINISTIC;
        else if (sel.value === 'ephemeral') fl |= POL.SPOOF_EPHEMERAL;
        else if (sel.value === 'custom') fl |= POL.SPOOF_CUSTOM;
        await SentinelBridge.rpc('update_app', { uid, flags: fl });
        showToast(t('toastSaved'));
        await refreshSnapshot();
      });
    });

    const proxyGrid = document.getElementById('proxy-apps-checklist');
    proxyGrid.innerHTML = userApps.map((a) => `
      <label class="check-tile">
        <span><strong>${escHtml(a.label)}</strong> <small class="mono">SOCKS5</small></span>
        <input type="checkbox" class="switch-input" data-proxy-uid="${a.uid}" ${(a.flags & POL.ROUTE_PROXY) ? 'checked' : ''} />
      </label>
    `).join('');

    proxyGrid.querySelectorAll('[data-proxy-uid]').forEach((chk) => {
      chk.addEventListener('change', async () => {
        const uid = Number(chk.dataset.proxyUid);
        const app = snap.apps.find((x) => x.uid === uid);
        if (!app) return;
        const fl = chk.checked ? (app.flags | POL.ROUTE_PROXY) : (app.flags & ~POL.ROUTE_PROXY);
        await SentinelBridge.rpc('update_app', { uid, flags: fl });
        showToast(t('toastSaved'));
        await refreshSnapshot();
      });
    });
  }

  function renderSystemTab() {
    const modules = [
      { name: 'BakaSU + Built-in SuSFS', note: 'Kernel root + automatic ksu_susfs path cloaking for /data/adb/privacy_sentinel' },
      { name: 'Zygisk Next (Standalone)', note: 'API v5 PLT hooks + root companion SCM_RIGHTS policy.mmap descriptor' },
      { name: 'Vector Framework (LibXposed API 102)', note: 'Protective exception mode + API 102 hot-reload + system_server IPC' },
      { name: 'Play Integrity Fix (v4.9) & Tricky Store', note: 'Zero-Touch DLCLOSE_MODULE_LIBRARY on GMS, Vending & target.txt' },
      { name: 'OverlayFS Metamodule', note: 'skip_mount enabled — zero /system partition modifications' },
      { name: 'ViPER4Android', note: 'AudioTrack & AudioEffect untouched; only background AudioRecord PCM zeroed' },
      { name: 'Yet Another Bootloop Protector (YABP)', note: '3-strike post-fs-data watchdog with automatic Safe Bypass fallback' }
    ];

    document.getElementById('compat-matrix-slot').innerHTML = modules.map((m) => `
      <div class="check-tile" style="align-items:flex-start;flex-direction:column;gap:4px;">
        <div style="display:flex;width:100%;justify-content:space-between;align-items:center;">
          <strong>${escHtml(m.name)}</strong>
          <span class="status-dot">${escHtml(t('compatOk'))}</span>
        </div>
        <span class="section-sub" style="margin:0">${escHtml(m.note)}</span>
      </div>
    `).join('');

    const transportMode = SentinelBridge.mode === 'ksu_native'
      ? 'Transport A: window.ksu.exec -> sentinelctl -> UNIX Socket (Zero TCP Port)'
      : 'Transport B: 127.0.0.1 HTTP/SSE + 256-bit X-Sentinel-Token';

    document.getElementById('security-details-slot').innerHTML = `
      <div class="check-tile" style="flex-direction:column;align-items:flex-start;gap:4px;">
        <strong>WebUI Active Transport</strong>
        <span class="mono section-sub" style="margin:0">${escHtml(transportMode)}</span>
      </div>
      <div class="check-tile" style="flex-direction:column;align-items:flex-start;gap:4px;">
        <strong>Android 17 MemoryLimiter &amp; Freezer Bypass</strong>
        <span class="section-sub" style="margin:0">sentineld runs as UID 0 in /sys/fs/cgroup/privacy_sentinel (oom_score_adj = -900), completely exempt from UID &ge; 10000 cgroup v2 MemoryLimiter.</span>
      </div>
      <div class="check-tile" style="flex-direction:column;align-items:flex-start;gap:4px;">
        <strong>POCO X6 5G (garnet) • HyperOS 4 • Linux 5.10 Engine</strong>
        <span class="mono section-sub" style="margin:0">${escHtml((state.status && state.status.fw_backend) || 'iptables-xtables (SENTINEL_* chains)')}</span>
      </div>
    `;
  }

  /* ---- Per-App Dossier Drawer ---- */
  function openAppDossier(uid) {
    const app = state.snapshot && state.snapshot.apps.find((a) => a.uid === uid);
    if (!app) return;
    state.openDrawerUid = uid;

    const sheet = document.getElementById('app-drawer-sheet');
    const flagRow = (bit, labelKey) => `
      <label class="option-row">
        <span>${escHtml(t(labelKey))}</span>
        <input type="checkbox" class="switch-input" data-drawer-bit="${bit}" ${(app.flags & bit) ? 'checked' : ''} />
      </label>
    `;

    sheet.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px;">
        <div class="app-id-group">
          ${SentinelSVG.appAvatar(app.package_name, app.label, false)}
          <div>
            <div class="app-name">${escHtml(app.label)} <span class="uid-chip">UID ${app.uid}</span></div>
            <div class="app-pkg">${escHtml(app.package_name)}</div>
          </div>
        </div>
        <button class="btn" id="btn-close-drawer">${escHtml(t('btnClose'))}</button>
      </div>

      <h4 class="section-title" style="margin-top:10px">${escHtml(t('secNetSandbox'))}</h4>
      ${flagRow(POL.BLOCK_NETWORK, 'optBlockNet')}
      ${flagRow(POL.SLEEP_SELECTED, 'optSleepMember')}
      ${flagRow(POL.SANDBOX_FS_L1, 'optSandboxL1')}
      ${flagRow(POL.SANDBOX_KERNEL_L2, 'optSandboxL2')}
      ${flagRow(POL.ASK_INTERACTIVE, 'optAskPrompt')}
      ${flagRow(POL.STRICT_KILLSWITCH, 'optKillSwitch')}

      <h4 class="section-title" style="margin-top:14px">${escHtml(t('secIpcRules'))}</h4>
      ${flagRow(POL.BLOCK_BG_IPC, 'optBlockBgIpc')}
      ${flagRow(POL.BLOCK_AUTOSTART, 'optBlockAutostart')}
      ${flagRow(POL.IPC_REJECT_EXPLICIT, 'optExplicitReject')}

      <h4 class="section-title" style="margin-top:14px">${escHtml(t('secSpoofSpy'))}</h4>
      ${flagRow(POL.ANTISPY_BG_MIC_CAM, 'optBgMicCam')}
      ${flagRow(POL.ANTISPY_BG_CLIP, 'optBgClip')}
      ${flagRow(POL.TRAP_ROOT_SCAN, 'optTrapRoot')}
      ${flagRow(POL.ROUTE_PROXY, 'optRouteProxy')}

      <div class="form-grid" style="margin-top:12px">
        <div>
          <label class="field-lbl">Custom IMEI</label>
          <input id="drw-imei" class="input mono" style="width:100%" value="${escHtml(app.custom_imei)}" />
        </div>
        <div>
          <label class="field-lbl">Custom MAC</label>
          <input id="drw-mac" class="input mono" style="width:100%" value="${escHtml(app.custom_mac)}" />
        </div>
        <div>
          <label class="field-lbl">GPS Latitude</label>
          <input id="drw-lat" type="number" step="0.0001" class="input mono" style="width:100%" value="${app.custom_lat}" />
        </div>
        <div>
          <label class="field-lbl">GPS Longitude</label>
          <input id="drw-lon" type="number" step="0.0001" class="input mono" style="width:100%" value="${app.custom_lon}" />
        </div>
      </div>

      <button class="btn btn-primary" style="width:100%;margin-top:16px" id="btn-save-drawer">${escHtml(t('btnSaveApp'))}</button>
    `;

    document.getElementById('app-drawer-backdrop').classList.add('open');

    document.getElementById('btn-close-drawer').onclick = () => {
      document.getElementById('app-drawer-backdrop').classList.remove('open');
      state.openDrawerUid = null;
    };

    document.getElementById('btn-save-drawer').onclick = async () => {
      let mask = app.flags & (POL.SPOOF_DETERMINISTIC | POL.SPOOF_EPHEMERAL | POL.SPOOF_CUSTOM);
      sheet.querySelectorAll('[data-drawer-bit]').forEach((chk) => {
        if (chk.checked) mask |= Number(chk.dataset.drawerBit);
      });
      await SentinelBridge.rpc('update_app', {
        uid: app.uid,
        flags: mask,
        custom_imei: document.getElementById('drw-imei').value,
        custom_mac: document.getElementById('drw-mac').value,
        custom_lat: Number(document.getElementById('drw-lat').value),
        custom_lon: Number(document.getElementById('drw-lon').value)
      });
      document.getElementById('app-drawer-backdrop').classList.remove('open');
      state.openDrawerUid = null;
      showToast(t('toastSaved'));
      await refreshSnapshot();
    };
  }

  /* ---- Real-Time Android 17 System Permission Prompt Modal ---- */
  function checkAndRenderInteractivePrompts() {
    const prompts = (state.snapshot && state.snapshot.prompts) || [];
    const backdrop = document.getElementById('prompt-modal-backdrop');
    if (prompts.length === 0) {
      backdrop.classList.remove('open');
      state.activePromptId = null;
      return;
    }

    const p = prompts[0];
    if (state.activePromptId === p.id && backdrop.classList.contains('open')) {
      const remEl = document.getElementById('prompt-rem-sec');
      if (remEl) remEl.textContent = `${Math.ceil((p.remaining_ms || 0) / 1000)}s`;
      return;
    }

    state.activePromptId = p.id;
    const sheet = document.getElementById('prompt-modal-sheet');
    sheet.innerHTML = `
      ${SentinelSVG.permissionGuardian()}
      <div class="version-pill" style="display:inline-block;margin-bottom:6px">${escHtml(t('promptHeader'))} • <span id="prompt-rem-sec">${Math.ceil((p.remaining_ms || 9000) / 1000)}s</span></div>
      <h3 class="section-title">${escHtml(t('promptQuestion'))}</h3>

      <div class="prompt-detail-box">
        <div><strong>${escHtml(p.app_label)}</strong> <span class="mono">(UID ${p.uid})</span></div>
        <div class="mono" style="font-size:11.5px;color:var(--text-muted);margin-bottom:6px">${escHtml(p.package_name)}</div>
        <div class="mono" style="color:var(--accent-primary);font-weight:700">${escHtml(p.resource_title)}</div>
        <div style="font-size:11.5px;color:var(--text-secondary);margin-top:4px">${escHtml(p.detail)}</div>
      </div>

      <div class="prompt-choices">
        <button class="btn btn-ok" data-prompt-dec="allow_once">${escHtml(t('promptAllowOnce'))}</button>
        <button class="btn btn-primary" data-prompt-dec="allow_always">${escHtml(t('promptAllowAlways'))}</button>
        <button class="btn btn-warn" data-prompt-dec="spoof">${escHtml(t('promptSpoofInstead'))}</button>
        <button class="btn btn-danger" data-prompt-dec="deny">${escHtml(t('promptDenySilent'))}</button>
      </div>
    `;

    backdrop.classList.add('open');

    sheet.querySelectorAll('[data-prompt-dec]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const decision = btn.dataset.promptDec;
        await SentinelBridge.rpc('resolve_prompt', { prompt_id: p.id, decision });
        backdrop.classList.remove('open');
        state.activePromptId = null;
        await refreshSnapshot();
      });
    });
  }

  function renderAll() {
    renderHeroAndSubsystems();
    renderAppsList();
    renderEventStream();
    renderFirewallAndIpcTab();
    renderSpoofAndProxyTab();
    renderSystemTab();
    checkAndRenderInteractivePrompts();
  }

  async function refreshSnapshot() {
    const [st, dash] = await Promise.all([
      SentinelBridge.rpc('status', {}),
      SentinelBridge.rpc('dashboard', { limit: 80 })
    ]);
    if (st && st.ok) state.status = st;
    if (dash && dash.ok) {
      state.snapshot = dash;
      renderAll();
    }
  }

  /* ---- Event Listeners & Initialization ---- */
  function bindGlobalEvents() {
    /* Navigation Dock */
    document.querySelectorAll('[data-nav]').forEach((btn) => {
      btn.addEventListener('click', () => {
        state.activeTab = btn.dataset.nav;
        document.querySelectorAll('[data-nav]').forEach((b) => b.classList.toggle('active', b === btn));
        document.querySelectorAll('.view-pane').forEach((v) => {
          v.classList.toggle('active', v.id === `view-${state.activeTab}`);
        });
      });
    });

    /* Design Switcher */
    document.querySelectorAll('[data-theme-pick]').forEach((btn) => {
      btn.addEventListener('click', () => {
        state.design = btn.dataset.themePick;
        localStorage.setItem('sentinel_design', state.design);
        applyDesignAndLanguage();
      });
    });

    /* Language Switcher */
    document.querySelectorAll('[data-lang-pick]').forEach((btn) => {
      btn.addEventListener('click', () => {
        state.lang = btn.dataset.langPick;
        localStorage.setItem('sentinel_lang', state.lang);
        applyDesignAndLanguage();
      });
    });

    /* Global Profile */
    document.querySelectorAll('[data-profile]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        await SentinelBridge.rpc('set_global', { global_profile: Number(btn.dataset.profile) });
        showToast(t('toastSaved'));
        await refreshSnapshot();
      });
    });

    /* Screen-Off / Deep Sleep Toggle */
    document.getElementById('btn-toggle-sleep').addEventListener('click', async () => {
      const next = !(state.snapshot && state.snapshot.screen_sleeping);
      await SentinelBridge.rpc('set_global', { screen_sleeping: next });
      showToast(next ? 'Deep Sleep active: sockets severed' : 'Screen awake: normal policy');
      await refreshSnapshot();
    });

    /* Trigger Interactive Android 17 Permission Prompt */
    document.getElementById('btn-trigger-prompt').addEventListener('click', async () => {
      await SentinelBridge.rpc('trigger_prompt', {
        uid: 10318,
        package_name: 'com.alibaba.aliexpresshd',
        category: CAT.NETWORK,
        resource_title: 'TCP Connect -> acs.aliexpress.com:443',
        detail: 'Blocked sandboxed app requested external network socket while in background',
        is_background: true
      });
      await refreshSnapshot();
    });

    /* Search & Show System Apps */
    document.getElementById('app-search-input').addEventListener('input', (e) => {
      state.searchQuery = e.target.value.trim();
      renderAppsList();
      renderEventStream();
    });

    document.getElementById('chk-system-apps').addEventListener('change', async (e) => {
      await SentinelBridge.rpc('set_global', { show_system_apps: e.target.checked });
      await refreshSnapshot();
    });

    /* Clear Stream */
    document.getElementById('btn-clear-events').addEventListener('click', async () => {
      await SentinelBridge.rpc('clear_events', {});
      await refreshSnapshot();
    });

    /* Save Sleep Config */
    document.getElementById('btn-save-sleep').addEventListener('click', async () => {
      await SentinelBridge.rpc('set_global', {
        sleep_mode: Number(document.getElementById('sel-sleep-mode').value),
        sleep_grace_sec: Number(document.getElementById('sel-sleep-grace').value)
      });
      showToast(t('toastSaved'));
      await refreshSnapshot();
    });

    /* Add IPC Matrix Rule */
    document.getElementById('btn-add-ipc-rule').addEventListener('click', async () => {
      const caller = document.getElementById('ipc-caller').value.trim() || '*';
      const target = document.getElementById('ipc-target').value.trim() || '*';
      const action = document.getElementById('ipc-action').value.trim() || '*';
      const comp = document.getElementById('ipc-comp').value;
      await SentinelBridge.rpc('add_ipc_rule', {
        caller_pkg: caller,
        target_pkg: target,
        action_glob: action,
        component_type: comp,
        allow: false
      });
      showToast(t('toastSaved'));
      await refreshSnapshot();
    });

    /* Inspect Compiled Kernel iptables & IntentFirewall XML */
    document.getElementById('btn-inspect-rules').addEventListener('click', async () => {
      const box = document.getElementById('compiled-rules-box');
      if (box.style.display === 'block') {
        box.style.display = 'none';
        return;
      }
      const res = await SentinelBridge.rpc('inspect_rules', {});
      if (res && res.ok) {
        box.textContent = `### Backend: ${res.backend}\n\n${res.firewall_script}\n\n### /data/system/ifw/privacy_sentinel.xml\n\n${res.ifw_xml}`;
        box.style.display = 'block';
      }
    });

    /* Rotate Master Seed */
    document.getElementById('btn-rotate-seed').addEventListener('click', async () => {
      await SentinelBridge.rpc('rotate_seed', {});
      showToast(t('toastSaved'));
      await refreshSnapshot();
    });

    /* Save Per-App SOCKS5 Proxy */
    document.getElementById('btn-save-proxy').addEventListener('click', async () => {
      await SentinelBridge.rpc('set_proxy', {
        enabled: document.getElementById('chk-proxy-enable').checked,
        socks5_host: document.getElementById('inp-proxy-host').value.trim(),
        socks5_port: Number(document.getElementById('inp-proxy-port').value),
        username: document.getElementById('inp-proxy-user').value.trim(),
        password: document.getElementById('inp-proxy-pass').value,
        block_quic: document.getElementById('chk-proxy-quic').checked,
        block_ipv6: document.getElementById('chk-proxy-ipv6').checked
      });
      showToast(t('toastSaved'));
      await refreshSnapshot();
    });

    /* Manual Token Submit */
    document.getElementById('btn-submit-token').addEventListener('click', async () => {
      const val = document.getElementById('inp-manual-token').value;
      SentinelBridge.setManualToken(val);
      const st = await SentinelBridge.rpc('status', {});
      if (st && st.ok) {
        document.getElementById('token-modal-backdrop').classList.remove('open');
        await refreshSnapshot();
        SentinelBridge.startLiveStream((snap) => {
          state.snapshot = snap;
          renderAll();
        });
      }
    });

    /* Android Back / Escape closes modals cleanly */
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        document.getElementById('app-drawer-backdrop').classList.remove('open');
      }
    });
  }

  async function boot() {
    mountStaticIllustrations();
    bindGlobalEvents();
    applyDesignAndLanguage();

    const init = await SentinelBridge.initialize(() => {
      document.getElementById('token-modal-backdrop').classList.add('open');
    });

    if (init.ok) {
      await refreshSnapshot();
      SentinelBridge.startLiveStream((snap) => {
        state.snapshot = snap;
        renderAll();
      });
      /* Fallback poll if in ksu_native mode (no SSE socket needed) */
      if (SentinelBridge.mode === 'ksu_native') {
        setInterval(refreshSnapshot, 2200);
      }
    }
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
