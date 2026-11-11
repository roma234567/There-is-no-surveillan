/* ============================================================================
 * Privacy Sentinel v2.0 — Pure Mobile Native Controller (Vanilla JS, 120Hz)
 * ============================================================================ */

(() => {
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
    dashSub: 'apps',
    fwSub: 'sleep',
    spSub: 'antispy',
    activeCategory: 0,
    searchQuery: '',
    selectedGrace: 15,
    status: null,
    snapshot: null,
    sparkTotal: [8, 11, 10, 13, 14, 16, 15, 18, 19, 21, 22, 24],
    sparkBlocked: [3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11],
    lastTotalEvents: 0,
    lastBlockedEvents: 0,
    openDrawerUid: null,
    activePromptId: null,
    dirtyFormLockUntil: 0
  };

  const t = (key) => (window.SentinelI18n[state.lang] && window.SentinelI18n[state.lang][key]) || key;

  function escHtml(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function isUserEditingForm() {
    if (Date.now() < state.dirtyFormLockUntil) return true;
    const el = document.activeElement;
    if (!el) return false;
    const tag = el.tagName;
    return (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') && el.id !== 'app-search-input';
  }

  function showToast(msg) {
    const el = document.getElementById('toast-banner');
    if (!el) return;
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(showToast._tid);
    showToast._tid = setTimeout(() => el.classList.remove('show'), 2000);
  }

  function mountStaticIllustrations() {
    document.getElementById('brand-crest-slot').innerHTML = SentinelSVG.brandCrest();
    document.getElementById('btn-quick-theme').innerHTML = SentinelSVG.themeContrast();
    document.getElementById('hero-radar-slot').innerHTML = SentinelSVG.tacticalRadar();
    document.getElementById('sleep-ic-slot').innerHTML = SentinelSVG.moonState();
    document.getElementById('search-ic-slot').innerHTML = SentinelSVG.searchLens();
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

    const quickLangBtn = document.getElementById('btn-quick-lang');
    if (quickLangBtn) quickLangBtn.textContent = state.lang.toUpperCase();

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
    if (state.snapshot) renderAll(true);
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

  function renderHeroAndSubsystems() {
    const snap = state.snapshot;
    if (!snap) return;

    document.getElementById('kpi-events').textContent = snap.total_events.toLocaleString();
    document.getElementById('kpi-blocked').textContent = snap.total_blocked.toLocaleString();
    document.getElementById('kpi-spoofed').textContent = snap.total_spoofed.toLocaleString();
    document.getElementById('kpi-ring').textContent = `${snap.ring_used}/${(snap.ring_capacity / 1000).toFixed(0)}k`;

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

    document.querySelectorAll('[data-profile]').forEach((b) => {
      b.classList.toggle('active', Number(b.dataset.profile) === snap.global_profile);
    });

    const sleepBtn = document.getElementById('btn-toggle-sleep');
    const sleepLbl = document.getElementById('sleep-btn-label');
    sleepBtn.classList.toggle('m-btn-primary', !!snap.screen_sleeping);
    sleepLbl.textContent = snap.screen_sleeping ? t('btnSleepSimOn') : t('btnSleepSimOff');
    document.getElementById('chk-system-apps').checked = !!snap.show_system_apps;

    const proxyOn = state.status && state.status.proxy && state.status.proxy.enabled;
    const subSlot = document.getElementById('subsystem-tiles-slot');
    subSlot.innerHTML = `
      <div class="m-sub-tile">
        <div class="m-sub-top">${SentinelSVG.catNetwork()}<span class="m-dot">${escHtml(t('stateActive'))}</span></div>
        <strong style="font-size:12px">${escHtml(t('subNetfilter'))}</strong>
        <span class="m-p m-mono" style="font-size:10.5px">SENTINEL_OUT • 5.10</span>
      </div>
      <div class="m-sub-tile">
        <div class="m-sub-top">${SentinelSVG.catSandbox()}<span class="m-dot">${escHtml(t('stateActive'))}</span></div>
        <strong style="font-size:12px">${escHtml(t('subZygisk'))}</strong>
        <span class="m-p m-mono" style="font-size:10.5px">PLT • MountNS • PIF</span>
      </div>
      <div class="m-sub-tile">
        <div class="m-sub-top">${SentinelSVG.catIpc()}<span class="m-dot">${escHtml(t('stateActive'))}</span></div>
        <strong style="font-size:12px">${escHtml(t('subVector'))}</strong>
        <span class="m-p m-mono" style="font-size:10.5px">AMS • IFW • ZeroPCM</span>
      </div>
      <div class="m-sub-tile">
        <div class="m-sub-top">${SentinelSVG.catProxy()}<span class="m-dot ${proxyOn ? '' : 'standby'}">${escHtml(proxyOn ? t('stateActive') : t('stateStandby'))}</span></div>
        <strong style="font-size:12px">${escHtml(t('subProxy'))}</strong>
        <span class="m-p m-mono" style="font-size:10.5px">${proxyOn ? escHtml(`${state.status.proxy.socks5_host}:${state.status.proxy.socks5_port}`) : '127.0.0.1:9050'}</span>
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
    document.getElementById('cnt-apps-pill').textContent = String(apps.length);

    container.innerHTML = apps.map((app) => {
      const isZeroTouch = (app.flags & POL.EXEMPT_ZERO_TOUCH) !== 0;
      const c = app.counts || {};
      const isSandboxed = (app.flags & (POL.SANDBOX_FS_L1 | POL.SANDBOX_KERNEL_L2)) !== 0;
      const isProxied = (app.flags & POL.ROUTE_PROXY) !== 0;
      const netBlocked = (app.flags & POL.BLOCK_NETWORK) !== 0;
      const askOn = (app.flags & POL.ASK_INTERACTIVE) !== 0;

      const plaques = isZeroTouch
        ? `<span class="t-chip sandbox hot">${SentinelSVG.zeroTouchSeal()}<span>${escHtml(t('zeroTouchBadge'))}</span></span>`
        : `
          <span class="t-chip net ${c.network > 0 ? 'hot' : ''}">${SentinelSVG.catNetwork()}<span>${escHtml(t('badgeNet'))}</span><b>${c.network || 0}</b></span>
          <span class="t-chip data ${c.data > 0 ? 'hot' : ''}">${SentinelSVG.catData()}<span>${escHtml(t('badgeData'))}</span><b>${c.data || 0}</b></span>
          <span class="t-chip auto ${c.autostart > 0 ? 'hot' : ''}">${SentinelSVG.catAutostart()}<span>${escHtml(t('badgeAuto'))}</span><b>${c.autostart || 0}</b></span>
          <span class="t-chip ipc ${c.ipc > 0 ? 'hot' : ''}">${SentinelSVG.catIpc()}<span>${escHtml(t('badgeIpc'))}</span><b>${c.ipc || 0}</b></span>
          <span class="t-chip danger ${c.danger > 0 ? 'hot' : ''}">${SentinelSVG.catDanger()}<span>${escHtml(t('badgeDanger'))}</span><b>${c.danger || 0}</b></span>
          ${isSandboxed ? `<span class="t-chip sandbox hot">${SentinelSVG.catSandbox()}<span>${escHtml(t('badgeSandbox'))}</span></span>` : ''}
          ${isProxied ? `<span class="t-chip proxy hot">${SentinelSVG.catProxy()}<span>${escHtml(t('badgeProxy'))}</span></span>` : ''}
        `;

      return `
        <article class="m-app-card" data-uid="${app.uid}">
          <div class="m-app-top">
            <div class="m-app-ident" ${!isZeroTouch ? `data-open-dossier="${app.uid}"` : ''}>
              ${SentinelSVG.appAvatar(app.package_name, app.label, isZeroTouch)}
              <div class="m-app-meta">
                <div class="m-app-name-row">
                  <span class="m-app-name">${escHtml(app.label)}</span>
                  <span class="m-badge-mini ${app.proc_state === 'FG' ? 'fg' : ''}">${escHtml(app.proc_state)}</span>
                  <span class="m-badge-mini">${app.uid}</span>
                </div>
                <div class="m-app-pkg">${escHtml(app.package_name)}</div>
              </div>
            </div>
            ${!isZeroTouch ? `
              <button class="m-icon-btn" data-open-dossier="${app.uid}" aria-label="${escHtml(t('btnConfigureApp'))}">
                ${SentinelSVG.tuneSliders()}
              </button>
            ` : ''}
          </div>

          <div class="m-plaques">${plaques}</div>

          ${!isZeroTouch ? `
          <div class="m-app-bar">
            <button class="m-pill-toggle ${netBlocked ? 'on-block' : ''}" data-pill-flag="${POL.BLOCK_NETWORK}" data-uid="${app.uid}">
              ${escHtml(t('quickNetBlock'))}
            </button>
            <button class="m-pill-toggle ${askOn ? 'on-ask' : ''}" data-pill-flag="${POL.ASK_INTERACTIVE}" data-uid="${app.uid}">
              ${escHtml(t('quickAskMode'))}
            </button>
            <button class="m-btn m-btn-sm m-btn-danger" data-kill-sock="${app.uid}">
              ${SentinelSVG.boltSever()}
              <span>${escHtml(t('btnSeverSockets'))}</span>
            </button>
          </div>` : ''}
        </article>
      `;
    }).join('');

    container.querySelectorAll('[data-open-dossier]').forEach((el) => {
      el.addEventListener('click', () => openAppDossier(Number(el.dataset.openDossier)));
    });

    container.querySelectorAll('[data-pill-flag]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const uid = Number(btn.dataset.uid);
        const bit = Number(btn.dataset.pillFlag);
        const app = state.snapshot.apps.find((a) => a.uid === uid);
        if (!app) return;
        const nextFlags = (app.flags & bit) ? (app.flags & ~bit) : (app.flags | bit);
        await SentinelBridge.rpc('update_app', { uid, flags: nextFlags });
        showToast(t('toastSaved'));
        await refreshSnapshot();
      });
    });

    container.querySelectorAll('[data-kill-sock]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const uid = Number(btn.dataset.killSock);
        const r = await SentinelBridge.rpc('kill_sockets', { uid });
        showToast(`SOCK_DESTROY: ${r.sockets_killed ?? 0}`);
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

    document.getElementById('cnt-stream-pill').textContent = String(events.length);

    feed.innerHTML = events.slice(0, 50).map((ev) => {
      const act = actionMeta(ev.action);
      const dt = new Date(ev.ts).toLocaleTimeString();
      return `
        <div class="m-ev-card" data-ev-uid="${ev.uid}">
          <div class="m-ev-top">
            <span class="m-ev-type">${categoryIcon(ev.category)}<span>${escHtml(ev.type)}</span></span>
            <span class="m-ev-act ${act.cls}">${escHtml(act.label)}</span>
          </div>
          <div class="m-ev-target">${escHtml(ev.target)}</div>
          <div class="m-ev-foot">
            <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(ev.pkg)} (${ev.uid}${ev.is_bg ? '•BG' : ''})</span>
            <span class="m-mono">#${ev.seq} • ${dt}</span>
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

  function renderFirewallAndIpcTab(forceFormSync = false) {
    const snap = state.snapshot;
    if (!snap) return;

    if (forceFormSync || !isUserEditingForm()) {
      document.getElementById('sel-sleep-mode').value = String(snap.sleep_mode);
      state.selectedGrace = Number(snap.sleep_grace_sec ?? 15);
      document.querySelectorAll('[data-grace]').forEach((b) => {
        b.classList.toggle('active', Number(b.dataset.grace) === state.selectedGrace);
      });
    }

    const sleepList = document.getElementById('sleep-apps-checklist');
    const userApps = (snap.apps || []).filter((a) => !a.is_system && !(a.flags & POL.EXEMPT_ZERO_TOUCH));
    sleepList.innerHTML = userApps.map((a) => `
      <label class="m-check-item">
        <div class="m-check-left">
          ${SentinelSVG.appAvatar(a.package_name, a.label, false)}
          <div class="m-app-meta">
            <div class="m-app-name">${escHtml(a.label)}</div>
            <div class="m-app-pkg">UID ${a.uid} • ${escHtml(a.package_name)}</div>
          </div>
        </div>
        <input type="checkbox" class="m-switch" data-sleep-uid="${a.uid}" ${(a.flags & POL.SLEEP_SELECTED) ? 'checked' : ''} />
      </label>
    `).join('');

    sleepList.querySelectorAll('[data-sleep-uid]').forEach((chk) => {
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

    const rulesList = document.getElementById('ipc-rules-list');
    const rules = snap.ipc_rules || [];
    if (rules.length === 0) {
      rulesList.innerHTML = `<div class="m-card m-p" style="text-align:center">${escHtml(t('ipcEmptyHint'))}</div>`;
    } else {
      rulesList.innerHTML = rules.map((r) => `
        <div class="m-rule-card">
          <div class="m-rule-body">
            <div class="m-rule-flow">${escHtml(r.caller_pkg)} &rarr; ${escHtml(r.target_pkg)}</div>
            <div class="m-rule-sub">${escHtml(r.component_type.toUpperCase())} • ${escHtml(r.action_glob)}</div>
          </div>
          <button class="m-icon-btn m-btn-danger" data-del-ipc="${escHtml(r.id)}" aria-label="Delete">
            ${SentinelSVG.trashBin()}
          </button>
        </div>
      `).join('');

      rulesList.querySelectorAll('[data-del-ipc]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          await SentinelBridge.rpc('delete_ipc_rule', { id: btn.dataset.delIpc });
          await refreshSnapshot();
        });
      });
    }
  }

  function renderSpoofAndProxyTab(forceFormSync = false) {
    const snap = state.snapshot;
    if (!snap) return;

    if (state.status) {
      document.getElementById('seed-badge').textContent =
        `Seed: 0x${Number(state.status.master_seed || 0).toString(16).toUpperCase()}`;

      if (forceFormSync || !isUserEditingForm()) {
        const p = state.status.proxy || {};
        document.getElementById('chk-proxy-enable').checked = !!p.enabled;
        document.getElementById('inp-proxy-host').value = p.socks5_host || '127.0.0.1';
        document.getElementById('inp-proxy-port').value = p.socks5_port || 9050;
        document.getElementById('chk-proxy-quic').checked = p.block_quic !== false;
        document.getElementById('chk-proxy-ipv6').checked = p.block_ipv6 !== false;
      }
    }

    const userApps = (snap.apps || []).filter((a) => !a.is_system && !(a.flags & POL.EXEMPT_ZERO_TOUCH));

    if (forceFormSync || !isUserEditingForm()) {
      const spoofList = document.getElementById('spoof-apps-list');
      spoofList.innerHTML = userApps.map((a) => {
        let curMode = 'off';
        if (a.flags & POL.SPOOF_CUSTOM) curMode = 'custom';
        else if (a.flags & POL.SPOOF_EPHEMERAL) curMode = 'ephemeral';
        else if (a.flags & POL.SPOOF_DETERMINISTIC) curMode = 'deterministic';

        return `
          <div class="m-card" style="padding:11px 12px">
            <div class="m-app-top" style="margin-bottom:8px">
              <div class="m-check-left" data-open-spoof-dossier="${a.uid}" style="cursor:pointer">
                ${SentinelSVG.appAvatar(a.package_name, a.label, false)}
                <div class="m-app-meta">
                  <div class="m-app-name">${escHtml(a.label)}</div>
                  <div class="m-app-pkg">${escHtml(a.package_name)}</div>
                </div>
              </div>
              <button class="m-icon-btn" data-open-spoof-dossier="${a.uid}">${SentinelSVG.tuneSliders()}</button>
            </div>
            <select class="m-input" data-spoof-sel="${a.uid}">
              <option value="off" ${curMode === 'off' ? 'selected' : ''}>${escHtml(t('spoofModeOff'))}</option>
              <option value="deterministic" ${curMode === 'deterministic' ? 'selected' : ''}>${escHtml(t('spoofModeDet'))}</option>
              <option value="ephemeral" ${curMode === 'ephemeral' ? 'selected' : ''}>${escHtml(t('spoofModeEph'))}</option>
              <option value="custom" ${curMode === 'custom' ? 'selected' : ''}>${escHtml(t('spoofModeCustom'))}</option>
            </select>
          </div>
        `;
      }).join('');

      spoofList.querySelectorAll('[data-open-spoof-dossier]').forEach((el) => {
        el.addEventListener('click', () => openAppDossier(Number(el.dataset.openSpoofDossier)));
      });

      spoofList.querySelectorAll('[data-spoof-sel]').forEach((sel) => {
        sel.addEventListener('focus', () => { state.dirtyFormLockUntil = Date.now() + 4000; });
        sel.addEventListener('change', async () => {
          state.dirtyFormLockUntil = 0;
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
    }

    const proxyGrid = document.getElementById('proxy-apps-checklist');
    proxyGrid.innerHTML = userApps.map((a) => `
      <label class="m-check-item">
        <div class="m-check-left">
          ${SentinelSVG.appAvatar(a.package_name, a.label, false)}
          <div class="m-app-meta">
            <div class="m-app-name">${escHtml(a.label)}</div>
            <div class="m-app-pkg">SOCKS5 • UID ${a.uid}</div>
          </div>
        </div>
        <input type="checkbox" class="m-switch" data-proxy-uid="${a.uid}" ${(a.flags & POL.ROUTE_PROXY) ? 'checked' : ''} />
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
      { name: 'BakaSU + SuSFS', note: 'Kernel root + automatic ksu_susfs path cloaking' },
      { name: 'Zygisk Next (API v5)', note: 'Native PLT hooks + SCM_RIGHTS policy.mmap' },
      { name: 'Vector (LibXposed API 102)', note: 'Protective hooks + hot-reload + system_server IPC' },
      { name: 'PIF v4.9 & Tricky Store', note: 'Zero-Touch DLCLOSE on GMS, Vending & target.txt' },
      { name: 'OverlayFS Metamodule', note: 'skip_mount active — zero /system edits' },
      { name: 'ViPER4Android', note: 'AudioTrack/Effect untouched; only BG AudioRecord muted' },
      { name: 'YABP Watchdog', note: '3-strike post-fs-data bootloop failsafe' }
    ];

    document.getElementById('compat-matrix-slot').innerHTML = modules.map((m) => `
      <div class="m-rule-card">
        <div class="m-rule-body">
          <div style="font-size:13px;font-weight:700">${escHtml(m.name)}</div>
          <div class="m-p" style="font-size:11.5px;margin-top:2px">${escHtml(m.note)}</div>
        </div>
        <span class="m-dot">${escHtml(t('compatOk'))}</span>
      </div>
    `).join('');

    const transportMode = SentinelBridge.mode === 'ksu_native'
      ? 'ksu.exec -> sentinelctl (UNIX Socket, Zero Port)'
      : '127.0.0.1 HTTP/SSE + 256-bit X-Sentinel-Token';

    document.getElementById('security-details-slot').innerHTML = `
      <div class="m-rule-card">
        <div class="m-rule-body">
          <div style="font-size:12.5px;font-weight:700">WebUI Transport</div>
          <div class="m-p m-mono" style="font-size:11px;margin-top:2px">${escHtml(transportMode)}</div>
        </div>
      </div>
      <div class="m-rule-card">
        <div class="m-rule-body">
          <div style="font-size:12.5px;font-weight:700">Android 17 MemoryLimiter Exemption</div>
          <div class="m-p" style="font-size:11.5px;margin-top:2px">sentineld UID 0 (oom_score_adj -900) outside UID &ge; 10000 cgroup limits</div>
        </div>
      </div>
      <div class="m-rule-card">
        <div class="m-rule-body">
          <div style="font-size:12.5px;font-weight:700">Firewall Engine (garnet • 5.10)</div>
          <div class="m-p m-mono" style="font-size:11px;margin-top:2px">${escHtml((state.status && state.status.fw_backend) || 'iptables-xtables (SENTINEL_*)')}</div>
        </div>
      </div>
    `;
  }

  /* ---- Native Bottom Sheet: Per-App Policy Dossier ---- */
  function openAppDossier(uid) {
    const app = state.snapshot && state.snapshot.apps.find((a) => a.uid === uid);
    if (!app) return;
    state.openDrawerUid = uid;

    const sheet = document.getElementById('app-drawer-sheet');
    const flagRow = (bit, labelKey) => `
      <label class="m-switch-row">
        <span>${escHtml(t(labelKey))}</span>
        <input type="checkbox" class="m-switch" data-drawer-bit="${bit}" ${(app.flags & bit) ? 'checked' : ''} />
      </label>
    `;

    sheet.innerHTML = `
      <div class="m-sheet-handle"></div>
      <div class="m-app-top" style="margin-bottom:10px">
        <div class="m-check-left">
          ${SentinelSVG.appAvatar(app.package_name, app.label, false)}
          <div class="m-app-meta">
            <div class="m-app-name">${escHtml(app.label)} <span class="m-badge-mini">UID ${app.uid}</span></div>
            <div class="m-app-pkg">${escHtml(app.package_name)}</div>
          </div>
        </div>
        <button class="m-btn m-btn-sm" id="btn-close-drawer">${escHtml(t('btnClose'))}</button>
      </div>

      <div class="m-lbl" style="margin-top:8px;color:var(--accent-primary)">${escHtml(t('secNetSandbox'))}</div>
      ${flagRow(POL.BLOCK_NETWORK, 'optBlockNet')}
      ${flagRow(POL.SLEEP_SELECTED, 'optSleepMember')}
      ${flagRow(POL.SANDBOX_FS_L1, 'optSandboxL1')}
      ${flagRow(POL.SANDBOX_KERNEL_L2, 'optSandboxL2')}
      ${flagRow(POL.ASK_INTERACTIVE, 'optAskPrompt')}
      ${flagRow(POL.STRICT_KILLSWITCH, 'optKillSwitch')}

      <div class="m-lbl" style="margin-top:12px;color:var(--accent-primary)">${escHtml(t('secIpcRules'))}</div>
      ${flagRow(POL.BLOCK_BG_IPC, 'optBlockBgIpc')}
      ${flagRow(POL.BLOCK_AUTOSTART, 'optBlockAutostart')}
      ${flagRow(POL.IPC_REJECT_EXPLICIT, 'optExplicitReject')}

      <div class="m-lbl" style="margin-top:12px;color:var(--accent-primary)">${escHtml(t('secSpoofSpy'))}</div>
      ${flagRow(POL.ANTISPY_BG_MIC_CAM, 'optBgMicCam')}
      ${flagRow(POL.ANTISPY_BG_CLIP, 'optBgClip')}
      ${flagRow(POL.TRAP_ROOT_SCAN, 'optTrapRoot')}
      ${flagRow(POL.ROUTE_PROXY, 'optRouteProxy')}

      <div class="m-stack-fields" style="margin-top:12px">
        <div class="m-row-2">
          <div>
            <label class="m-lbl">IMEI</label>
            <input id="drw-imei" class="m-input m-mono" value="${escHtml(app.custom_imei)}" />
          </div>
          <div>
            <label class="m-lbl">MAC</label>
            <input id="drw-mac" class="m-input m-mono" value="${escHtml(app.custom_mac)}" />
          </div>
        </div>
        <div class="m-row-2">
          <div>
            <label class="m-lbl">GPS Lat</label>
            <input id="drw-lat" type="number" step="0.0001" class="m-input m-mono" value="${app.custom_lat}" />
          </div>
          <div>
            <label class="m-lbl">GPS Lon</label>
            <input id="drw-lon" type="number" step="0.0001" class="m-input m-mono" value="${app.custom_lon}" />
          </div>
        </div>
      </div>

      <button class="m-btn m-btn-primary m-btn-block" style="margin-top:14px" id="btn-save-drawer">
        ${escHtml(t('btnSaveApp'))}
      </button>
    `;

    const backdrop = document.getElementById('app-drawer-backdrop');
    backdrop.classList.add('open');

    document.getElementById('btn-close-drawer').onclick = () => {
      backdrop.classList.remove('open');
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
      backdrop.classList.remove('open');
      state.openDrawerUid = null;
      showToast(t('toastSaved'));
      await refreshSnapshot(true);
    };
  }

  /* ---- Real-Time Android 17 System Permission Prompt Sheet ---- */
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
      <div class="m-sheet-handle"></div>
      ${SentinelSVG.permissionGuardian()}
      <span class="m-ver" style="display:inline-block;margin-bottom:6px">${escHtml(t('promptHeader'))} • <span id="prompt-rem-sec">${Math.ceil((p.remaining_ms || 9000) / 1000)}s</span></span>
      <h3 class="m-h2">${escHtml(t('promptQuestion'))}</h3>

      <div class="m-prompt-box">
        <div><strong>${escHtml(p.app_label)}</strong> <span class="m-mono">(UID ${p.uid})</span></div>
        <div class="m-mono" style="font-size:11px;color:var(--text-muted);margin-bottom:6px">${escHtml(p.package_name)}</div>
        <div class="m-mono" style="color:var(--accent-primary);font-weight:700;word-break:break-all">${escHtml(p.resource_title)}</div>
        <div style="font-size:11.5px;color:var(--text-secondary);margin-top:4px">${escHtml(p.detail)}</div>
      </div>

      <div class="m-prompt-actions">
        <button class="m-btn m-btn-ok m-btn-block" data-prompt-dec="allow_once">${escHtml(t('promptAllowOnce'))}</button>
        <button class="m-btn m-btn-primary m-btn-block" data-prompt-dec="allow_always">${escHtml(t('promptAllowAlways'))}</button>
        <button class="m-btn m-btn-warn m-btn-block" data-prompt-dec="spoof">${escHtml(t('promptSpoofInstead'))}</button>
        <button class="m-btn m-btn-danger m-btn-block" data-prompt-dec="deny">${escHtml(t('promptDenySilent'))}</button>
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

  function renderAll(forceFormSync = false) {
    renderHeroAndSubsystems();
    renderAppsList();
    renderEventStream();
    renderFirewallAndIpcTab(forceFormSync);
    renderSpoofAndProxyTab(forceFormSync);
    renderSystemTab();
    checkAndRenderInteractivePrompts();
  }

  async function refreshSnapshot(forceFormSync = false) {
    const [st, dash] = await Promise.all([
      SentinelBridge.rpc('status', {}),
      SentinelBridge.rpc('dashboard', { limit: 80 })
    ]);
    if (st && st.ok) state.status = st;
    if (dash && dash.ok) {
      state.snapshot = dash;
      renderAll(forceFormSync);
    }
  }

  function bindSubSwitcher(attr, stateProp, prefix) {
    document.querySelectorAll(`[${attr}]`).forEach((btn) => {
      btn.addEventListener('click', () => {
        const val = btn.getAttribute(attr);
        state[stateProp] = val;
        document.querySelectorAll(`[${attr}]`).forEach((b) => b.classList.toggle('active', b === btn));
        document.querySelectorAll(`[id^="${prefix}-"]`).forEach((pane) => {
          pane.classList.toggle('active', pane.id === `${prefix}-${val}`);
        });
      });
    });
  }

  function bindGlobalEvents() {
    /* Bottom Navigation */
    document.querySelectorAll('[data-nav]').forEach((btn) => {
      btn.addEventListener('click', () => {
        state.activeTab = btn.dataset.nav;
        document.querySelectorAll('[data-nav]').forEach((b) => b.classList.toggle('active', b === btn));
        document.querySelectorAll('.m-pane').forEach((v) => {
          v.classList.toggle('active', v.id === `view-${state.activeTab}`);
        });
        window.scrollTo({ top: 0, behavior: 'instant' });
      });
    });

    /* Mobile Sub-Tab Switchers */
    bindSubSwitcher('data-dash-sub', 'dashSub', 'dash-sub');
    bindSubSwitcher('data-fw-sub', 'fwSub', 'fw-sub');
    bindSubSwitcher('data-sp-sub', 'spSub', 'sp-sub');

    /* Header 1-Tap Theme & Language Toggles */
    document.getElementById('btn-quick-theme').addEventListener('click', () => {
      state.design = state.design === 'obsidian' ? 'ceramic' : 'obsidian';
      localStorage.setItem('sentinel_design', state.design);
      applyDesignAndLanguage();
    });

    document.getElementById('btn-quick-lang').addEventListener('click', () => {
      state.lang = state.lang === 'ru' ? 'en' : 'ru';
      localStorage.setItem('sentinel_lang', state.lang);
      applyDesignAndLanguage();
    });

    /* System Tab Theme & Language Cards */
    document.querySelectorAll('[data-theme-pick]').forEach((btn) => {
      btn.addEventListener('click', () => {
        state.design = btn.dataset.themePick;
        localStorage.setItem('sentinel_design', state.design);
        applyDesignAndLanguage();
      });
    });

    document.querySelectorAll('[data-lang-pick]').forEach((btn) => {
      btn.addEventListener('click', () => {
        state.lang = btn.dataset.langPick;
        localStorage.setItem('sentinel_lang', state.lang);
        applyDesignAndLanguage();
      });
    });

    /* Global Security Profile */
    document.querySelectorAll('[data-profile]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        await SentinelBridge.rpc('set_global', { global_profile: Number(btn.dataset.profile) });
        showToast(t('toastSaved'));
        await refreshSnapshot();
      });
    });

    /* Sleep State Toggle */
    document.getElementById('btn-toggle-sleep').addEventListener('click', async () => {
      const next = !(state.snapshot && state.snapshot.screen_sleeping);
      await SentinelBridge.rpc('set_global', { screen_sleeping: next });
      showToast(next ? t('btnSleepSimOn') : t('btnSleepSimOff'));
      await refreshSnapshot();
    });

    /* Test Android 17 Interactive Prompt */
    document.getElementById('btn-trigger-prompt').addEventListener('click', async () => {
      await SentinelBridge.rpc('trigger_prompt', {
        uid: 10318,
        package_name: 'com.alibaba.aliexpresshd',
        category: CAT.NETWORK,
        resource_title: 'TCP -> acs.aliexpress.com:443',
        detail: 'Blocked background app requested external socket',
        is_background: true
      });
      await refreshSnapshot();
    });

    /* Search & System Apps */
    document.getElementById('app-search-input').addEventListener('input', (e) => {
      state.searchQuery = e.target.value.trim();
      renderAppsList();
      renderEventStream();
    });

    document.getElementById('chk-system-apps').addEventListener('change', async (e) => {
      await SentinelBridge.rpc('set_global', { show_system_apps: e.target.checked });
      await refreshSnapshot();
    });

    /* Clear Telemetry Stream */
    document.getElementById('btn-clear-events').addEventListener('click', async () => {
      await SentinelBridge.rpc('clear_events', {});
      await refreshSnapshot();
    });

    /* Grace Delay Segmented Buttons */
    document.querySelectorAll('[data-grace]').forEach((btn) => {
      btn.addEventListener('click', () => {
        state.dirtyFormLockUntil = Date.now() + 5000;
        state.selectedGrace = Number(btn.dataset.grace);
        document.querySelectorAll('[data-grace]').forEach((b) => b.classList.toggle('active', b === btn));
      });
    });

    document.getElementById('sel-sleep-mode').addEventListener('focus', () => {
      state.dirtyFormLockUntil = Date.now() + 5000;
    });

    /* Save Sleep Policy */
    document.getElementById('btn-save-sleep').addEventListener('click', async () => {
      state.dirtyFormLockUntil = 0;
      await SentinelBridge.rpc('set_global', {
        sleep_mode: Number(document.getElementById('sel-sleep-mode').value),
        sleep_grace_sec: state.selectedGrace
      });
      showToast(t('toastSaved'));
      await refreshSnapshot(true);
    });

    /* Add IPC Rule */
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
      document.getElementById('ipc-caller').value = '';
      document.getElementById('ipc-target').value = '';
      showToast(t('toastSaved'));
      await refreshSnapshot(true);
    });

    /* Inspect Kernel Rules */
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
      await refreshSnapshot(true);
    });

    /* Save SOCKS5 Proxy */
    document.getElementById('btn-save-proxy').addEventListener('click', async () => {
      state.dirtyFormLockUntil = 0;
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
      await refreshSnapshot(true);
    });

    /* Manual Token Submit */
    document.getElementById('btn-submit-token').addEventListener('click', async () => {
      const val = document.getElementById('inp-manual-token').value;
      SentinelBridge.setManualToken(val);
      const st = await SentinelBridge.rpc('status', {});
      if (st && st.ok) {
        document.getElementById('token-modal-backdrop').classList.remove('open');
        await refreshSnapshot(true);
        SentinelBridge.startLiveStream((snap) => {
          state.snapshot = snap;
          renderAll();
        });
      }
    });

    /* Tap outside bottom sheet closes App Dossier cleanly */
    const appBackdrop = document.getElementById('app-drawer-backdrop');
    appBackdrop.addEventListener('click', (e) => {
      if (e.target === appBackdrop) {
        appBackdrop.classList.remove('open');
        state.openDrawerUid = null;
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
      await refreshSnapshot(true);
      SentinelBridge.startLiveStream((snap) => {
        state.snapshot = snap;
        renderAll();
      });
      if (SentinelBridge.mode === 'ksu_native') {
        setInterval(() => refreshSnapshot(false), 2200);
      }
    }
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
