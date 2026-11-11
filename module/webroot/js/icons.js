/* ============================================================================
 * Privacy Sentinel — Custom Multi-Layered SVG Illustrations & Vector Artwork
 * 100% Bespoke Inline SVGs — Zero Emojis, Zero External Font Dependencies
 * ============================================================================ */

window.SentinelSVG = {
  /* Brand Shield Crest */
  brandCrest: () => `
    <svg class="svg-illust svg-crest" viewBox="0 0 48 48" fill="none" aria-hidden="true">
      <rect x="2" y="2" width="44" height="44" rx="12" fill="var(--surface-elevated)" stroke="var(--border-strong)" stroke-width="1.2"/>
      <path d="M24 7L10 13V23.2C10 32.3 16 40.4 24 42.6C32 40.4 38 32.3 38 23.2V13L24 7Z" fill="var(--accent-soft)" stroke="var(--accent-primary)" stroke-width="1.7"/>
      <circle cx="24" cy="23.5" r="6.2" stroke="var(--text-primary)" stroke-width="1.6"/>
      <circle cx="24" cy="23.5" r="2.3" fill="var(--status-ok)"/>
      <path d="M24 13.5V17.2M24 29.8V33.5M14.2 23.5H17.8M30.2 23.5H33.8" stroke="var(--text-secondary)" stroke-width="1.4" stroke-linecap="round"/>
    </svg>`,

  /* POCO X6 5G (garnet) Hardware Silhouette */
  deviceGarnet: () => `
    <svg class="svg-illust svg-device" viewBox="0 0 40 40" fill="none" aria-hidden="true">
      <rect x="10" y="3" width="20" height="34" rx="4" fill="var(--surface-subtle)" stroke="var(--border-strong)" stroke-width="1.5"/>
      <rect x="12.5" y="6.5" width="15" height="10" rx="2" fill="var(--accent-soft)" stroke="var(--accent-primary)" stroke-width="1.1"/>
      <circle cx="16" cy="9.8" r="1.4" fill="var(--text-primary)"/>
      <circle cx="16" cy="13.4" r="1.4" fill="var(--text-primary)"/>
      <circle cx="20.2" cy="11.6" r="1.1" fill="var(--status-ok)"/>
      <path d="M14 23H26M14 27H22" stroke="var(--text-muted)" stroke-width="1.3" stroke-linecap="round"/>
      <rect x="17" y="33.5" width="6" height="1.4" rx="0.7" fill="var(--text-secondary)"/>
    </svg>`,

  /* Radar Tactical Graphic (Dashboard Hero) */
  tacticalRadar: () => `
    <svg class="svg-radar" viewBox="0 0 120 120" fill="none" aria-hidden="true">
      <circle cx="60" cy="60" r="52" fill="var(--surface-subtle)" stroke="var(--border-subtle)" stroke-width="1.2"/>
      <circle cx="60" cy="60" r="37" stroke="var(--border-subtle)" stroke-width="1" stroke-dasharray="3 3"/>
      <circle cx="60" cy="60" r="21" stroke="var(--border-strong)" stroke-width="1"/>
      <path d="M60 8V112M8 60H112" stroke="var(--border-subtle)" stroke-width="1"/>
      <path class="radar-sector" d="M60 60L60 8A52 52 0 0 1 104 32Z" fill="var(--accent-soft)"/>
      <line class="radar-needle" x1="60" y1="60" x2="98" y2="28" stroke="var(--accent-primary)" stroke-width="1.8" stroke-linecap="round"/>
      <circle cx="79" cy="37" r="3.2" fill="var(--status-warn)"/>
      <circle cx="42" cy="44" r="2.8" fill="var(--status-ok)"/>
      <circle cx="74" cy="78" r="3.4" fill="var(--status-danger)"/>
      <circle cx="60" cy="60" r="4" fill="var(--text-primary)"/>
    </svg>`,

  /* Threat Category 1: Network & Pre-DoH DNS */
  catNetwork: () => `
    <svg class="svg-badge-art" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="8.5" stroke="currentColor" stroke-width="1.6"/>
      <ellipse cx="12" cy="12" rx="4" ry="8.5" stroke="currentColor" stroke-width="1.4"/>
      <path d="M4.2 9.5H19.8M4.2 14.5H19.8" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
      <circle cx="18.2" cy="6.2" r="2.3" fill="var(--surface-card)" stroke="currentColor" stroke-width="1.4"/>
    </svg>`,

  /* Threat Category 2: Data Collection (Clipboard, Contacts, Sensors, Logs) */
  catData: () => `
    <svg class="svg-badge-art" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect x="4.5" y="4" width="15" height="16.5" rx="2.8" stroke="currentColor" stroke-width="1.6"/>
      <path d="M9 4V6.2H15V4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      <path d="M8.2 10.5H15.8M8.2 14H13.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      <circle cx="15.8" cy="15.8" r="2.1" stroke="currentColor" stroke-width="1.4"/>
    </svg>`,

  /* Threat Category 3: Autostart (BOOT_COMPLETED, FGS, JobScheduler) */
  catAutostart: () => `
    <svg class="svg-badge-art" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M19.2 10.2A7.6 7.6 0 0 0 6.3 7.1L4.5 9" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
      <path d="M4.5 5.2V9H8.3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
      <path d="M4.8 13.8A7.6 7.6 0 0 0 17.7 16.9L19.5 15" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
      <path d="M19.5 18.8V15H15.7" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
      <path d="M12.5 8.8L10.3 12.3H13.5L11.5 15.4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`,

  /* Threat Category 4: IPC & Binder Cross-App Calls */
  catIpc: () => `
    <svg class="svg-badge-art" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect x="3" y="5" width="6.5" height="6.5" rx="1.8" stroke="currentColor" stroke-width="1.6"/>
      <rect x="14.5" y="12.5" width="6.5" height="6.5" rx="1.8" stroke="currentColor" stroke-width="1.6"/>
      <path d="M9.5 8.2H14.2C15.9 8.2 17.2 9.5 17.2 11.2V12.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      <path d="M14.5 15.8H9.8C8.1 15.8 6.8 14.5 6.8 12.8V11.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-dasharray="2 2"/>
      <circle cx="12" cy="12" r="1.6" fill="currentColor"/>
    </svg>`,

  /* Threat Category 5: Dangerous / Root Probe / BG Mic & Camera / Accessibility */
  catDanger: () => `
    <svg class="svg-badge-art" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 3.6L20.6 18.6C21.1 19.5 20.5 20.6 19.5 20.6H4.5C3.5 20.6 2.9 19.5 3.4 18.6L12 3.6Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
      <path d="M12 9.4V13.8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
      <circle cx="12" cy="17" r="1.1" fill="currentColor"/>
    </svg>`,

  /* Threat Category 6: Kernel Mount Namespace Sandbox */
  catSandbox: () => `
    <svg class="svg-badge-art" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 3.2L20 7.7V16.3L12 20.8L4 16.3V7.7L12 3.2Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
      <path d="M4 7.7L12 12.2L20 7.7M12 12.2V20.8" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>
      <rect x="9.5" y="6.2" width="5" height="3" rx="0.8" fill="currentColor" fill-opacity="0.22"/>
    </svg>`,

  /* Threat Category 7: Per-App SOCKS5 / Tor Relay */
  catProxy: () => `
    <svg class="svg-badge-art" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M4 12C4 7.6 7.6 4 12 4C16.4 4 20 7.6 20 12C20 16.4 16.4 20 12 20" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
      <path d="M7.5 12C7.5 9.5 9.5 7.5 12 7.5C14.5 7.5 16.5 9.5 16.5 12C16.5 14.5 14.5 16.5 12 16.5" stroke="currentColor" stroke-width="1.4" stroke-dasharray="2.5 2"/>
      <path d="M4 16.5L8.5 16.5L6.8 14.5M4 16.5L6.8 18.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
      <circle cx="12" cy="12" r="1.8" fill="currentColor"/>
    </svg>`,

  /* Zero-Touch PIF / Tricky Store Verified Shield */
  zeroTouchSeal: () => `
    <svg class="svg-badge-art" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 3L5 6.2V11.8C5 16.5 8 20.6 12 21.8C16 20.6 19 16.5 19 11.8V6.2L12 3Z" stroke="currentColor" stroke-width="1.6"/>
      <path d="M8.8 12.2L11 14.4L15.4 9.8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`,

  /* Deep Sleep / Screen-Off Socket Sever Illustration */
  deepSleepWave: () => `
    <svg class="svg-illust" viewBox="0 0 36 36" fill="none" aria-hidden="true">
      <rect x="2" y="2" width="32" height="32" rx="10" fill="var(--surface-subtle)" stroke="var(--border-subtle)"/>
      <path d="M21.5 9.5A8.2 8.2 0 1 0 26.5 22.8A6.6 6.6 0 0 1 21.5 9.5Z" stroke="var(--accent-primary)" stroke-width="1.7" stroke-linejoin="round"/>
      <path d="M9 26L14.5 26M21.5 26H27M16.5 23.8L19.5 28.2M19.5 23.8L16.5 28.2" stroke="var(--status-warn)" stroke-width="1.5" stroke-linecap="round"/>
    </svg>`,

  /* Anti-Spy Mic & Camera Guard Illustration */
  antiSpyShutter: () => `
    <svg class="svg-illust" viewBox="0 0 36 36" fill="none" aria-hidden="true">
      <rect x="2" y="2" width="32" height="32" rx="10" fill="var(--surface-subtle)" stroke="var(--border-subtle)"/>
      <rect x="9" y="11" width="11" height="14" rx="2.5" stroke="var(--text-primary)" stroke-width="1.5"/>
      <circle cx="14.5" cy="18" r="2.6" stroke="var(--accent-primary)" stroke-width="1.4"/>
      <path d="M24.5 12.5V19.5A2.5 2.5 0 0 1 22 22" stroke="var(--text-secondary)" stroke-width="1.5" stroke-linecap="round"/>
      <line x1="8" y1="27" x2="28" y2="9" stroke="var(--status-danger)" stroke-width="1.8" stroke-linecap="round"/>
    </svg>`,

  /* Android 17 System Permission Guardian Modal Artwork */
  permissionGuardian: () => `
    <svg class="svg-prompt-hero" viewBox="0 0 72 72" fill="none" aria-hidden="true">
      <rect x="6" y="6" width="60" height="60" rx="18" fill="var(--surface-subtle)" stroke="var(--border-strong)" stroke-width="1.4"/>
      <path d="M36 14L18 21.5V34.8C18 46.2 25.6 56.2 36 59C46.4 56.2 54 46.2 54 34.8V21.5L36 14Z" fill="var(--accent-soft)" stroke="var(--accent-primary)" stroke-width="2"/>
      <circle cx="36" cy="33" r="6" stroke="var(--text-primary)" stroke-width="1.8"/>
      <path d="M36 39V45" stroke="var(--text-primary)" stroke-width="2" stroke-linecap="round"/>
      <circle cx="51" cy="21" r="6" fill="var(--status-warn)"/>
      <path d="M51 18.2V21.5M51 23.8H51.02" stroke="#111318" stroke-width="1.8" stroke-linecap="round"/>
    </svg>`,

  /* Navigation Dock SVGs */
  navRadar: () => `
    <svg class="nav-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="8.5" stroke="currentColor" stroke-width="1.7"/>
      <circle cx="12" cy="12" r="4.2" stroke="currentColor" stroke-width="1.4" stroke-dasharray="2.5 2"/>
      <path d="M12 12L17.6 6.4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
      <circle cx="12" cy="12" r="1.8" fill="currentColor"/>
    </svg>`,

  navFirewall: () => `
    <svg class="nav-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 3.2L4.5 6.5V12.2C4.5 16.9 7.7 21.1 12 22.3C16.3 21.1 19.5 16.9 19.5 12.2V6.5L12 3.2Z" stroke="currentColor" stroke-width="1.7"/>
      <path d="M8.5 11.5H15.5M8.5 15H13" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
    </svg>`,

  navSpoof: () => `
    <svg class="nav-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M7.5 8.5C7.5 6 9.5 4 12 4C14.5 4 16.5 6 16.5 8.5C16.5 11 14.5 13 12 13" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>
      <path d="M5 18.5C6.4 15.8 9 14.2 12 14.2C15 14.2 17.6 15.8 19 18.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>
      <path d="M9.5 8.8C9.5 7.4 10.6 6.3 12 6.3C13.4 6.3 14.5 7.4 14.5 8.8" stroke="currentColor" stroke-width="1.4" stroke-dasharray="2 2"/>
    </svg>`,

  navSystem: () => `
    <svg class="nav-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect x="4" y="4" width="7" height="7" rx="2" stroke="currentColor" stroke-width="1.7"/>
      <rect x="13" y="4" width="7" height="7" rx="2" stroke="currentColor" stroke-width="1.7"/>
      <rect x="4" y="13" width="7" height="7" rx="2" stroke="currentColor" stroke-width="1.7"/>
      <circle cx="16.5" cy="16.5" r="3.5" stroke="currentColor" stroke-width="1.7"/>
    </svg>`,

  /* Mobile UI Micro-Illustrations (Zero Font Icons) */
  themeContrast: () => `
    <svg class="ui-svg" viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <circle cx="10" cy="10" r="7.2" stroke="currentColor" stroke-width="1.6"/>
      <path d="M10 2.8A7.2 7.2 0 0 1 10 17.2V2.8Z" fill="currentColor"/>
    </svg>`,

  searchLens: () => `
    <svg class="ui-svg" viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <circle cx="9" cy="9" r="5.6" stroke="currentColor" stroke-width="1.6"/>
      <path d="M13.2 13.2L16.8 16.8" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>
    </svg>`,

  tuneSliders: () => `
    <svg class="ui-svg" viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <path d="M3.5 6H16.5M3.5 14H16.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
      <circle cx="7.5" cy="6" r="2.2" fill="var(--surface-card)" stroke="currentColor" stroke-width="1.6"/>
      <circle cx="12.5" cy="14" r="2.2" fill="var(--surface-card)" stroke="currentColor" stroke-width="1.6"/>
    </svg>`,

  trashBin: () => `
    <svg class="ui-svg" viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <path d="M4.5 6H15.5M8 6V4.4C8 4 8.4 3.6 8.8 3.6H11.2C11.6 3.6 12 4 12 4.4V6M6.2 6L6.8 15.4C6.8 16 7.3 16.5 8 16.5H12C12.7 16.5 13.2 16 13.2 15.4L13.8 6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`,

  boltSever: () => `
    <svg class="ui-svg" viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <path d="M11 2.8L5.2 10.6H10L9 17.2L14.8 9.4H10L11 2.8Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
    </svg>`,

  moonState: () => `
    <svg class="ui-svg" viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <path d="M12.6 3.4A6.4 6.4 0 1 0 16.6 13.2A5.1 5.1 0 0 1 12.6 3.4Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
    </svg>`,

  /* Deterministic Bespoke SVG Package Avatar Generator */
  appAvatar: (pkgName, label, isZeroTouch) => {
    let hash = 0;
    const str = pkgName || label || 'app';
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    const palettes = [
      ['#3A5A78', '#6B93B8'],
      ['#3D6B58', '#6BA38B'],
      ['#6E5438', '#B0895E'],
      ['#59486E', '#8E78AA'],
      ['#6B4246', '#A86E74'],
      ['#3F5E66', '#6D99A4']
    ];
    const [c1, c2] = isZeroTouch ? ['#2F6650', '#58A483'] : palettes[Math.abs(hash) % palettes.length];
    const initials = (label || pkgName || 'AP')
      .replace(/[^A-Za-zА-Яа-я0-9 ]/g, ' ')
      .trim()
      .split(/\s+/)
      .slice(0, 2)
      .map(w => w[0] ? w[0].toUpperCase() : '')
      .join('') || 'PS';

    const patternVariant = Math.abs(hash >> 3) % 3;
    let geo = '';
    if (patternVariant === 0) {
      geo = `<circle cx="34" cy="10" r="12" fill="${c2}" fill-opacity="0.22"/><path d="M4 34L20 22L40 36" stroke="${c2}" stroke-opacity="0.35" stroke-width="1.5"/>`;
    } else if (patternVariant === 1) {
      geo = `<rect x="24" y="-4" width="20" height="20" rx="5" transform="rotate(20 24 -4)" fill="${c2}" fill-opacity="0.22"/><circle cx="10" cy="34" r="9" stroke="${c2}" stroke-opacity="0.3" stroke-width="1.4"/>`;
    } else {
      geo = `<path d="M0 12H44M12 0V44" stroke="${c2}" stroke-opacity="0.18" stroke-width="1.2"/><circle cx="33" cy="33" r="10" fill="${c2}" fill-opacity="0.2"/>`;
    }

    return `
      <svg class="app-avatar-svg" viewBox="0 0 44 44" fill="none" aria-hidden="true">
        <rect width="44" height="44" rx="12" fill="${c1}"/>
        ${geo}
        <rect x="0.75" y="0.75" width="42.5" height="42.5" rx="11.25" stroke="#FFFFFF" stroke-opacity="0.14" stroke-width="1.5"/>
        <text x="22" y="26.5" text-anchor="middle" fill="#F6F8FA" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="14" font-weight="700" letter-spacing="0.5">${initials}</text>
      </svg>`;
  },

  /* Dynamic Smooth Sparkline SVG */
  sparkline: (points, blockedPoints) => {
    const w = 260, h = 58, pad = 5;
    const maxVal = Math.max(8, ...points, ...blockedPoints);
    const toCoords = (arr) => arr.map((v, idx) => {
      const x = pad + (idx / Math.max(1, arr.length - 1)) * (w - pad * 2);
      const y = h - pad - (v / maxVal) * (h - pad * 2);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    });
    const pAll = toCoords(points);
    const pBlk = toCoords(blockedPoints);
    const areaPath = `M ${pad},${h - pad} L ${pAll.join(' L ')} L ${w - pad},${h - pad} Z`;
    return `
      <svg class="sparkline-svg" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">
        <path d="${areaPath}" fill="var(--accent-soft)"/>
        <polyline points="${pAll.join(' ')}" fill="none" stroke="var(--accent-primary)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        <polyline points="${pBlk.join(' ')}" fill="none" stroke="var(--status-danger)" stroke-width="1.6" stroke-dasharray="3 2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>`;
  }
};
