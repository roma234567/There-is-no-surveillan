/* ============================================================================
 * Privacy Sentinel — Dual-Transport Communication Bridge
 *
 * Transport A (Primary inside BakaSU / KernelSU Manager / KsuWebUI):
 *   Uses injected window.ksu.exec() to invoke /data/adb/modules/privacy_sentinel/bin/sentinelctl
 *   over UNIX domain socket (/data/adb/privacy_sentinel/run/sentinel.sock).
 *   -> Zero open ports required, immune to Android 17 USE_LOOPBACK_INTERFACE!
 *
 * Transport B (Local REST + Server-Sent Events on 127.0.0.1:18917):
 *   Protected by 256-bit X-Sentinel-Token:
 *   - Option A (per user spec): auto-retrieved via ksu.exec inside Manager,
 *     or prompted when opened from external browser (with preview handshake support).
 * ============================================================================ */

class SentinelTransportBridge {
  constructor() {
    this.mode = 'detecting'; // 'ksu_native' | 'http_rest'
    this.token = sessionStorage.getItem('sentinel_token') || '';
    this.ctlBin = '/data/adb/modules/privacy_sentinel/bin/sentinelctl';
    this.sse = null;
  }

  hasKsuNativeBridge() {
    return typeof window.ksu === 'object' && window.ksu !== null && typeof window.ksu.exec === 'function';
  }

  ksuExecPromise(cmd) {
    return new Promise((resolve) => {
      try {
        const cbName = `__sentinel_cb_${Date.now()}_${Math.random().toString(36).slice(2)}`;
        window[cbName] = (errno, stdout, stderr) => {
          delete window[cbName];
          resolve({ errno: Number(errno), stdout: stdout || '', stderr: stderr || '' });
        };
        const maybePromise = window.ksu.exec(cmd, '{}', cbName);
        if (maybePromise && typeof maybePromise.then === 'function') {
          maybePromise.then((res) => {
            if (window[cbName]) {
              delete window[cbName];
              resolve(res);
            }
          }).catch((err) => {
            delete window[cbName];
            resolve({ errno: 1, stdout: '', stderr: String(err) });
          });
        }
      } catch (e) {
        resolve({ errno: 1, stdout: '', stderr: String(e) });
      }
    });
  }

  async initialize(onTokenPromptNeeded) {
    /* 1. Try KernelSU / BakaSU / KsuWebUI native JS bridge first */
    if (this.hasKsuNativeBridge()) {
      const tokRes = await this.ksuExecPromise(`${this.ctlBin} token`);
      if (tokRes.errno === 0 && tokRes.stdout.includes('"ok":true')) {
        try {
          const parsed = JSON.parse(tokRes.stdout.trim());
          if (parsed.token) {
            this.token = parsed.token;
            sessionStorage.setItem('sentinel_token', this.token);
          }
        } catch (_) {}
      }
      const stRes = await this.ksuExecPromise(`${this.ctlBin} status`);
      if (stRes.errno === 0 && stRes.stdout.includes('"ok":true')) {
        this.mode = 'ksu_native';
        return { ok: true, mode: this.mode };
      }
    }

    /* 2. HTTP REST + SSE mode (check preview handshake or stored token) */
    this.mode = 'http_rest';
    if (!this.token) {
      try {
        const pre = await fetch('/api/v1/preview-handshake', { cache: 'no-store' });
        if (pre.ok) {
          const data = await pre.json();
          if (data.ok && data.token) {
            this.token = data.token;
            sessionStorage.setItem('sentinel_token', this.token);
          }
        }
      } catch (_) {}
    }

    if (this.token) {
      const check = await this.httpCall('status', {});
      if (check && check.ok) {
        return { ok: true, mode: this.mode };
      }
    }

    if (typeof onTokenPromptNeeded === 'function') {
      onTokenPromptNeeded();
    }
    return { ok: false, mode: this.mode, needsAuth: true };
  }

  setManualToken(tok) {
    this.token = (tok || '').trim();
    sessionStorage.setItem('sentinel_token', this.token);
  }

  async rpc(cmd, payload = {}) {
    if (this.mode === 'ksu_native') {
      const jsonArg = JSON.stringify({ cmd, ...payload }).replace(/'/g, `'\\''`);
      const res = await this.ksuExecPromise(`${this.ctlBin} rpc '${jsonArg}'`);
      if (res.errno === 0 && res.stdout) {
        try {
          return JSON.parse(res.stdout.trim());
        } catch (_) {}
      }
    }
    return this.httpCall(cmd, payload);
  }

  async httpCall(cmd, payload = {}) {
    try {
      const resp = await fetch(`/api/v1/${cmd}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Sentinel-Token': this.token
        },
        body: JSON.stringify(payload),
        cache: 'no-store'
      });
      if (resp.status === 401) {
        return { ok: false, unauthorized: true };
      }
      return await resp.json();
    } catch (e) {
      return { ok: false, error: String(e) };
    }
  }

  startLiveStream(onSnapshot) {
    this.stopLiveStream();
    if (this.mode === 'http_rest' && typeof EventSource !== 'undefined' && this.token) {
      try {
        const es = new EventSource(`/api/v1/stream?token=${encodeURIComponent(this.token)}`);
        es.addEventListener('snapshot', (ev) => {
          try {
            const data = JSON.parse(ev.data);
            if (data && data.ok) onSnapshot(data);
          } catch (_) {}
        });
        es.onerror = () => {
          es.close();
          this.sse = null;
        };
        this.sse = es;
      } catch (_) {}
    }
  }

  stopLiveStream() {
    if (this.sse) {
      this.sse.close();
      this.sse = null;
    }
  }
}

window.SentinelBridge = new SentinelTransportBridge();
