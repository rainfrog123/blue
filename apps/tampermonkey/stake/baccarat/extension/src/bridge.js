'use strict';

/** postMessage ↔ isolated content.js (debugger, storage, HUD bus). */
(function (SB) {
    const HUD_STORE_KEY = 'sb-play-hud';
    const HUD_WIDTH = 400;
    const HUD_HEIGHT = 440;
    const HUD_SIZE_GEN = 2;
    const SIDE_ENGINES = ['math', 'crypto', 'fair', 'mix', 'shuffle'];
    const WALLET_VALUE_SELS = [
        '[data-testid="wallet-balance-value"] span',
        '[data-testid="wallet-mobile-balance"] [data-testid="wallet-mobile-value"] span',
        '[data-testid="wallet-mobile-balance-value"] span',
    ];

    SB.HUD_STORE_KEY = HUD_STORE_KEY;
    SB.HUD_WIDTH = HUD_WIDTH;
    SB.HUD_HEIGHT = HUD_HEIGHT;
    SB.HUD_SIZE_GEN = HUD_SIZE_GEN;
    SB.SIDE_ENGINES = SIDE_ENGINES;
    SB.WALLET_VALUE_SELS = WALLET_VALUE_SELS;

    SB.moneyFromText = (text) => {
        const n = parseFloat(String(text || '').replace(/[^0-9.]/g, ''));
        return Number.isFinite(n) ? n : 0;
    };

    SB.readDomWallet = () => {
        for (const sel of WALLET_VALUE_SELS) {
            const el = document.querySelector(sel);
            if (!el?.textContent) continue;
            const n = SB.moneyFromText(el.textContent);
            if (n > 0) return n;
        }
        return 0;
    };

    SB.normalizeSideEngine = (raw) => {
        const s = String(raw || 'math').toLowerCase();
        return SIDE_ENGINES.includes(s) ? s : 'math';
    };

    SB.extCall = (type, extra = {}) => new Promise((resolve) => {
        const id = `sb-${type}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const onMsg = (e) => {
            const d = e.data;
            if (!d || d.source !== 'sb-ext' || d.id !== id) return;
            window.removeEventListener('message', onMsg);
            resolve({ ok: !!d.ok, data: d.data, error: d.error || null });
        };
        window.addEventListener('message', onMsg);
        window.postMessage({ source: 'sb-page', type, id, ...extra }, '*');
        setTimeout(() => {
            window.removeEventListener('message', onMsg);
            resolve({ ok: false, data: null, error: 'timeout' });
        }, type === 'attachDebugger' ? 4000 : 2500);
    });

    SB.hudBusSend = (payload) => {
        try {
            window.postMessage({
                source: 'sb-page',
                type: 'hudBus',
                id: `sb-bus-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
                payload,
            }, '*');
        } catch (_) {}
    };

    SB.defaultHudStore = () => ({
        side: 'random',
        mode: 'paroli',
        hunt: 'concurrent',
        rng: 'math',
        min: false,
        left: '',
        top: '12px',
        width: 400,
        height: 440,
        sizeGen: 2,
    });

    SB.migrateLocalHud = (store) => {
        const next = { ...store };
        try {
            const hunt = localStorage.getItem('sb-play-hud-hunt');
            if (hunt === 'serial' || hunt === 'concurrent') next.hunt = hunt;
            const rng = localStorage.getItem('sb-play-hud-rng');
            if (rng) next.rng = SB.normalizeSideEngine(rng);
            if (localStorage.getItem('sb-play-hud-min') === '1') next.min = true;
            const pos = JSON.parse(localStorage.getItem('sb-play-hud-pos') || 'null');
            if (pos?.left) next.left = pos.left;
            if (pos?.top) next.top = pos.top;
            const side = localStorage.getItem('sb-play-hud-side');
            if (side === 'P' || side === 'B' || side === 'random') next.side = side;
            const mode = localStorage.getItem('sb-play-hud-mode');
            if (mode === 'paroli' || mode === 'martingale') next.mode = mode;
        } catch (_) {}
        return next;
    };

    SB.readHudStore = async () => {
        const res = await SB.extCall('storageGet', { keys: [HUD_STORE_KEY] });
        const raw = res.ok && res.data ? res.data[HUD_STORE_KEY] : null;
        const base = SB.defaultHudStore();
        const merged = raw && typeof raw === 'object' ? { ...base, ...raw } : SB.migrateLocalHud(base);
        merged.rng = SB.normalizeSideEngine(merged.rng);
        if (merged.side !== 'P' && merged.side !== 'B') merged.side = 'random';
        if (merged.mode !== 'martingale') merged.mode = 'paroli';
        if (merged.hunt !== 'serial') merged.hunt = 'concurrent';
        const w = parseInt(merged.width, 10);
        const h = parseInt(merged.height, 10);
        const gen = parseInt(merged.sizeGen, 10);
        if (gen !== HUD_SIZE_GEN) {
            merged.width = HUD_WIDTH;
            merged.height = HUD_HEIGHT;
            merged.sizeGen = HUD_SIZE_GEN;
        } else {
            merged.width = Number.isFinite(w) && w >= 280 ? Math.min(2400, w) : HUD_WIDTH;
            merged.height = Number.isFinite(h) && h >= 200 ? Math.min(2000, h) : HUD_HEIGHT;
        }
        return merged;
    };

    SB.writeHudStore = async (patch) => {
        const cur = await SB.readHudStore();
        const next = { ...cur, ...patch };
        await SB.extCall('storageSet', { data: { [HUD_STORE_KEY]: next } });
        return next;
    };

    SB.bindHudResize = (host, wrap, opts) => {
        const minW = 320;
        const minH = 200;
        ['e', 's', 'se'].forEach((edge) => {
            const el = document.createElement('div');
            el.className = 'rsz ' + edge;
            el.title = 'Drag to resize';
            wrap.appendChild(el);
            el.addEventListener('mousedown', (e) => {
                if (opts.isCollapsed()) return;
                e.preventDefault();
                e.stopPropagation();
                const r = host.getBoundingClientRect();
                const start = { x: e.clientX, y: e.clientY, w: r.width, h: r.height, left: r.left, top: r.top };
                const move = (ev) => {
                    let w = start.w;
                    let h = start.h;
                    if (edge.indexOf('e') !== -1) w = start.w + (ev.clientX - start.x);
                    if (edge.indexOf('s') !== -1) h = start.h + (ev.clientY - start.y);
                    const maxW = Math.max(minW, window.innerWidth - start.left - 8);
                    const maxH = Math.max(minH, window.innerHeight - start.top - 8);
                    w = Math.round(Math.min(maxW, Math.max(minW, w)));
                    h = Math.round(Math.min(maxH, Math.max(minH, h)));
                    host.style.width = w + 'px';
                    host.style.height = h + 'px';
                    host.style.maxHeight = 'none';
                    wrap.style.minHeight = '0';
                    wrap.style.height = '100%';
                };
                const up = () => {
                    window.removeEventListener('mousemove', move);
                    window.removeEventListener('mouseup', up);
                    const box = host.getBoundingClientRect();
                    opts.onSave({
                        width: Math.round(box.width),
                        height: Math.round(box.height),
                    });
                };
                window.addEventListener('mousemove', move);
                window.addEventListener('mouseup', up);
            });
        });
    };

    SB.storeToConfigPatch = (store) => ({
        SIDE: store.side === 'P' || store.side === 'B' ? store.side : null,
        PROGRESSION_MODE: store.mode === 'martingale' ? 'martingale' : 'paroli',
        CONCURRENT: store.hunt !== 'serial',
        RANDOM_SIDE_ENGINE: SB.normalizeSideEngine(store.rng),
    });
})(window.__SB);
