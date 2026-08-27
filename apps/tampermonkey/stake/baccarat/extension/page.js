/*
 * Stake Baccarat — Chrome extension MAIN-world script (MV3).
 * Injected by manifest content_scripts at document_start (not Tampermonkey).
 *
 * v8.1.17 — Smaller HUD; log is the main pane (monospace). Old 760×560 size resets once.
 * v8.1.16 — Support popup: find OK by label, click through the HUD, retry if it stays.
 * v8.1.15 — HUD lives in the Multiplay iframe again (Stake only relays wallet).
 * v8.1.14 — HUD size: drag the right/bottom edges or the corner grip; saved with last-used settings.
 * v8.1.13 — HUD – collapses to the title bar only (no leftover min-height).
 * v8.1.12 — HUD on Stake (not the PP iframe); last-used Side/Mode/Hunt/RNG in chrome.storage; larger log.
 * v8.1.11 — HUD P/B random: Math.random, crypto bit, von Neumann, mix hash, shuffle 4+4.
 * v8.1.10 — $0.20 bets always arm the $0.20 chip first (never P/B while a $1 chip is still selected).
 * v8.1.9 — CDP Emulation.setFocusEmulationEnabled (same as DevTools “Emulate a focused page”).
 * v8.1.8 — stake ≥ $1: fill with $1 chips first, then $0.20 (never lead with $5 or $0.20).
 * v8.1.7 — always click the chip we need (ring is in the DOM even when unselected).
 * v8.1.6 — $1-min tables: raise stake to min and start with the $1 chip when stake ≥ $1.
 * v8.1.5 — concurrent: recalc 1-unit size from bankroll after every settled hand.
 * v8.1.4 — book the wire lpbet (not felt text); scoped focus mask; CDP re-attach on click miss.
 * v8.1.3 — wider HUD, selectable log, hunt switch (concurrent / one-by-one). Concurrent default.
 * v8.1.2 — top-up short chips immediately (do not wait 2s); watch leftover felt stake.
 * v8.1.1 — serial hunt again: one place, wait for result, then the next table.
 * v8.1.0 — concurrent hunt: keep placing on other tables while results settle.
 * v8.0.1 — confirm felt/wire before “placement failed” (CDP clicks are slower than dispatchEvent).
 * v8.0.0 — trusted clicks via extension debugger Input.dispatchMouseEvent.
 * v7.2.1 — Customer Support popup → OK, resume after iframe reload.
 * v7.2.0 — human-like click jitter (timing + point inside the button).
 * v7.1.9 — HUD says “1 unit”, not “1u”.
 * v7.1.8 — recalc unit (balance/8) at every Paroli/Martingale round reset to 1u.
 * v7.1.7 — greedy chip tray (0.2 / 1 / 5 / … whichever is enabled).
 * v7.1.6 — burst P/B clicks then top-up (betting window is ~1–2s).
 * v7.1.5 — lpbet amt is a running total (do not sum clicks; 0.8 was landing as 0.6).
 * v7.1.4 — always-focused mask on Stake + PP; HUD still multibaccarat-only.
 * v7.1.3 — click until wire stake matches (dropped $0.20 clicks).
 * v7.1.2 — after-T hunts every pp table, not pick.eligible().
 * v7.1.1 — HUD fits the viewport (scroll body, stay above PP footer).
 * v7.1.0 — bet only the next hand after a Tie (last road result === T).
 * v7.0.0 — single IIFE, three factories (pp → pick → play).
 * Snapshot: archive/2026-08-14-0437-stake-baccarat.js.bak
 * WS hook must run at document-start. Pick firewall unchanged.
 */

(function (global) {
    'use strict';

    const VERSION = '8.1.17';

    /**
     * Keep PP/Stake from pausing when the tab is in the background.
     * CDP clicks do not need the tab focused; the game still checks visibility.
     * Scope patches to this document only — do not touch Document.prototype or mouseleave.
     */
    const maskPageFocus = () => {
        const doc = document;
        const define = (obj, key, get) => {
            try {
                Object.defineProperty(obj, key, { configurable: true, get });
            } catch (_) {}
        };
        define(doc, 'visibilityState', () => 'visible');
        define(doc, 'webkitVisibilityState', () => 'visible');
        define(doc, 'hidden', () => false);
        define(doc, 'webkitHidden', () => false);
        try {
            Object.defineProperty(doc, 'hasFocus', {
                configurable: true,
                value: () => true,
            });
        } catch (_) {
            try { doc.hasFocus = () => true; } catch (_) {}
        }
        const silent = (e) => { e.stopImmediatePropagation(); };
        window.addEventListener('blur', silent, true);
        doc.addEventListener('visibilitychange', silent, true);
        doc.addEventListener('webkitvisibilitychange', silent, true);
        window.addEventListener('pagehide', silent, true);
        window.addEventListener('freeze', silent, true);
    };

    const isMultibaccarat = /pragmaticplaylive\.net\/desktop\/multibaccarat/i.test(String(location.href || ''));
    const isStakeHost = /(?:^|\.)stake\.com$/i.test(String(location.hostname || ''));
    const isTopWindow = window === window.top;

    maskPageFocus();
    try {
        window.postMessage({
            source: 'sb-page',
            type: 'attachDebugger',
            id: `sb-attach-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        }, '*');
    } catch (_) {}

    const extCall = (type, extra = {}) => new Promise((resolve) => {
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

    const hudBusSend = (payload) => {
        try {
            window.postMessage({
                source: 'sb-page',
                type: 'hudBus',
                id: `sb-bus-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
                payload,
            }, '*');
        } catch (_) {}
    };

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
    const moneyFromText = (text) => {
        const n = parseFloat(String(text || '').replace(/[^0-9.]/g, ''));
        return Number.isFinite(n) ? n : 0;
    };
    const readDomWallet = () => {
        for (const sel of WALLET_VALUE_SELS) {
            const el = document.querySelector(sel);
            if (!el?.textContent) continue;
            const n = moneyFromText(el.textContent);
            if (n > 0) return n;
        }
        return 0;
    };
    const normalizeSideEngine = (raw) => {
        const s = String(raw || 'math').toLowerCase();
        return SIDE_ENGINES.includes(s) ? s : 'math';
    };
    const defaultHudStore = () => ({
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
    const migrateLocalHud = (store) => {
        const next = { ...store };
        try {
            const hunt = localStorage.getItem('sb-play-hud-hunt');
            if (hunt === 'serial' || hunt === 'concurrent') next.hunt = hunt;
            const rng = localStorage.getItem('sb-play-hud-rng');
            if (rng) next.rng = normalizeSideEngine(rng);
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
    const readHudStore = async () => {
        const res = await extCall('storageGet', { keys: [HUD_STORE_KEY] });
        const raw = res.ok && res.data ? res.data[HUD_STORE_KEY] : null;
        const base = defaultHudStore();
        const merged = raw && typeof raw === 'object' ? { ...base, ...raw } : migrateLocalHud(base);
        merged.rng = normalizeSideEngine(merged.rng);
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
    const writeHudStore = async (patch) => {
        const cur = await readHudStore();
        const next = { ...cur, ...patch };
        await extCall('storageSet', { data: { [HUD_STORE_KEY]: next } });
        return next;
    };
    const bindHudResize = (host, wrap, opts) => {
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

    const storeToConfigPatch = (store) => ({
        SIDE: store.side === 'P' || store.side === 'B' ? store.side : null,
        PROGRESSION_MODE: store.mode === 'martingale' ? 'martingale' : 'paroli',
        CONCURRENT: store.hunt !== 'serial',
        RANDOM_SIDE_ENGINE: normalizeSideEngine(store.rng),
    });

    if (!isMultibaccarat) {
        if (isStakeHost && isTopWindow) {
            const kick = () => {
                setInterval(() => {
                    const bal = readDomWallet();
                    if (bal > 0) hudBusSend({ kind: 'wallet', balance: bal });
                }, 800);
            };
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', kick, { once: true });
            } else {
                kick();
            }
            global.sb = { version: VERSION, focusOnly: true, walletRelay: true };
            console.log(`[SB] v${VERSION} · extension · focus + wallet relay (${location.host})`);
        } else {
            global.sb = { version: VERSION, focusOnly: true };
            console.log(`[SB] v${VERSION} · extension · focus mask + CDP focus emulation (${location.host})`);
        }
        return;
    }

    const util = {
        displayName: (s) => String(s ?? '').replace(/_/g, ' '),
        sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
        money: moneyFromText,
        ensureDebugger: async () => !!(await extCall('attachDebugger')).ok,
        trustedClick: async (clientX, clientY, gapMs) =>
            !!(await extCall('trustedClick', { x: clientX, y: clientY, gapMs })).ok,
        click: async (el, opts = {}) => {
            if (!el) return false;
            const r = el.getBoundingClientRect();
            const padX = Math.min(8, r.width * 0.2);
            const padY = Math.min(8, r.height * 0.2);
            const spanX = Math.max(1, r.width - padX * 2);
            const spanY = Math.max(1, r.height - padY * 2);
            const clientX = r.left + padX + Math.random() * spanX;
            const clientY = r.top + padY + Math.random() * spanY;
            const screenX = clientX + (global.screenX || 0);
            const screenY = clientY + (global.screenY || 0);
            const gap = opts.eventGapMs != null
                ? opts.eventGapMs
                : (4 + Math.floor(Math.random() * 18));
            if (await util.trustedClick(clientX, clientY, gap)) return true;
            await util.ensureDebugger();
            if (await util.trustedClick(clientX, clientY, gap)) return true;
            if (!util._trustedFallbackWarned) {
                util._trustedFallbackWarned = true;
                console.warn('[SB] trusted CDP click failed — synthetic dispatchEvent fallback');
            }
            const shared = {
                bubbles: true,
                cancelable: true,
                composed: true,
                view: global,
                clientX,
                clientY,
                screenX,
                screenY,
                button: 0,
                which: 1,
                pointerId: 1,
                pointerType: 'mouse',
                isPrimary: true,
            };
            const fire = (type, extra) => {
                const init = { ...shared, ...extra };
                try {
                    if (typeof PointerEvent === 'function' && type.startsWith('pointer')) {
                        el.dispatchEvent(new PointerEvent(type, init));
                        return;
                    }
                } catch (_) {}
                el.dispatchEvent(new MouseEvent(type.startsWith('pointer') ? type.replace('pointer', 'mouse') : type, init));
            };
            fire('pointerover', { buttons: 0 });
            fire('mouseover', { buttons: 0 });
            fire('pointerdown', { buttons: 1 });
            fire('mousedown', { buttons: 1 });
            if (gap > 0) await util.sleep(gap);
            fire('pointerup', { buttons: 0 });
            fire('mouseup', { buttons: 0 });
            fire('click', { buttons: 0, detail: 1 });
            return true;
        },
        esc: (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
        }[c])),
        signed: (n, digits = 2) => {
            const v = Number(n) || 0;
            return `${v > 0 ? '+' : ''}${v.toFixed(digits)}`;
        },
    };

    const createPp = () => {

// Counter abbreviations used in this file:
    // P  = Player wins, B  = Banker wins, T  = Tie wins
    // PP = Player Pairs, BP = Banker Pairs

    const tables = new Map();           // gameId -> tableData
    const configs = new Map();          // gameId -> raw tableconfig
    const uidMap = new Map();           // uid -> gameId
    const idToUid = new Map();          // gameId -> uid
    const gameToLobby = new Map();      // gameId -> lobbyId (operator_game_id)
    const lobbyToGame = new Map();      // lobbyId -> gameId
    let nextUid = 1;
    let tablesOrder = [];
    let globalStats = null;
    let lastPlayersCount = null;
    let msgCount = 0;
    let lastSeq = 0;
    let suppressGoodRoadWarnings = true;

    /** Outgoing <lpbet> wire sends (for play.js / confirmations). */
    let lpbetCount = 0;
    let lastLpbetEvent = null;
    const lpbetHistory = [];
    const lpbetListeners = new Set();
    const LPBET_HISTORY_MAX = 40;

    const parseLpbetXml = (raw) => {
        const s = typeof raw === 'string' ? raw : '';
        if (!s.includes('lpbet')) return null;
        const ch = /channel="table-([^"]+)"/.exec(s);
        const tableId = ch ? ch[1] : null;
        const gM = /gId="([^"]+)"/.exec(s);
        const uM = /uId="([^"]+)"/.exec(s);
        const bets = [];
        const betRe = /<bet\s+([^>]+)\/?>/g;
        let bm;
        while ((bm = betRe.exec(s)) !== null) {
            const attrs = bm[1];
            const am = /amt="([^"]+)"/.exec(attrs);
            const bcm = /bc="([^"]+)"/.exec(attrs);
            if (am && bcm) {
                bets.push({
                    amt: parseFloat(am[1]),
                    bc: bcm[1],
                });
            }
        }
        if (!tableId && bets.length === 0) return null;
        return {
            tableId,
            gameId: gM ? gM[1] : null,
            userId: uM ? uM[1] : null,
            bets,
            time: Date.now(),
        };
    };

    const emitLpbet = (rec) => {
        if (!rec) return;
        lpbetCount++;
        lastLpbetEvent = rec;
        lpbetHistory.push(rec);
        if (lpbetHistory.length > LPBET_HISTORY_MAX) lpbetHistory.shift();
        for (const fn of lpbetListeners) {
            try {
                fn(rec);
            } catch (_) {}
        }
    };

    const hookOutgoingSend = (data) => {
        let s = '';
        if (typeof data === 'string') s = data;
        else if (data instanceof ArrayBuffer) s = new TextDecoder().decode(data);
        else if (ArrayBuffer.isView(data)) s = new TextDecoder().decode(data);
        else return;
        if (!s.includes('lpbet')) return;
        const rec = parseLpbetXml(s);
        if (rec && (rec.tableId || rec.gameId || rec.bets.length)) emitLpbet(rec);
    };

    /** On `betsopen`, delay before `pp.get(id).canBet === true`. */
    const CAN_BET_OPEN_DELAY_MS = 1000;

    const _consoleWarn = console.warn.__ppOriginalWarn || console.warn.bind(console);
    const isGoodRoadTablesOrderWarning = (args) => {
        const line = args.map((x) => {
            if (typeof x === 'string') return x;
            if (x && typeof x.message === 'string') return x.message;
            return '';
        }).join(' ');
        return line.includes('is not in tablesOrder') &&
               line.includes('GoodRoadGameCommunicationProcessor');
    };

    const ppWarnProxy = (...args) => {
        if (suppressGoodRoadWarnings && isGoodRoadTablesOrderWarning(args)) return;
        _consoleWarn(...args);
    };
    ppWarnProxy.__ppOriginalWarn = _consoleWarn;
    console.warn = ppWarnProxy;

    const bumpSeq = (seq) => {
        if (seq == null || seq === '') return;
        const n = typeof seq === 'string' ? parseInt(seq, 10) : seq;
        if (!Number.isFinite(n)) return;
        if (n > lastSeq) lastSeq = n;
    };

    const resolveGameId = (tableOrLobbyId) => {
        if (tableOrLobbyId == null) return null;
        const s = String(tableOrLobbyId);
        return lobbyToGame.get(s) || s;
    };

    const tableMatchLpbet = (rec, tableId) => {
        if (!rec) return false;
        const tid = resolveGameId(tableId) || String(tableId);
        const want = new Set([tid, String(tableId)].filter(Boolean));
        for (const c of [rec.tableId, rec.gameId]) {
            if (!c) continue;
            const rt = resolveGameId(c) || c;
            if (want.has(String(c)) || want.has(String(rt))) return true;
        }
        return false;
    };

    const stakeFromRecSide = (rec, side) => {
        const wantBc = side === 'B' ? '1' : '0';
        let s = 0;
        for (const b of rec.bets || []) {
            if (String(b.bc) === wantBc) s += Number(b.amt) || 0;
        }
        return s;
    };

    const lpbetStakeSince = (tableId, opts = {}) => {
        const since = opts.since ?? 0;
        const side = opts.side;
        const amounts = [];
        for (const rec of lpbetHistory) {
            if (!tableMatchLpbet(rec, tableId) || rec.time < since) continue;
            const a = stakeFromRecSide(rec, side);
            if (a > 0) amounts.push(a);
        }
        if (amounts.length === 0) return 0;
        const sum = amounts.reduce((s, x) => s + x, 0);
        const first = amounts[0];
        const last = amounts[amounts.length - 1];
        const grew = last > first + 1e-9;
        const nonDecreasing = amounts.every((a, i) => i === 0 || a + 1e-9 >= amounts[i - 1]);
        // Each click typically sends the *current* spot total (0.2, 0.4, 0.6…), not a chip delta.
        // Summing those stops one chip short (want $0.80, felt $0.60).
        if (grew && nonDecreasing) return last;
        return sum;
    };

    function patchTable(gameId, partial, bumpUpdates = true) {
        const gid = resolveGameId(gameId);
        if (!gid) return;

        const uid = assignUid(gid);
        const prev = tables.get(gid) || {};
        tables.set(gid, {
            ...prev,
            id: gid,
            gameId: gid,
            uid: prev.uid || uid,
            ...partial,
            updated: Date.now(),
            updates: bumpUpdates ? (prev.updates || 0) + 1 : (prev.updates || 0)
        });
    }

    // Assign simple numeric UID to table
    const assignUid = (gameId, forceUid = null) => {
        if (forceUid !== null) {
            // Reassign existing UID to new gameId
            const oldGameId = uidMap.get(forceUid);
            if (oldGameId && oldGameId !== gameId) {
                idToUid.delete(oldGameId);
            }
            uidMap.set(forceUid, gameId);
            idToUid.set(gameId, forceUid);
            return forceUid;
        }
        if (!idToUid.has(gameId)) {
            const uid = nextUid++;
            uidMap.set(uid, gameId);
            idToUid.set(gameId, uid);
        }
        return idToUid.get(gameId);
    };

    // Resolve uid, gameId, or lobbyId to gameId
    const resolveId = (uidOrId) => {
        if (typeof uidOrId === 'number') {
            // Could be UID or numeric lobby ID
            if (uidMap.has(uidOrId)) return uidMap.get(uidOrId);
            // Try as lobbyId string
            const strId = String(uidOrId);
            if (lobbyToGame.has(strId)) return lobbyToGame.get(strId);
            return null;
        }
        // String ID - could be gameId or lobbyId
        if (typeof uidOrId === 'string') {
            if (tables.has(uidOrId)) return uidOrId;
            if (lobbyToGame.has(uidOrId)) return lobbyToGame.get(uidOrId);
        }
        return uidOrId;
    };

    // Player count is known only when lobby provides totalSeatedPlayers for that table.
    const hasKnownPlayers = (t) => !!(t && Number.isFinite(t.players) && t.players >= 0);

    // Hook WebSocket
    const _WS = window.WebSocket;
    window.WebSocket = function(url, proto) {
        const ws = proto ? new _WS(url, proto) : new _WS(url);
        console.log('[PP] WS:', url);
        hookWS(ws, url);
        return ws;
    };
    window.WebSocket.prototype = _WS.prototype;
    window.WebSocket.CONNECTING = 0;
    window.WebSocket.OPEN = 1;
    window.WebSocket.CLOSING = 2;
    window.WebSocket.CLOSED = 3;
    if (!_WS.prototype.send.__sbHooked) {
        const _protoSend = _WS.prototype.send;
        const hookedSend = function(data) {
            try { hookOutgoingSend(data); } catch (_) {}
            return _protoSend.apply(this, arguments);
        };
        hookedSend.__sbHooked = true;
        _WS.prototype.send = hookedSend;
        window.WebSocket.prototype.send = hookedSend;
    }

    function gameIdFromWsUrl(url) {
        if (!url || typeof url !== 'string') return null;
        try {
            const u = new URL(url.replace(/^ws/i, 'http'));
            const t = u.searchParams.get('tableId');
            return t ? decodeURIComponent(t) : null;
        } catch (_) {
            const m = url.match(/[?&]tableId=([^&]+)/i);
            return m ? decodeURIComponent(m[1]) : null;
        }
    }

    function hookWS(ws, url) {
        const ctxGameId = gameIdFromWsUrl(url);
        ws.addEventListener('message', (e) => {
            try {
                const msg = JSON.parse(e.data);
                msgCount++;
                handleMessage(msg, ctxGameId);
            } catch(err) {}
        });
    }

    function handleMessage(msg, ctxGameId) {
        if (msg.seq) bumpSeq(msg.seq);

        // === LOBBY WEBSOCKET FORMAT (dga.pragmaticplaylive.net) ===
        if (msg.globalStats) {
            globalStats = msg.globalStats;
        }

        if (msg.playersCount) {
            const pc = msg.playersCount;
            lastPlayersCount = {
                total_seated_players: pc.total_seated_players,
                seq: pc.seq
            };
            bumpSeq(pc.seq);
        }

        if (msg.tableKey) {
            tablesOrder = msg.tableKey;
        }

        if (msg.tableId) {
            if (msg.baccaratShoeSummary || msg.tableName) {
                updateFromLobby(msg);
            } else if (msg.totalSeatedPlayers !== undefined) {
                updateLobbyDelta(msg);
            } else if (msg.statistics !== undefined || msg.gameResult !== undefined ||
                       msg.goodRoadsMap !== undefined || msg.goodRoadsDepthMap !== undefined) {
                updateFromLobbyPartial(msg);
            }
        }

        // === GAME WEBSOCKET FORMAT (gs*.pragmaticplaylive.net/game) ===
        if (msg.tablesorder) {
            tablesOrder = msg.tablesorder;
            bumpSeq(msg.seq);
        }

        if (msg.tableconfig) {
            updateFromConfig(msg.tableconfig);
            bumpSeq(msg.tableconfig.seq);
        }

        if (msg.statistic) {
            updateFromStatistic(msg.statistic);
            bumpSeq(msg.statistic.seq);
        }

        if (msg.statisticLA) {
            updateFromStatisticLA(msg.statisticLA);
            bumpSeq(msg.statisticLA.seq);
        }

        if (msg.betsopen) {
            bumpSeq(msg.betsopen.seq);
            updateBetStatus(msg.betsopen.table, true, msg.betsopen.game, msg.betsopen.seq);
        }

        if (msg.betsclosed) {
            bumpSeq(msg.betsclosed.seq);
            updateBetStatus(msg.betsclosed.table, false, msg.betsclosed.game, msg.betsclosed.seq);
        }

        if (msg.ShoeSummary) mergeShoeSummary(msg.ShoeSummary);
        if (msg.goodroad) mergeGoodroad(msg.goodroad);
        if (msg.game) mergeGameMeta(msg.game);
        if (msg.timer) mergeTimer(msg.timer);
        if (msg.dealer) mergeDealer(msg.dealer, ctxGameId);
        if (msg.table && typeof msg.table === 'object' && 'value' in msg.table) {
            mergeTableMeta(msg.table, ctxGameId);
        }
        if (msg.subscribe) mergeSubscribe(msg.subscribe);
        if (msg.betstats) mergeBetstats(msg.betstats);
        if (msg.disablesidebets) mergeDisableSidebets(msg.disablesidebets);
        if (msg.gameresult) mergeGameresultPayload(msg.gameresult);
        if (msg.winners) mergeWinnersPayload(msg.winners);
        if (msg.betsclosingsoon) mergeBetsClosingSoon(msg.betsclosingsoon);
        if (msg.startDealing) mergeStartDealing(msg.startDealing);
        if (msg.startshuffling) mergeShuffling(msg.startshuffling, 'start');
        if (msg.endshuffling) mergeShuffling(msg.endshuffling, 'end');
        if (msg.currentShoe) mergeCurrentShoe(msg.currentShoe, ctxGameId);
        if (msg.voip_cc) mergeVoip(msg.voip_cc, ctxGameId);
        if (msg.pong) {
            bumpSeq(msg.pong.seq);
            mergePong(msg.pong, ctxGameId);
        }
        if (msg.seat) mergeSeat(msg.seat);
        if (msg.card) mergeCard(msg.card);
        if (msg.cardinc) mergeCardInc(msg.cardinc);
    }

    function updateFromLobbyPartial(msg) {
        const lobbyId = msg.tableId;
        let gameId = lobbyToGame.get(lobbyId);
        if (!gameId) gameId = lobbyId;

        const uid = assignUid(gameId);
        const prev = tables.get(gameId) || {};
        const next = {
            ...prev,
            id: gameId,
            gameId,
            lobbyId,
            uid,
            updated: Date.now(),
            updates: (prev.updates || 0) + 1,
            source: 'lobby-partial'
        };

        if (msg.statistics !== undefined) next.bigRoad = msg.statistics;
        if (msg.gameResult !== undefined) next.games = msg.gameResult;
        if (msg.goodRoadsMap !== undefined) next.roads = msg.goodRoadsMap;
        if (msg.goodRoadsDepthMap !== undefined) next.goodRoadsDepthMap = msg.goodRoadsDepthMap;
        if (msg.grTableCount !== undefined) next.grTableCount = msg.grTableCount;
        if (msg.shuffle !== undefined) next.shuffle = msg.shuffle;

        tables.set(gameId, next);
        bumpSeq(msg.seq);
    }

    function mergeShoeSummary(s) {
        if (!s?.table) return;
        bumpSeq(s.seq);
        const gid = resolveGameId(s.table);
        const prev = tables.get(gid) || {};
        patchTable(s.table, {
            P: s.playerWinCounter != null ? +s.playerWinCounter : (prev.P ?? 0),
            B: s.bankerWinCounter != null ? +s.bankerWinCounter : (prev.B ?? 0),
            T: s.tieCounter != null ? +s.tieCounter : (prev.T ?? 0),
            PP: s.playerPairCounter != null ? +s.playerPairCounter : (prev.PP ?? 0), // Player Pairs
            BP: s.bankerPairCounter != null ? +s.bankerPairCounter : (prev.BP ?? 0), // Banker Pairs
            total: s.totalGames != null ? +s.totalGames : (prev.total ?? 0),
            seq: s.seq,
            source: 'game-shoe'
        });
    }

    function mergeGoodroad(g) {
        const tid = g.sourcetableId || g.table;
        if (!tid) return;
        bumpSeq(g.seq);
        patchTable(tid, { goodroadLive: g }, false);
    }

    function mergeGameMeta(g) {
        if (!g?.table) return;
        bumpSeq(g.seq);
        patchTable(g.table, {
            currentGame: g.id,
            gameClock: g.value,
            gameStartTime: g.starttime,
            seq: g.seq
        }, false);
    }

    function mergeTimer(t) {
        if (!t?.table) return;
        bumpSeq(t.seq);
        patchTable(t.table, { bettingTimer: t.value, timerGameId: t.id, seq: t.seq }, false);
    }

    function mergeDealer(d, ctxGameId) {
        if (!d) return;
        const gameId = ctxGameId || [...tables.entries()].find(([, row]) => row.dealerId === d.id)?.[0];
        if (!gameId) return;
        bumpSeq(d.seq);
        patchTable(gameId, { dealer: d.value, dealerId: d.id, seq: d.seq }, false);
    }

    function mergeTableMeta(t, ctxGameId) {
        bumpSeq(t.seq);
        const gameId = ctxGameId;
        if (!gameId) return;
        patchTable(gameId, {
            tableLabel: t.value,
            tableOpenTime: t.openTime,
            tableNewTable: t.newTable,
            tableMetaSeq: t.seq
        }, false);
    }

    function mergeSubscribe(s) {
        if (!s?.table) return;
        bumpSeq(s.seq);
        patchTable(s.table, { subscribeChannel: s.channel, subscribeStatus: s.status }, false);
    }

    function mergeBetstats(b) {
        if (!b?.table) return;
        bumpSeq(b.seq);
        patchTable(b.table, { betstats: b }, false);
    }

    function mergeDisableSidebets(d) {
        const gid = d.tableId;
        if (!gid) return;
        bumpSeq(d.seq);
        patchTable(gid, { disabledSidebets: d.value, seq: d.seq }, false);
    }

    function mergeGameresultPayload(g) {
        if (!g?.table) return;
        bumpSeq(g.seq);
        patchTable(g.table, { lastGameresult: g }, true);
    }

    function mergeWinnersPayload(w) {
        if (!w?.table) return;
        bumpSeq(w.seq);
        patchTable(w.table, { lastWinners: w }, true);
    }

    function mergeBetsClosingSoon(b) {
        if (!b?.table) return;
        bumpSeq(b.seq);
        patchTable(b.table, {
            betsClosingSoon: true,
            betsClosingSoonGame: b.game,
            seq: b.seq
        }, false);
    }

    function mergeStartDealing(s) {
        if (!s?.table) return;
        bumpSeq(s.seq);
        patchTable(s.table, { dealing: true, dealingGame: s.game, seq: s.seq }, false);
    }

    function mergeShuffling(s, phase) {
        if (!s?.table) return;
        bumpSeq(s.seq);
        patchTable(s.table, { shuffling: phase === 'start', shuffleGame: s.game || '', seq: s.seq }, false);
    }

    function mergeCurrentShoe(c, ctxGameId) {
        bumpSeq(c.seq);
        const gameId = ctxGameId;
        if (!gameId) return;
        patchTable(gameId, { currentShoe: c }, false);
    }

    function mergeVoip(v, ctxGameId) {
        bumpSeq(v.seq);
        const gameId = v.table || ctxGameId;
        if (!gameId) return;
        patchTable(gameId, { voip: true, seq: v.seq }, false);
    }

    function mergePong(p, ctxGameId) {
        const gameId = ctxGameId;
        if (!gameId) return;
        patchTable(gameId, { lastPong: p }, false);
    }

    function mergeSeat(s) {
        const tid = s.table_id || s.tableId;
        if (!tid) return;
        bumpSeq(s.seq);
        patchTable(tid, { lastSeatEvent: s }, false);
    }

    function mergeCard(c) {
        if (!c?.table) return;
        bumpSeq(c.seq);
        patchTable(c.table, { lastCard: c, seq: c.seq }, false);
    }

    function mergeCardInc(c) {
        if (!c?.table) return;
        bumpSeq(c.seq);
        patchTable(c.table, { lastCardInc: c, seq: c.seq }, false);
    }

    // Lobby delta: just tableId + player count update
    function updateLobbyDelta(msg) {
        const lobbyId = msg.tableId;
        let gameId = lobbyToGame.get(lobbyId) || lobbyId;

        // Only update if table already exists
        const prev = tables.get(gameId);
        if (!prev) return;

        tables.set(gameId, {
            ...prev,
            players: msg.totalSeatedPlayers ?? prev.players ?? null,
            updated: Date.now()
        });
    }

    // Lobby format: {tableId, baccaratShoeSummary, gameResult, statistics...}
    // tableId here is the LOBBY ID (like "422")
    function updateFromLobby(msg) {
        const lobbyId = msg.tableId;
        // Check if we have a mapping to gameId
        let gameId = lobbyToGame.get(lobbyId);

        // If no mapping yet, use lobbyId as the key (will be merged later)
        if (!gameId) {
            gameId = lobbyId;
        }

        const uid = assignUid(gameId);
        const prev = tables.get(gameId) || {};

        tables.set(gameId, {
            ...prev,
            id: gameId,
            gameId: gameId,
            lobbyId: lobbyId,
            uid,
            name: msg.tableName || prev.name || '',
            type: msg.tableType || prev.type || '',
            subtype: msg.tableSubtype || prev.subtype || '',
            dealer: msg.dealer?.name || prev.dealer || '',
            minBet: msg.tableLimits?.minBet ?? prev.minBet ?? 0,
            maxBet: msg.tableLimits?.maxBet ?? prev.maxBet ?? 0,
            players: msg.totalSeatedPlayers ?? prev.players ?? null,
            P: msg.baccaratShoeSummary?.playerWinCounter != null ? +msg.baccaratShoeSummary.playerWinCounter : (prev.P ?? 0),
            B: msg.baccaratShoeSummary?.bankerWinCounter != null ? +msg.baccaratShoeSummary.bankerWinCounter : (prev.B ?? 0),
            T: msg.baccaratShoeSummary?.tieCounter != null ? +msg.baccaratShoeSummary.tieCounter : (prev.T ?? 0),
            PP: msg.baccaratShoeSummary?.playerPairCounter != null ? +msg.baccaratShoeSummary.playerPairCounter : (prev.PP ?? 0), // Player Pairs
            BP: msg.baccaratShoeSummary?.bankerPairCounter != null ? +msg.baccaratShoeSummary.bankerPairCounter : (prev.BP ?? 0), // Banker Pairs
            total: msg.baccaratShoeSummary?.totalGames != null ? +msg.baccaratShoeSummary.totalGames : (prev.total ?? 0),
            roads: msg.goodRoadsMap || prev.roads || {},
            bigRoad: msg.statistics || prev.bigRoad || '',
            games: msg.gameResult || prev.games || [],
            open: msg.tableOpen ?? prev.open ?? true,
            updated: Date.now(),
            updates: (prev.updates || 0) + 1,
            source: 'lobby'
        });
    }

    // Game format: tableconfig
    // Contains both tableId (gameId) and operator_game_id (lobbyId)
    function updateFromConfig(cfg) {
        const gameId = cfg.tableId;
        const lobbyId = cfg.operator_game_id;
        if (!gameId) return;

        let existingUid = null;

        // Create gameId <-> lobbyId mapping
        if (lobbyId) {
            gameToLobby.set(gameId, lobbyId);
            lobbyToGame.set(lobbyId, gameId);

            // Migrate any existing data from lobbyId key to gameId key
            if (tables.has(lobbyId) && lobbyId !== gameId) {
                const lobbyData = tables.get(lobbyId);
                existingUid = lobbyData.uid; // Preserve the original UID
                const gameData = tables.get(gameId) || {};
                tables.set(gameId, { ...lobbyData, ...gameData, id: gameId, gameId, lobbyId });
                tables.delete(lobbyId);
            }
        }

        // Use existing UID from migrated data, or assign new one
        const uid = existingUid ? assignUid(gameId, existingUid) : assignUid(gameId);
        configs.set(gameId, cfg);
        const prev = tables.get(gameId) || {};

        tables.set(gameId, {
            ...prev,
            id: gameId,
            gameId,
            lobbyId: lobbyId || prev.lobbyId || '',
            uid,
            name: cfg.table_name || prev.name || '',
            type: cfg.table_type || prev.type || '',
            category: cfg.table_category || prev.category || '',
            minBet: parseFloat(cfg.table_bet_min_limit) || prev.minBet || 0,
            maxBet: parseFloat(cfg.table_bet_max_limit) || prev.maxBet || 0,
            bettingTime: parseInt(cfg.betting_time) || prev.bettingTime || 15,
            open: cfg.table_closed !== 'true',
            mtbGroupId: cfg.mtb_groupId || prev.mtbGroupId || '',
            updated: Date.now(),
            source: 'game'
        });
    }

    // Game format: statistic (full road data)
    function updateFromStatistic(stat) {
        const gameId = stat.table;
        if (!gameId) return;

        const uid = assignUid(gameId);
        let data = {};
        try {
            data = JSON.parse(stat.value);
        } catch(e) { return; }

        const prev = tables.get(gameId) || {};

        tables.set(gameId, {
            ...prev,
            id: gameId,
            gameId,
            uid,
            P: data.playerWinCounter ?? prev.P ?? 0,
            B: data.bankerWinCounter ?? prev.B ?? 0,
            T: data.tieCounter ?? prev.T ?? 0,
            PP: data.playerPairCounter ?? prev.PP ?? 0, // Player Pairs
            BP: data.bankerPairCounter ?? prev.BP ?? 0, // Banker Pairs
            total: (data.playerWinCounter || 0) + (data.bankerWinCounter || 0) + (data.tieCounter || 0),
            bigRoad: data.bigRoad || prev.bigRoad || [],
            beadPlate: data.beadPlate || prev.beadPlate || [],
            bigEyeBoy: data.bigEyeBoy || prev.bigEyeBoy || [],
            smallRoad: data.smallRoad || prev.smallRoad || [],
            cockroachPig: data.cockroachPig || prev.cockroachPig || [],
            playerEnhance: data.playerEnhancement || prev.playerEnhance || null,
            bankerEnhance: data.bankerEnhancement || prev.bankerEnhance || null,
            seq: stat.seq || prev.seq || 0,
            updated: Date.now(),
            updates: (prev.updates || 0) + 1,
            source: 'game'
        });
    }

    // Bet status: betsopen / betsclosed
    function updateBetStatus(tableId, canBet, gameRoundId, seq) {
        const gameId = tableId;
        if (!gameId) return;

        const apply = (flag) => {
            const prev = tables.get(gameId) || {};
            tables.set(gameId, {
                ...prev,
                id: gameId,
                gameId,
                uid: prev.uid || assignUid(gameId),
                canBet: flag,
                currentGame: gameRoundId,
                betStatusTime: Date.now(),
                seq: seq || prev.seq || 0
            });
        };

        if (canBet) {
            if (CAN_BET_OPEN_DELAY_MS <= 0) {
                apply(true);
            } else {
                setTimeout(() => apply(true), CAN_BET_OPEN_DELAY_MS);
            }
        } else {
            apply(false);
        }
    }

    // Game format: statisticLA (last action - incremental)
    function updateFromStatisticLA(stat) {
        const gameId = stat.table;
        if (!gameId) return;

        const uid = assignUid(gameId);
        let data = {};
        try {
            data = JSON.parse(stat.value);
        } catch(e) { return; }

        const prev = tables.get(gameId) || {};

        // LA format uses short keys: bwc, pwc, tc, bpc, ppc
        tables.set(gameId, {
            ...prev,
            id: gameId,
            gameId,
            uid,
            P: data.pwc ?? prev.P ?? 0,
            B: data.bwc ?? prev.B ?? 0,
            T: data.tc ?? prev.T ?? 0,
            PP: data.ppc ?? prev.PP ?? 0, // Player Pairs
            BP: data.bpc ?? prev.BP ?? 0, // Banker Pairs
            total: (data.pwc ?? prev.P ?? 0) + (data.bwc ?? prev.B ?? 0) + (data.tc ?? prev.T ?? 0),
            lastBR: data.br || prev.lastBR,      // last big road position
            lastBP: data.bp || prev.lastBP,      // last bead plate position
            lastBEB: data.beb || prev.lastBEB,   // last big eye boy
            lastSR: data.sr || prev.lastSR,      // last small road
            lastCP: data.cp || prev.lastCP,      // last cockroach pig
            playerEnhance: data.pE || prev.playerEnhance || null,
            bankerEnhance: data.bE || prev.bankerEnhance || null,
            seq: stat.seq || prev.seq || 0,
            updated: Date.now(),
            updates: (prev.updates || 0) + 1,
            source: 'game-la'
        });
    }

    // Calculate P/B ratio for filtering
    const calcRatio = (t) => {
        if (!t || !t.total || t.total === 0) return 999;
        const diff = Math.abs((t.P || 0) - (t.B || 0));
        return diff / t.total;
    };

    // Extract P/B/T sequence from table data
    // Returns array like ['P','B','B','T','P',...] in chronological order (oldest first)
    const getPBTSequence = (t) => {
        if (!t) return [];

        // Method 1: From beadPlate (game WebSocket) - most reliable
        // beadPlate is 2D: [[col0row0, col0row1,...], [col1row0,...], ...]
        // Fills column by column (top to bottom in each column, then next column)
        // First char: R=Banker (red), B=Player (blue), G=Tie (green)
        if (t.beadPlate && Array.isArray(t.beadPlate)) {
            const seq = [];
            const numRows = t.beadPlate[0]?.length || 6;
            // Read column by column, top to bottom in each column
            for (let col = 0; col < t.beadPlate.length; col++) {
                for (let row = 0; row < numRows; row++) {
                    const cell = t.beadPlate[col]?.[row];
                    if (cell && cell !== '---') {
                        const c = cell.charAt(0);
                        if (c === 'R') seq.push('B');      // Red = Banker
                        else if (c === 'B') seq.push('P'); // Blue = Player
                        else if (c === 'G') seq.push('T'); // Green = Tie
                    }
                }
            }
            return seq;
        }

        // Method 2: From gameResult (lobby WebSocket)
        // gameResult is array of {winner: "BANKER_WIN" | "PLAYER_WIN" | "TIE", ...}
        if (t.games && Array.isArray(t.games)) {
            return t.games.map(g => {
                if (g.winner === 'PLAYER_WIN') return 'P';
                if (g.winner === 'BANKER_WIN') return 'B';
                if (g.winner === 'TIE') return 'T';
                return '?';
            }).filter(x => x !== '?');
        }

        // Method 3: From bigRoad string (lobby format) - parse the string
        if (t.bigRoad && typeof t.bigRoad === 'string') {
            try {
                const road = JSON.parse(t.bigRoad);
                if (Array.isArray(road)) {
                    const seq = [];
                    for (let col = 0; col < road.length; col++) {
                        for (let row = 0; row < road[col].length; row++) {
                            const cell = road[col][row];
                            if (cell && cell !== '---') {
                                const c = cell.charAt(0);
                                if (c === 'P') seq.push('P');
                                else if (c === 'B') seq.push('B');
                                // Ties are embedded in P/B cells with numbers
                            }
                        }
                    }
                    return seq;
                }
            } catch (e) {}
        }

        return [];
    };

    /** Latest live-stream payloads merged onto a table row (card, timer, goodroad, …). */
    const buildLiveSnapshot = (t) => {
        const out = {};
        if (t.lastCard) out.card = t.lastCard;
        if (t.lastCardInc) out.cardInc = t.lastCardInc;
        if (t.bettingTimer != null && t.bettingTimer !== '' || t.timerGameId) {
            out.timer = { value: t.bettingTimer, gameId: t.timerGameId };
        }
        if (t.goodroadLive) out.goodroad = t.goodroadLive;
        if (t.currentGame != null && t.currentGame !== '' || t.gameClock != null && t.gameClock !== '' || t.gameStartTime) {
            out.game = { id: t.currentGame, clock: t.gameClock, startTime: t.gameStartTime };
        }
        if (t.lastGameresult) out.gameresult = t.lastGameresult;
        if (t.lastWinners) out.winners = t.lastWinners;
        if (t.betstats) out.betstats = t.betstats;
        if (t.disabledSidebets != null && t.disabledSidebets !== '') {
            out.disabledSidebets = t.disabledSidebets;
        }
        if (t.betsClosingSoon) {
            out.betsClosingSoon = { game: t.betsClosingSoonGame };
        }
        if (t.dealing) {
            out.dealing = { game: t.dealingGame };
        }
        if (t.shuffling || (t.shuffleGame !== undefined && t.shuffleGame !== '')) {
            out.shuffling = { active: !!t.shuffling, game: t.shuffleGame };
        }
        if (t.subscribeChannel || t.subscribeStatus) {
            out.subscribe = { channel: t.subscribeChannel, status: t.subscribeStatus };
        }
        if (t.lastSeatEvent) out.seat = t.lastSeatEvent;
        if (t.lastPong) out.pong = t.lastPong;
        if (t.voip) out.voip = true;
        if (t.currentShoe) out.shoe = t.currentShoe;
        if (t.tableLabel != null && t.tableLabel !== '' || t.tableOpenTime || t.tableNewTable != null) {
            out.tableMeta = {
                label: t.tableLabel,
                openTime: t.tableOpenTime,
                newTable: t.tableNewTable
            };
        }
        if (t.dealer || t.dealerId) {
            out.dealer = { name: t.dealer, id: t.dealerId };
        }
        return out;
    };

    const liveForId = (uidOrId) => {
        const id = resolveId(uidOrId);
        const t = id ? tables.get(id) : null;
        if (!t) return null;
        return buildLiveSnapshot(t);
    };

    // API
    const api = {
        tables: () => {
            const obj = {};
            for (const [id, t] of tables) {
                obj[id] = { ...t, ratio: calcRatio(t) };
            }
            return obj;
        },
        configs: () => Object.fromEntries(configs),
        get: (uidOrId) => {
            const id = resolveId(uidOrId);
            const t = id ? tables.get(id) : null;
            return t ? { ...t, ratio: calcRatio(t) } : null;
        },
        /** Grouped live-stream fields for one table (same ids as pp.get). Alias: lastEvents. */
        live: liveForId,
        lastEvents: liveForId,
        count: () => tables.size,
        msgs: () => msgCount,
        order: () => tablesOrder,
        stats: () => {
            const out = {};
            if (globalStats && typeof globalStats === 'object') Object.assign(out, globalStats);
            if (lastPlayersCount) out.lobbyPlayersCount = lastPlayersCount;
            return Object.keys(out).length ? out : null;
        },
        seq: () => lastSeq,

        /** Last outgoing <lpbet> parsed from WS send, or null */
        lastLpbet: () => lastLpbetEvent,
        /** Recent outgoing lpbet records (newest last) */
        lpbetHistory: () => lpbetHistory.slice(),
        lpbetCount: () => lpbetCount,
        /** Subscribe to each lpbet send; returns unsubscribe */
        onLpbet: (fn) => {
            if (typeof fn !== 'function') return () => {};
            lpbetListeners.add(fn);
            return () => lpbetListeners.delete(fn);
        },
        /**
         * Outgoing <lpbet> stake for this table + side after `since`.
         * bc on wire: "0" = Player, "1" = Banker (same as data-betcode).
         * Uses the running spot total when PP sends increasing amts; otherwise sums chip deltas.
         */
        lpbetStake: (tableId, opts = {}) => lpbetStakeSince(tableId, opts),
        /**
         * Wait until outgoing lpbet stake for this table matches side after `since`.
         * If `minTotal` is set, waits until the interpreted stake reaches that amount.
         */
        waitLpbet: (tableId, opts = {}) => {
            const timeoutMs = opts.timeoutMs ?? 8000;
            const since = opts.since ?? 0;
            const side = opts.side;
            const minTotal = opts.minTotal;

            const satisfied = (accumulated) => {
                if (minTotal != null && Number(minTotal) > 0) {
                    return accumulated >= Number(minTotal) - 1e-9;
                }
                return accumulated > 0;
            };

            return new Promise((resolve) => {
                let lastRec = null;
                const catchUp = () => {
                    lastRec = null;
                    for (const rec of lpbetHistory) {
                        if (!tableMatchLpbet(rec, tableId) || rec.time < since) continue;
                        if (stakeFromRecSide(rec, side) <= 0) continue;
                        lastRec = rec;
                    }
                    return lpbetStakeSince(tableId, { side, since });
                };

                const accumulated0 = catchUp();
                if (satisfied(accumulated0)) {
                    resolve(lastRec);
                    return;
                }

                let timer = null;
                const fn = (rec) => {
                    if (!tableMatchLpbet(rec, tableId) || rec.time < since) return;
                    if (stakeFromRecSide(rec, side) <= 0) return;
                    const accumulated = catchUp();
                    if (satisfied(accumulated)) {
                        if (timer) clearTimeout(timer);
                        lpbetListeners.delete(fn);
                        resolve(lastRec);
                    }
                };
                lpbetListeners.add(fn);
                timer = setTimeout(() => {
                    lpbetListeners.delete(fn);
                    resolve(null);
                }, timeoutMs);
            });
        },

        setWarnFilter: (enabled = true) => {
            suppressGoodRoadWarnings = !!enabled;
            return suppressGoodRoadWarnings;
        },
        warnFilter: () => suppressGoodRoadWarnings,

        help: () => {
            const W = 62;
            const line = (ch) => ch.repeat(W);
            const row = (cmd, hint) =>
                `  ${String(cmd).padEnd(26)} ${hint}`;
            const title = 'pp — Pragmatic Play websocket intercept (tables + roads)';
            const boxLine = () => `${line('═')}`;
            const boxTitle = () => `║ ${title.padEnd(W - 4)} ║`;
            const t = `
${boxLine()}
${boxTitle()}
${boxLine()}

 ▸ Table views
${row('pp.help()', 'This cheat sheet')}
${row('pp.status()', 'Print summary of all tracked tables')}
${row('pp.tables()', 'Object: gameId → full row')}
${row('pp.get(id)', 'One row · id = numeric uid OR gameId OR lobbyId')}
${row('pp.list()', 'Compact array (total > 0) incl. playersKnown')}
${row('pp.betting()', 'Subset with canBet and enough history')}
${row('pp.players(id)', 'Seated players for table, or null if unknown')}
${row('pp.playersKnown(id)', 'true when lobby sent totalSeatedPlayers')}

 ▸ Live snapshots
${row('pp.live(id)', 'Grouped recent stream fields (cards, timer, …)')}
${row('pp.lastEvents(id)', 'Alias of pp.live')}

 ▸ Road / PBT
${row('pp.road(id)', 'bigRoad blob for table')}
${row('pp.pbt(id)', "Chronological ['P','B','T',…]")}
${row('pp.pbtStr(id)', 'Same sequence as string')}
${row('pp.lastN(id, n)', 'Last n results')}
${row('pp.sequences()', 'All tables + arrays')}
${row('pp.seqAll()', 'Pretty-print sequences in console')}

 ▸ ID mapping
${row('pp.gameToLobby(g)', 'lobby id from game id')}
${row('pp.lobbyToGame(l)', 'game id from lobby id')}

 ▸ Global / meta
${row('pp.stats()', 'Lobby global stats + playersCount blob')}
${row('pp.order()', 'tableKey / tablesorder array')}
${row('pp.seq()', 'Highest seq seen')}
${row('pp.msgs()', 'Parsed JSON message count')}
${row('pp.lpbetCount()', 'Outgoing <lpbet> sends observed')}
${row('pp.lastLpbet()', 'Last parsed lpbet from WS send')}
${row('pp.lpbetStake(id, {side,since})', 'Running lpbet stake for table + side')}
${row('pp.waitLpbet(id, {side,since,minTotal,timeoutMs})', 'Promise: wire stake sum for table + side')}
${row('pp.onLpbet(fn)', 'Callback on each lpbet; returns unsubscribe')}
${row('pp.count()', 'Tables in internal map')}
${row('pp.setWarnFilter(v)', 'Suppress GoodRoad / tablesOrder noise')}
${row('pp.warnFilter()', 'Current filter on/off')}

 ▸ Raw dump
${row('pp.configs()', 'Raw tableconfig by game id')}
${row('pp.export()', 'JSON stringify of all table rows')}
${row('pp.clear()', 'Clear all in-memory state')}

${line('─')}
  Tip: use a monospace console font so columns align.
`.trimEnd();
            console.log(t);
        },

        // ID mapping functions
        gameToLobby: (gameId) => gameToLobby.get(gameId) || null,
        lobbyToGame: (lobbyId) => lobbyToGame.get(String(lobbyId)) || null,

        list: () => [...tables.values()]
            .filter(t => t.total > 0)
            .sort((a, b) => a.uid - b.uid)
            .map(t => {
                const seq = getPBTSequence(t);
                return {
                    uid: t.uid,
                    id: t.id,
                    gameId: t.gameId,
                    lobbyId: t.lobbyId,
                    name: t.name,
                    players: hasKnownPlayers(t) ? t.players : null,
                    playersKnown: hasKnownPlayers(t),
                    P: t.P,
                    B: t.B,
                    T: t.T,
                    total: t.total,
                    canBet: t.canBet,
                    ratio: calcRatio(t),
                    upd: t.updates,
                    last10: seq.slice(-10).join('')
                };
            }),

        // Get tables that can currently bet
        betting: () => [...tables.values()]
            .filter(t => t.canBet === true && t.total >= 20)
            .sort((a, b) => calcRatio(a) - calcRatio(b))
            .map(t => ({
                uid: t.uid,
                gameId: t.gameId,
                name: t.name,
                P: t.P,
                B: t.B,
                T: t.T,
                ratio: calcRatio(t)
            })),

        status: () => {
            const active = [...tables.values()].filter(t => t.total > 0);
            console.log(`\n═══ PP TABLES (${active.length}) | msgs:${msgCount} | seq:${lastSeq} ═══\n`);
            active
                .sort((a, b) => a.uid - b.uid)
                .forEach(t => {
                    const bet = t.canBet ? '✓' : ' ';
                    const seq = getPBTSequence(t).slice(-8).join('');
                    console.log(
                        `#${String(t.uid).padStart(2)}${bet} ${(t.name || t.gameId || '?').slice(0,18).padEnd(18)} ` +
                        `P:${String(t.P||0).padStart(2)} B:${String(t.B||0).padStart(2)} T:${t.T||0} ` +
                        `(${String(t.total||0).padStart(2)}) ${seq.padEnd(8)}`
                    );
                });
        },

        road: (uidOrId) => {
            const id = resolveId(uidOrId);
            const t = id ? tables.get(id) : null;
            return t?.bigRoad || null;
        },

        // Get P/B/T sequence for a table
        // Returns array like ['P','B','B','T','P',...] in chronological order
        pbt: (uidOrId) => {
            const id = resolveId(uidOrId);
            const t = id ? tables.get(id) : null;
            return getPBTSequence(t);
        },

        // Get P/B/T sequence as string (e.g., "PBBPTBPBBB")
        pbtStr: (uidOrId) => {
            const id = resolveId(uidOrId);
            const t = id ? tables.get(id) : null;
            return getPBTSequence(t).join('');
        },

        // Seated players count for a table. Returns null when unknown.
        players: (uidOrId) => {
            const id = resolveId(uidOrId);
            const t = id ? tables.get(id) : null;
            return hasKnownPlayers(t) ? t.players : null;
        },

        playersKnown: (uidOrId) => {
            const id = resolveId(uidOrId);
            const t = id ? tables.get(id) : null;
            return hasKnownPlayers(t);
        },

        // Get last N results for a table
        lastN: (uidOrId, n = 10) => {
            const id = resolveId(uidOrId);
            const t = id ? tables.get(id) : null;
            const seq = getPBTSequence(t);
            return seq.slice(-n);
        },

        // List all tables with full sequences
        sequences: () => [...tables.values()]
            .filter(t => t.total > 0)
            .sort((a, b) => a.uid - b.uid)
            .map(t => {
                const seq = getPBTSequence(t);
                return {
                    uid: t.uid,
                    name: t.name || t.gameId,
                    total: t.total,
                    P: t.P,
                    B: t.B,
                    T: t.T,
                    sequence: seq,
                    sequenceStr: seq.join('')
                };
            }),

        // Print all tables with full sequences
        seqAll: () => {
            console.log(`\n═══ ALL TABLE SEQUENCES (${tables.size} tables) ═══\n`);
            [...tables.values()]
                .filter(t => t.total > 0)
                .sort((a, b) => a.uid - b.uid)
                .forEach(t => {
                    const seq = getPBTSequence(t);
                    const name = (t.name || t.gameId || '?').slice(0, 20).padEnd(20);
                    console.log(`#${String(t.uid).padStart(2)} ${name} (${t.total})`);
                    console.log(`    ${seq.join('')}`);
                    console.log('');
                });
        },

        export: () => JSON.stringify(Object.fromEntries(tables), null, 2),
        clear: () => {
            tables.clear();
            configs.clear();
            uidMap.clear();
            idToUid.clear();
            gameToLobby.clear();
            lobbyToGame.clear();
            nextUid = 1;
            msgCount = 0;
            lastSeq = 0;
            tablesOrder = [];
            globalStats = null;
            lastPlayersCount = null;
            lpbetCount = 0;
            lastLpbetEvent = null;
            lpbetHistory.length = 0;
        }
    };

    console.log('[PP] v3.2.5 | + outgoing lpbet capture (pp.waitLpbet / pp.lastLpbet)');
    console.log('[PP] API: pp.help() pp.status() pp.get(1) pp.live(1) …');

    return api;

    };

    const createPick = (pp) => {

/**
     * v4.0 — "Absurdity firewall" + chop signal from PP payloads
     * Prefer: goodroadLive / goodRoadsDepthMap playerPingPongDepth & bankerPingPongDepth
     * Prefer: betstats playerpercentage / bankerpercentage (crowd)
     * Fallback: shallow alternations in last-12 when depths missing (labelled in diagnostics)
     */

    const Config = {
        MIN_TOTAL: 30,              // Ghost tables — not enough rounds
        MAX_TIE_RATIO: 0.12,        // ~12%+ ties ⇒ reject ("tie storm")
        MAX_PB_GAP_RATIO: 0.10,     // |P-B|/total > 10% ⇒ reject ("gravity")
        MAX_CROWD_PCT: 85,          // Either side ≥ 85% ⇒ reject (percent units 0..100)

        REQUIRE_BETSTATS_FOR_CROWD: false,

        MIN_EFFECTIVE_DEPTH: 0,     // Extra gate: chop depth gate (PP uses max of both depths); 0 = off

        // Display score clamps
        DISPLAY_SCORE_ELIGIBLE_MIN: 50,
        DISPLAY_SCORE_ELIGIBLE_MAX: 100,
    };

    const getSequence = (t) => {
        if (!pp) return [];
        const id = t?.uid || t?.gameId || t?.id || t;
        return pp.pbt(id) || [];
    };

    const getLive = (t) => {
        if (!pp) return null;
        const id = t?.uid || t?.gameId || t?.id || t;
        return pp.live(id) || null;
    };

    const n = (v) => {
        if (v == null || v === '') return null;
        const x = typeof v === 'number' ? v : parseFloat(String(v).replace(/%/g, ''));
        return Number.isFinite(x) ? x : null;
    };

    /** If value looks like ratio 0..1 convert to percentage for crowd compare */
    const asPercentMaybe = (v) => {
        const x = n(v);
        if (x == null) return null;
        if (x > 0 && x <= 1) return x * 100;
        return x;
    };

    const countAlternations = (seq) => {
        const filtered = (seq || []).filter(x => x !== 'T');
        if (filtered.length < 2) return 0;
        let alt = 0;
        for (let i = 1; i < filtered.length; i++) {
            if (filtered[i] !== filtered[i - 1]) alt++;
        }
        return alt;
    };

    const walkForCrowdPct = (obj, maxDepth = 6) => {
        let player = null;
        let banker = null;
        const visit = (o, d) => {
            if (!o || typeof o !== 'object' || d > maxDepth) return;
            if (Array.isArray(o)) {
                for (const it of o) visit(it, d + 1);
                return;
            }
            for (const [key, val] of Object.entries(o)) {
                const kl = key.toLowerCase().replace(/\s+/g, '');
                if (/^playerperc/.test(kl) || kl === 'playerpercentage' || kl === 'pctplayer') {
                    const p = asPercentMaybe(val);
                    if (p != null) player = player == null ? p : Math.max(player, p);
                }
                if (/^bankerperc/.test(kl) || kl === 'bankerpercentage' || kl === 'pctbanker') {
                    const b = asPercentMaybe(val);
                    if (b != null) banker = banker == null ? b : Math.max(banker, b);
                }
                if (val != null && typeof val === 'object') visit(val, d + 1);
            }
        };
        visit(obj, 0);
        return { player, banker };
    };

    /** Pull ping-pong depth from known maps or deep-scan goodroad payload */
    const extractPingPongDepths = (t) => {
        let pp = 0;
        let bp = 0;
        let source = '';

        // Game WS goodroad — same as working play.js / console snippet (parseInt on top-level keys)
        const gl = t?.goodroadLive;
        if (gl && typeof gl === 'object') {
            const a = parseInt(gl.playerPingPongDepth || 0, 10);
            const b = parseInt(gl.bankerPingPongDepth || 0, 10);
            pp = Number.isFinite(a) ? a : 0;
            bp = Number.isFinite(b) ? b : 0;
            source = 'goodroadLive';
        }

        const takeMap = (m, label) => {
            if (!m || typeof m !== 'object') return;
            const a = n(m.playerPingPongDepth ?? m.playerpingpongdepth);
            const b = n(m.bankerPingPongDepth ?? m.bankerpingpongdepth);
            if (a != null) {
                pp = Math.max(pp, a);
                if (!source) source = label;
            }
            if (b != null) {
                bp = Math.max(bp, b);
                if (!source) source = label;
            }
        };

        takeMap(t?.goodRoadsDepthMap, 'goodRoadsDepthMap');

        const deepPing = (root, label) => {
            if (!root || typeof root !== 'object') return;
            const scan = (o, depth) => {
                if (!o || typeof o !== 'object' || depth > 5) return;
                for (const [k, v] of Object.entries(o)) {
                    const kl = k.toLowerCase();
                    if (/pingpong.*depth|ping_pong.*depth/.test(kl) ||
                        (/pingpong/.test(kl) && /depth/.test(kl))) {
                        const num = n(v);
                        if (num != null) {
                            if (/player/.test(kl)) pp = Math.max(pp, num);
                            else if (/banker/.test(kl)) bp = Math.max(bp, num);
                            else if (pp === 0 && bp === 0) {
                                pp = num;
                                source = source || label + '-ambiguous';
                            }
                        }
                    } else if (v != null && typeof v === 'object') scan(v, depth + 1);
                }
            };
            scan(root, 0);
            if ((pp > 0 || bp > 0) && !source) source = label;
        };

        if (pp === 0 && bp === 0) deepPing(t?.goodroadLive, 'goodroadLive-scan');

        const effective = Math.max(pp, bp);
        const depthSource = effective > 0 ? (source || 'payload') : 'none';

        return { pp, bp, effective, depthSource };
    };

    const scoreTable = (t) => {
        if (!t) {
            return {
                score: 0,
                eligible: false,
                reasons: ['no-table'],
                breakdown: {},
                firewall: {},
                diagnostics: {},
            };
        }

        const total = t.total ?? 0;
        const P = t.P ?? 0;
        const B = t.B ?? 0;
        const Tie = t.T ?? 0;
        const pbGapRatio = total > 0 ? Math.abs(P - B) / total : 1;
        const tieRatio = total > 0 ? Tie / total : 0;

        const firewall = [];

        // --- HARD REJECT ---
        if (total < Config.MIN_TOTAL) {
            firewall.push(`ghost: total=${total}<${Config.MIN_TOTAL}`);
            return mkReject(firewall, { total, P, B, Tie, pbGapRatio, tieRatio }, t);
        }

        if (tieRatio > Config.MAX_TIE_RATIO + 1e-9) {
            firewall.push(`tie-storm: ${(tieRatio * 100).toFixed(1)}% (> ${Config.MAX_TIE_RATIO * 100}%)`);
        }

        if (pbGapRatio > Config.MAX_PB_GAP_RATIO + 1e-9) {
            firewall.push(`gravity: |P−B|/total=${(pbGapRatio * 100).toFixed(1)}% (> ${Config.MAX_PB_GAP_RATIO * 100}%)`);
        }

        const bs = t.betstats;
        let crowd = { playerPct: null, bankerPct: null };
        if (bs && typeof bs === 'object') {
            crowd = walkForCrowdPct(bs);
            const extremes = [];
            if (crowd.playerPct != null && crowd.playerPct >= Config.MAX_CROWD_PCT + 1e-9)
                extremes.push(`playerPct=${crowd.playerPct.toFixed(1)}%`);
            if (crowd.bankerPct != null && crowd.bankerPct >= Config.MAX_CROWD_PCT + 1e-9)
                extremes.push(`bankerPct=${crowd.bankerPct.toFixed(1)}%`);
            if (extremes.length) {
                firewall.push(`crowd: ${extremes.join(', ')} (≥ ${Config.MAX_CROWD_PCT}%)`);
            }
        } else if (Config.REQUIRE_BETSTATS_FOR_CROWD) {
            firewall.push('crowd: no betstats payload');
        }

        const seq12 = countAlternations(getSequence(t).slice(-12));
        const depthInfo = extractPingPongDepths(t);

        if (Config.MIN_EFFECTIVE_DEPTH > 0 && depthInfo.effective < Config.MIN_EFFECTIVE_DEPTH) {
            firewall.push(`chop-too-low: maxDepth=${depthInfo.effective} (< ${Config.MIN_EFFECTIVE_DEPTH})`);
        }

        if (firewall.length) return mkReject(firewall, { total, P, B, Tie, pbGapRatio, tieRatio }, t, seq12, depthInfo, crowd);

        const notes = [];

        let chopContribution = depthInfo.effective;
        let chopFallback = false;
        if (depthInfo.effective === 0 && seq12 > 0) {
            chopContribution = seq12 / 11;
            chopFallback = true;
            notes.push('depth from last-12 alts (no PP depth yet)');
        }

        const tieQuality = Math.max(0, 25 - tieRatio * 200);
        const balanceQuality = Math.max(0, 55 - pbGapRatio * 200);
        const chopQuality = Math.min(40, chopContribution * (chopFallback ? 6 : 8));
        const historyQuality = Math.min(15, (total / 60) * 15);

        let displayScore =
            chopQuality +
            tieQuality +
            balanceQuality +
            historyQuality;

        displayScore = Math.round(
            Math.max(
                Config.DISPLAY_SCORE_ELIGIBLE_MIN,
                Math.min(Config.DISPLAY_SCORE_ELIGIBLE_MAX, displayScore)
            )
        );

        let canBetBonus = 0;
        // If stream says bets open, do not penalize for dealing/shuffle flags (PP often overlaps phases)
        if (t.canBet === true) canBetBonus = 5;
        displayScore = Math.round(Math.min(100, displayScore + canBetBonus));

        return {
            score: displayScore,
            eligible: true,
            firewall: [],
            reasons: [],
            notes,
            breakdown: {
                chop: Math.round(chopQuality),
                balance: Math.round(balanceQuality),
                ties: Math.round(tieQuality),
                history: Math.round(historyQuality),
                canBet: canBetBonus,
            },
            diagnostics: {
                pbGapRatio,
                tieRatio,
                seqAlternations12: seq12,
                chopFallback,
                ...depthInfo,
                crowd,
            },
        };

        function mkReject(fw, sums, tbl, sq = 0, dpt = {}, cr = {}) {
            return {
                score: 0,
                eligible: false,
                reasons: [...fw],
                firewall: [...fw],
                notes: fw,
                breakdown: {},
                diagnostics: {
                    total: sums.total,
                    P: sums.P,
                    B: sums.B,
                    T: sums.Tie,
                    pbGapRatio: sums.pbGapRatio,
                    tieRatio: sums.tieRatio,
                    seqAlternations12: sq,
                    ...(dpt && typeof dpt === 'object' ? dpt : {}),
                    crowd: cr,
                    name: tbl.name,
                    gameId: tbl.gameId,
                },
            };
        }
    };

    const comparator = (a, b) => {
        const ae = a.diagnostics?.effective ?? Math.max(a.diagnostics?.pp ?? 0, a.diagnostics?.bp ?? 0);
        const be = b.diagnostics?.effective ?? Math.max(b.diagnostics?.pp ?? 0, b.diagnostics?.bp ?? 0);
        if (be !== ae) return be - ae;

        const ar = Math.abs(a.P - a.B) / (a.total || 1);
        const br = Math.abs(b.P - b.B) / (b.total || 1);
        if (ar !== br) return ar - br;

        const at = (a.T || 0) / (a.total || 1);
        const bt = (b.T || 0) / (b.total || 1);
        if (at !== bt) return at - bt;

        return (b.total || 0) - (a.total || 0);
    };

    const getAllScored = () => {
        if (!pp) return [];
        const tables = Object.values(pp.tables());
        return tables.map(t => {
            const result = scoreTable(t);
            const seq = getSequence(t);
            const live = getLive(t);
            const total = t.total || 0;
            const ratio = total > 0 ? Math.abs((t.P || 0) - (t.B || 0)) / total : 0;
            const tieRatio = total > 0 ? (t.T || 0) / total : 0;
            const diagnostics = result.diagnostics || {};
            const currentStreak = (() => {
                const fx = seq.filter(x => x !== 'T');
                if (!fx.length) return { side: null, length: 0 };
                const last = fx[fx.length - 1];
                let len = 0;
                for (let i = fx.length - 1; i >= 0; i--) {
                    if (fx[i] !== last) break;
                    len++;
                }
                return { side: last, length: len };
            })();
            const streak = currentStreak;
            return {
                ...t,
                ...result,
                ratio,
                ratioStr: ratio.toFixed(3),
                tieRatio,
                tieRatioStr: `${(tieRatio * 100).toFixed(1)}%`,
                live,
                streak,
                last12: seq.slice(-12).join(''),
                altIn12: countAlternations(seq.slice(-12)),
                pingPong: {
                    pp: diagnostics.pp ?? null,
                    bp: diagnostics.bp ?? null,
                    effective: diagnostics.effective ?? 0,
                    source: diagnostics.depthSource,
                },
            };
        }).sort(comparator);
    };

    const getEligible = () => getAllScored().filter(x => x.eligible);

    /** Everything sorted (eligible + rejected — rejected score 0) */
    const getRankedAll = () => getAllScored();

    const getBest = () => getEligible()[0] || null;

    const pick = () => {
        const table = getBest();
        if (!table) return null;
        return { table, score: table.score };
    };

    const topN = (n = 5) => getEligible().slice(0, n);

    const scoreLabel = (s, eligible) => {
        if (!eligible) return 'REJECT';
        if (s < 58) return 'FAIR';
        if (s < 68) return 'GOOD';
        if (s < 80) return 'GREAT';
        return 'IDEAL';
    };

    const scoreIcon = (s, eligible) => {
        if (!eligible) return '🔴';
        if (s < 58) return '🟡';
        if (s < 68) return '🟢';
        if (s < 80) return '💚';
        return '⭐️';
    };

    const liveFlags = (live) => {
        if (!live) return '-----';
        return [
            live.dealing ? 'D' : '-',
            live.shuffling?.active ? 'S' : '-',
            live.betsClosingSoon ? 'C' : '-',
            live.voip ? 'V' : '-',
            (live.card || live.cardInc) ? 'K' : '-',
        ].join('');
    };

    const displayTableName = util.displayName;

    const api = {
        config: Config,

        score: scoreTable,
        scoreAll: getAllScored,

        eligible: getEligible,
        all: getRankedAll,
        ranked: getRankedAll,
        best: getBest,
        pick,
        top: topN,

        chop: (t) => extractPingPongDepths(t).effective || countAlternations(getSequence(t).slice(-12)),

        status: () => {
            const all = getRankedAll();
            const eligible = all.filter(t => t.eligible);
            const line = () => `${'═'.repeat(74)}`;

            console.log(`
${line()}
║ TABLE PICKER v4 (${eligible.length} eligible / ${all.length} total) ${' '.repeat(Math.max(0, 74 - 44))} ║
${line()}
  Sort: PingPong depth (PP) ↑  →  balance |P−B|/total ↑  →  tie % ↑`);

            eligible.slice(0, 22).forEach((t) => {
                const icon = scoreIcon(t.score, true);
                const bet = t.canBet ? '✓' : ' ';
                const name = displayTableName(t.name || '?').slice(0, 16).padEnd(16);
                const chop = `${t.pingPong.effective}`.padStart(3);
                const gap = `${(Math.abs((t.P || 0) - (t.B || 0)) / (t.total || 1) * 100).toFixed(0)}%`;
                console.log(`${icon}${bet} s:${String(t.score).padStart(3)} chop:${chop} gap:${gap.padStart(4)} ` +
                    `T%:${parseFloat(String(t.tieRatioStr).replace('%', '')).toFixed(0).padStart(2)}% ` +
                    `${name} #${t.uid} ${liveFlags(t.live)}`);
            });
            const bestPick = getBest();
            console.log(`${line()}
  Best: ${bestPick ? displayTableName(bestPick.name) : '(none)'} · pick.best() · pick.summary()
${line()}
`);
        },

        check: (uidOrId) => {
            const t = pp?.get(uidOrId);
            if (!t) {
                console.log('Table not found');
                return null;
            }

            const r = scoreTable(t);
            const d = r.diagnostics || {};
            console.log(`
┌────────────────────────────────────────────────────────────
│ ${displayTableName(t.name || t.gameId).slice(0, 54)}
│ id ${t.uid} · game ${(t.gameId || '').slice(0, 32)}
├────────────────────────────────────────────────────────────
│ PASS firewall: ${r.eligible ? 'YES ✓' : 'NO ✗'}   display score: ${r.score}
└────────────────────────────────────────────────────────────`);

            console.log(`  Shoe   P:${t.P} B:${t.B} T:${t.T} total:${t.total}`);
            console.log(`  |P−B|/total: ${((d.pbGapRatio ?? 0) * 100).toFixed(2)}%  (reject if > ${Config.MAX_PB_GAP_RATIO * 100}%)`);
            console.log(`  ties/total:   ${((d.tieRatio ?? 0) * 100).toFixed(2)}%  (reject if > ${Config.MAX_TIE_RATIO * 100}%)`);
            console.log(`  Chop depth   PP:${d.pp ?? '—'}  BP:${d.bp ?? '—'}  max:${d.effective ?? 0}  [${d.depthSource}]`);
            const cr = d.crowd || {};
            console.log(`  Crowd pct    Player:${cr.playerPct != null ? `${cr.playerPct.toFixed(1)}%` : '—'}  Banker:${cr.bankerPct != null ? `${cr.bankerPct.toFixed(1)}%` : '—'}  (reject ≥${Config.MAX_CROWD_PCT}% on loaded side)`);
            console.log(`  Alt last-12: ${countAlternations(getSequence(t).slice(-12))} (fallback when depths missing)`);

            if (r.firewall?.length) {
                console.log('  REASONS:', r.firewall.join(' · '));
            }
            return r;
        },

        summary: () => {
            const rows = topN(5);
            console.log('\n═══ TOP 5 (eligible) ═══\n');
            rows.forEach((t, i) => {
                const chop = `${t.pingPong.effective}`.padStart(2);
                const gap = `${(Math.abs((t.P || 0) - (t.B || 0)) / (t.total || 1) * 100).toFixed(0)}%`;
                console.log(
                    `${i + 1}. ${scoreIcon(t.score, true)} ${displayTableName(t.name || '').slice(0, 26).padEnd(26)} chop:${chop} gap:${gap} ` +
                        `tie:${parseFloat(String(t.tieRatioStr).replace('%', '')).toFixed(0)}% uid:${t.uid}`
                );
            });
            console.log('');
        },

        live: (uidOrId) => pp?.live(uidOrId) || null,

        help: () => {
            console.log(`
╔════════════════════════════════════════════════════════════════════╗
║  pick v4 — firewall + PingPong depth (goodroadLive / lobby map)          ║
╠════════════════════════════════════════════════════════════════════╣
║  HARD REJECT                                                          ║
║  • total < ${Config.MIN_TOTAL}                                                         ║
║  • T/total > ${Config.MAX_TIE_RATIO * 100}% (tie storm)                                  ║
║  • |P−B|/total > ${Config.MAX_PB_GAP_RATIO * 100}% (gravity)                              ║
║  • betstats: playerPct or bankerPct ≥ ${Config.MAX_CROWD_PCT}% (crowd herd)                       ║
║                                                                       ║
║  SORT (eligible rows)                                                  ║
║  • max(playerPingPongDepth, bankerPingPongDepth) ↑ first              ║
║  • then |P−B|/total lower better                                      ║
║  • fallback chop signal: alternations in last 12                      ║
║                                                                       ║
║  COMMANDS pick.status · pick.summary · pick.check(uid) · pick.best() ║
╚════════════════════════════════════════════════════════════════════╝
`);
        },
    };

    console.log('[Pick] firewall + ping-pong depth + crowd');
    return api;

    };

    const createPlay = (pp, pick) => {

// ═══════════════════════════════════════════════════════════════════════
    // PROGRESSION CONFIGURATION (Martingale vs Paroli)
    // ═══════════════════════════════════════════════════════════════════════

    const Config = {
        /** `'martingale'` · LOSE → double up ladder | `'paroli'` · WIN → double, reset after loss or PAROLI_MAX_WIN_STREAK wins */
        PROGRESSION_MODE: 'paroli',
        /** After this many consecutive wins (using STEPS lengths), reset to step 1u. Only used when PROGRESSION_MODE is `'paroli'`. */
        PAROLI_MAX_WIN_STREAK: 3,

        // Martingale ladder (same steps used as Paroli “rungs”: 1u → 2u → 4u)
        STEPS: [1, 2, 4],           // Unit multipliers per step
        UNIT_FRACTION: 1/8,         // Unit = balance / 8
        MIN_UNIT: 0.2,              // Minimum unit size in dollars

        // Exit rules (in units)
        SESSION_STOP_LOSS: -6,      // Stop entire session
        SESSION_STOP_WIN: 3,        // Take profit at +3 units, start new session

        // Betting
        SIDE: null,                 // null = fair P/B each bet (see RANDOM_SIDE_ENGINE), 'B' / 'P' = fixed
        /** Only stake the hand whose previous road result is T. Scans **all** pp tables, not pick.eligible(). Off = every open eligible table. */
        BET_AFTER_TIE: true,
        /**
         * Used only when SIDE is null.
         * `math` = Math.random (default).
         * `crypto` = Web Crypto LSB.
         * `fair` = von Neumann extractor on crypto bits (unbiased 50/50).
         * `mix` = avalanche of crypto + time + bet index + table id, then LSB.
         * `shuffle` = crypto-shuffled 4P+4B shoe (exactly even each 8 bets).
         */
        RANDOM_SIDE_ENGINE: 'math',
        CHIP_VALUE: 0.20,           // Unit rounding; tray may also have $1 / $5 / …
        /** Gap between burst P/B clicks (ms). Keep short — betting window is often 1–2s. */
        CLICK_GAP_MS: 70,
        /** After each top-up P/B click, wait this long for wire/spot to move */
        CLICK_WIRE_WAIT_MS: 180,
        /** After retries are done, wait this long for late wire/spot (window may already be closed) */
        PLACE_CONFIRM_MS: 700,
        /** Brief settle after the planned burst, before top-up clicks */
        BURST_SETTLE_MS: 160,
        /** Extra clicks allowed if a click did not register on the wire */
        CLICK_RETRY: 8,
        CHIP_BAR_SEL: '[data-testid="chip-stack-bar"]',
        CHIP_BTN_PREFIX: 'chip-stack-value-',
        BET_DELAY: 2000,            // Delay between bet attempts (ms) when CONCURRENT is false
        /** Hunt other after-T tables without waiting for the previous hand to settle. Off = one-by-one. */
        CONCURRENT: true,
        /** Scan delay after a place (or when nothing is open) while concurrent. */
        CONCURRENT_SCAN_MS: 450,
        /** 0 = no cap. Live stakes are limited by wallet either way. */
        MAX_CONCURRENT: 0,
        /** After `canBet` is true, wait this long before clicking (ms). Jittered when HUMANIZE. */
        PRE_BET_DELAY_MS: 100,
        /** Vary timing and click point so bursts are not identical. Off = old fixed delays. */
        HUMANIZE: true,
        HUMAN_GAP_JITTER: 0.32,
        HUMAN_PRE_BET_MIN_MS: 70,
        HUMAN_PRE_BET_MAX_MS: 210,
        HUMAN_THINK_CHANCE: 0.2,
        HUMAN_THINK_MIN_MS: 30,
        HUMAN_THINK_MAX_MS: 140,
        HUMAN_BET_DELAY_JITTER: 0.28,
        WAIT_FOR_RESULT: 30000,     // Max wait for result (ms) - Speed Baccarat can be ~27s
        /** After clicks, wait for socks `pp.waitLpbet` (real <lpbet> on WS); requires socks ≥ 3.2.5 */
        LPBET_CONFIRM_MS: 3300,

        // DOM — PP multibaccarat 1.3.30 / core 26.7.0 (see core/elements.txt)
        PLAYER_BTN: '[data-betcode="0"]',
        BANKER_BTN: '[data-betcode="1"]',
        TILE_SEL: '[id^="TileHeight-"]',
        /** Current wallet first; keep mobile chip selectors as fallback. */
        WALLET_VALUE_SELS,
        POPUP_ROOT_SELS: [
            '[data-testid="popup"]',
            '[data-testid="popup-content"]',
            '[data-testid="blocking-popup-content"]',
            '[data-testid="modal"]',
        ],
        POPUP_TITLE_SEL: '[data-testid="blocking-popup-title"]',
        POPUP_BUTTON_SEL: 'button[data-testid="button"], button[data-testid="icon-button"], [data-testid="blocking-popup-buttons"] [data-testid="button"]',
        /** After Support OK reloads the iframe, wait this long for pp + wallet then Start */
        RESUME_AFTER_RELOAD: true,
        RESUME_WAIT_MS: 25000,

        // Table order among pick.eligible(): chop depth (goodroadLive) first, then pick score
        SORT_ELIGIBLE_BY_CHOP: true,

        // PP game WS: startshuffling → leave this table, wait, pick.pick another (keeps progression step)
        LEAVE_ON_SHUFFLE: true,
        SHUFFLE_SWITCH_DELAY_MS: 2000,
    };

    const RESUME_KEY = 'sb-play-resume';
    const resumeWanted = () => {
        try { return sessionStorage.getItem(RESUME_KEY) === '1'; } catch { return false; }
    };
    const setResumeWanted = (on) => {
        try {
            if (on) sessionStorage.setItem(RESUME_KEY, '1');
            else sessionStorage.removeItem(RESUME_KEY);
        } catch (_) {}
    };

    /** PP goodroadLive chop depth — same formula as console snippet (player vs banker ping-pong depth). */
    const getChopDepth = (t) => {
        if (!t) return 0;
        const gl = t.goodroadLive;
        const a = parseInt(gl?.playerPingPongDepth ?? 0, 10);
        const b = parseInt(gl?.bankerPingPongDepth ?? 0, 10);
        const pa = Number.isFinite(a) ? a : 0;
        const pb = Number.isFinite(b) ? b : 0;
        return Math.max(pa, pb);
    };

    const displayTableName = util.displayName;

    /** Game WS reports shuffle (new shoe prep) — socks merges startshuffling/endshuffling. */
    const tableIsShuffling = (tableId) => {
        if (!tableId || !pp) return false;
        const row = pp.get(tableId);
        if (row?.shuffling) return true;
        const live = pp.live(tableId);
        return !!(live?.shuffling?.active);
    };

    /** Leave table when shuffle starts; keep progression step for the next table. */
    const leaveTableForShuffle = (tableId) => {
        State.usedTables.add(tableId);
        State.focusedTable = null;
        State.tableBetCount = 0;
        log(
            `Shuffle on ${tableId}: switching table after wait · progression step unchanged (step ${State.currentStep + 1})`,
            'info'
        );
    };

    // ═══════════════════════════════════════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════════════════════════════════════

    const State = {
        // Session tracking (in units)
        sessionUnits: 0,            // +/- step-units this session (size may change each round)
        sessionProfitDollars: 0,    // dollar P/L using the unit in force for each bet
        sessionBets: 0,             // Total bets placed
        sessionWins: 0,             // Winning bets
        sessionLosses: 0,           // Losing bets
        sessionUnitSize: 0,         // Unit size for the current 1u round (recalc on ladder reset)
        sessionStartBalance: 0,     // Balance when session started

        // Current sequence
        currentStep: 0,             // Next STEPS index: Martingale advances on loss · Paroli advances on win (then cap reset)
        sequenceUnits: 0,           // Units in current sequence

        // Table focus (last / current bet target — multi mode picks open table each cycle)
        focusedTable: null,
        usedTables: new Set(),      // Skipped until play.clearUsed() (min bet, shuffle, etc.)
        /** tableId → shoe `total` when we last clicked (blocks a second click on the same after-T window). */
        stakedRoadTotal: new Map(),
        /** tableId → live bet still waiting on the road */
        pendingBets: new Map(),
        tableBetCount: 0,

        // Execution
        running: false,
        waitingForResult: false,
        lastBet: null,
        lastResult: null,

        // Timers
        popupBusy: false,
        intervalId: null,
        resultTimeout: null
    };

    // Calculate unit size: balance/8, rounded DOWN to nearest chip (0.2, 0.4, 0.6...)
    const calcUnitSize = (balance) => {
        const calculated = balance * Config.UNIT_FRACTION;
        // Round DOWN to nearest chip value (must be multiple of CHIP_VALUE)
        const rounded = Math.floor(calculated / Config.CHIP_VALUE) * Config.CHIP_VALUE;
        return Math.max(Config.MIN_UNIT, rounded);
    };

    const fmtUnitCount = (n, signed = false) => {
        const v = Number(n) || 0;
        const shown = Math.abs(v - Math.round(v)) < 1e-9 ? String(Math.round(v)) : v.toFixed(2);
        const word = Math.abs(Number(shown)) === 1 ? 'unit' : 'units';
        if (signed) {
            const sign = v > 0 ? '+' : '';
            return `${sign}${shown} ${word}`;
        }
        return `${shown} ${word}`;
    };

    // Get current unit size (recomputed when a Paroli/Martingale round returns to 1 unit)
    const getUnitSize = () => State.sessionUnitSize || Config.MIN_UNIT;

    const refreshUnitAfterRound = (opts = {}) => {
        const ui = getBalance();
        const estimated = (State.sessionStartBalance || 0) + (State.sessionProfitDollars || 0);
        const balance = opts.balance != null
            ? opts.balance
            : (Config.CONCURRENT !== false && estimated > 0 ? Math.max(ui, estimated) : ui);
        const next = calcUnitSize(balance);
        const prev = State.sessionUnitSize;
        State.sessionUnitSize = next;
        const changed = Math.abs(next - (prev || 0)) > 1e-9;
        log(
            `Round unit $${next.toFixed(2)}${changed && prev ? ` (was $${prev.toFixed(2)})` : ''} · wallet $${balance.toFixed(2)}`,
            'info',
        );
        return next;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // UTILITIES
    // ═══════════════════════════════════════════════════════════════════════

    const sleep = util.sleep;
    const randMs = (min, max) => {
        const a = Number(min) || 0;
        const b = Number(max) || 0;
        const lo = Math.min(a, b);
        const hi = Math.max(a, b);
        return Math.round(lo + Math.random() * (hi - lo));
    };
    const jitterMs = (base, frac) => {
        const b = Math.max(0, Number(base) || 0);
        const f = frac != null ? frac : (Config.HUMAN_GAP_JITTER ?? 0.32);
        const j = b * f;
        return Math.max(0, Math.round(b + (Math.random() * 2 - 1) * j));
    };
    const humanSleep = (base) => {
        if (Config.HUMANIZE === false) return sleep(base);
        return sleep(jitterMs(base));
    };
    const simulateClick = (el) => util.click(el);

    // Dark text + saturated labels — readable on DevTools light theme (avoid gray-200 / pastel on white)
    const LOG_STYLES = {
        info: { label: '[Play]', labelCss: 'color:#1d4ed8;font-weight:700;' },
        bet: { label: '[BET]', labelCss: 'color:#0f766e;font-weight:700;' },
        win: { label: '[WIN]', labelCss: 'color:#047857;font-weight:700;' },
        loss: { label: '[LOSS]', labelCss: 'color:#c2410c;font-weight:700;' },
        exit: {
            label: '[EXIT]',
            labelCss:
                'color:#fefce8;font-weight:800;background:#a16207;padding:2px 8px;border-radius:4px;',
        },
        error: {
            label: '[ERR]',
            labelCss:
                'color:#fef2f2;font-weight:800;background:#b91c1c;padding:2px 8px;border-radius:4px;',
        },
    };

    const uiEvents = [];
    let hudRefresh = null;

    const log = (msg, type = 'info') => {
        const cfg = LOG_STYLES[type] || LOG_STYLES.info;
        const bodyCss =
            type === 'exit'
                ? 'color:#92400e;font-weight:600;'
                : 'color:#0f172a;font-weight:500;';
        console.log(`%c${cfg.label}%c ${msg}`, cfg.labelCss, bodyCss);
        uiEvents.unshift({ at: Date.now(), type, msg: String(msg) });
        if (uiEvents.length > 80) uiEvents.length = 80;
        if (typeof hudRefresh === 'function') hudRefresh();
        try { hudBusSend({ kind: 'state', snapshot: snapshot() }); } catch (_) {}
    };

    // ═══════════════════════════════════════════════════════════════════════
    // BALANCE
    // ═══════════════════════════════════════════════════════════════════════

    let remoteWallet = 0;

    const getBalance = () => {
        const local = readDomWallet();
        if (local > 0) return local;
        if (remoteWallet > 0) return remoteWallet;
        return 0;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // TILE FINDING
    // ═══════════════════════════════════════════════════════════════════════

    const findTile = (tableId) => {
        if (!tableId) return null;
        const direct = document.getElementById(`TileHeight-${tableId}`);
        if (direct) return direct;
        const tiles = document.querySelectorAll(Config.TILE_SEL);
        for (const tile of tiles) {
            if (tile.id.includes(tableId)) return tile;
        }
        return null;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // TABLE SELECTION (from pick module) — multi-table: pick order, then first with canBet
    // ═══════════════════════════════════════════════════════════════════════

    const buildOrderedEligible = () => {
        if (!pick || !pp) return [];

        const pool = Config.BET_AFTER_TIE
            ? (typeof pick.all === 'function' ? pick.all() : pick.eligible())
            : pick.eligible();

        let tables = (pool || []).filter((t) => {
            const id = t.gameId || t.id;
            return id && !State.usedTables.has(id);
        });

        if (Config.SORT_ELIGIBLE_BY_CHOP) {
            tables = tables
                .map((t) => {
                    const id = t.gameId || t.id;
                    const full = pp.get(id) || t;
                    const chop = getChopDepth(full);
                    return { t, chop, score: t.score || 0 };
                })
                .sort((a, b) => {
                    if (b.chop !== a.chop) return b.chop - a.chop;
                    return b.score - a.score;
                })
                .map((x) => x.t);
        }

        return tables;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // SIDE SELECTION — fair 50/50 Banker vs Player when SIDE is null
    // ═══════════════════════════════════════════════════════════════════════

    const u32 = new Uint32Array(1);
    let sideShoe = [];

    const sideEngineLabel = (raw) => {
        switch (normalizeSideEngine(raw)) {
            case 'crypto': return 'crypto bit';
            case 'fair': return 'von Neumann';
            case 'mix': return 'mix hash';
            case 'shuffle': return 'shuffle 4+4';
            default: return 'Math.random';
        }
    };

    const randomU32 = () => {
        if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
            crypto.getRandomValues(u32);
            return u32[0] >>> 0;
        }
        return (Math.random() * 0x100000000) >>> 0;
    };

    const randomIndex = (n) => {
        const span = Math.max(1, n | 0);
        const max = Math.floor(0x100000000 / span) * span;
        for (;;) {
            const x = randomU32();
            if (x < max) return x % span;
        }
    };

    const bitToSide = (bit) => ((bit & 1) === 0 ? 'P' : 'B');

    const cryptoBit = () => randomU32() & 1;

    /** Unbiased 50/50: keep 01→P and 10→B, drop 00/11. */
    const vonNeumannBit = () => {
        for (let i = 0; i < 32; i++) {
            const a = cryptoBit();
            const b = cryptoBit();
            if (a !== b) return a;
        }
        return cryptoBit();
    };

    /** Independent 50/50; extra entropy so concurrent tables do not share a thin PRNG stream. */
    const mixHashBit = (tableId) => {
        let h = randomU32();
        h ^= Math.imul((State.sessionBets + 1) | 0, 0x9e3779b1);
        h ^= Math.floor((typeof performance !== 'undefined' ? performance.now() : Date.now()) * 1000) >>> 0;
        const tid = String(tableId || State.focusedTable?.gameId || '');
        for (let i = 0; i < tid.length; i++) {
            h = Math.imul(h ^ tid.charCodeAt(i), 16777619);
        }
        h ^= h >>> 16;
        h = Math.imul(h, 0x7feb352d);
        h ^= h >>> 15;
        h = Math.imul(h, 0x846ca68b);
        h ^= h >>> 16;
        return h & 1;
    };

    const refillSideShoe = () => {
        const deck = ['P', 'P', 'P', 'P', 'B', 'B', 'B', 'B'];
        for (let i = deck.length - 1; i > 0; i--) {
            const j = randomIndex(i + 1);
            const tmp = deck[i];
            deck[i] = deck[j];
            deck[j] = tmp;
        }
        sideShoe = deck;
    };

    const shuffleSide = () => {
        if (!sideShoe.length) refillSideShoe();
        return sideShoe.pop();
    };

    /** Uniform P/B. `math` default; other engines stay 50/50 (shuffle is exactly even per 8-bet shoe). */
    const randomSideFair = (tableId) => {
        const engine = normalizeSideEngine(Config.RANDOM_SIDE_ENGINE);
        if (engine === 'crypto') return bitToSide(cryptoBit());
        if (engine === 'fair') return bitToSide(vonNeumannBit());
        if (engine === 'mix') return bitToSide(mixHashBit(tableId));
        if (engine === 'shuffle') return shuffleSide();
        return Math.random() < 0.5 ? 'P' : 'B';
    };

    const chooseSide = (tableId) => {
        if (Config.SIDE === 'B') return 'B';
        if (Config.SIDE === 'P') return 'P';
        return randomSideFair(tableId);
    };

    // ═══════════════════════════════════════════════════════════════════════
    // BET EXECUTION
    // ═══════════════════════════════════════════════════════════════════════

    const roundCents = (n) => Math.round(Number(n) * 100) / 100;

    const tableMinBet = (table) => {
        const n = Number(table?.minBet);
        return Number.isFinite(n) && n > 0 ? n : 0;
    };

    const plannedDollars = () => {
        const chip = Config.CHIP_VALUE;
        const betDollars = getCurrentBetUnits() * getUnitSize();
        return Math.max(chip, Math.round(betDollars / chip) * chip);
    };

    const stakeForTable = (table) => {
        const planned = plannedDollars();
        const min = tableMinBet(table);
        if (min > 0 && planned + 1e-9 < min) {
            const chip = Config.CHIP_VALUE;
            return roundCents(Math.ceil(min / chip - 1e-9) * chip);
        }
        return planned;
    };

    const chipDisabled = (el) => !!(
        el.disabled
        || el.getAttribute('aria-disabled') === 'true'
        || el.hasAttribute('disabled')
    );

    const chipLooksSelected = (el) => {
        if (!el) return false;
        const pressed = String(el.getAttribute('aria-pressed') || '').toLowerCase();
        const checked = String(el.getAttribute('aria-checked') || '').toLowerCase();
        const current = String(el.getAttribute('aria-current') || '').toLowerCase();
        if (pressed === 'true' || checked === 'true' || current === 'true') return true;
        if (el.getAttribute('data-selected') === 'true') return true;
        const cls = `${el.className || ''} ${el.parentElement?.className || ''}`;
        return /\b(selected|is-selected|is-active|chip-selected)\b/i.test(cls);
    };

    const selectedChipValue = () => {
        const row = listChipButtons().find((c) => chipLooksSelected(c.el));
        return row ? row.value : 0;
    };

    const listChipButtons = () => {
        const prefix = Config.CHIP_BTN_PREFIX || 'chip-stack-value-';
        const root = document.querySelector(Config.CHIP_BAR_SEL) || document;
        const out = [];
        for (const el of root.querySelectorAll(`button[data-testid^="${prefix}"]`)) {
            const id = el.getAttribute('data-testid') || '';
            if (id.endsWith('-ring')) continue;
            const raw = id.slice(prefix.length);
            const value = parseFloat(raw);
            if (!Number.isFinite(value) || value <= 0) continue;
            out.push({
                value,
                el,
                disabled: chipDisabled(el),
            });
        }
        out.sort((a, b) => b.value - a.value);
        return out;
    };

    const chipPlan = (target, enabledDesc) => {
        const has = (v) => enabledDesc.some((c) => Math.abs(c.value - v) < 1e-9);
        const plan = [];
        let left = roundCents(target);

        // Stake ≥ $1: $1 chips first, then smaller (0.20…). Do not lead with $5.
        if (left + 1e-9 >= 1 && has(1)) {
            const n = Math.floor((left + 1e-9) / 1);
            for (let i = 0; i < n; i++) plan.push(1);
            left = roundCents(left - n);
        }

        const rest = enabledDesc
            .filter((c) => Math.abs(c.value - 1) > 1e-9)
            .slice()
            .sort((a, b) => b.value - a.value);
        for (const { value } of rest) {
            while (left + 1e-9 >= value) {
                plan.push(value);
                left = roundCents(left - value);
            }
        }
        return { plan, leftover: left };
    };

    const groupChipPlan = (plan) => {
        const groups = [];
        for (const value of plan) {
            const last = groups[groups.length - 1];
            if (last && Math.abs(last.value - value) < 1e-9) last.count++;
            else groups.push({ value, count: 1 });
        }
        return groups;
    };

    const chipsForStake = (target, chips) => {
        const tray = chips.filter((c) => !c.disabled);
        if (target + 1e-9 >= 1) {
            for (const c of chips) {
                if (c.value + 1e-9 < 1) continue;
                if (tray.some((t) => Math.abs(t.value - c.value) < 1e-9)) continue;
                tray.push(c);
            }
            tray.sort((a, b) => b.value - a.value);
        }
        return tray;
    };

    const selectChip = async (value) => {
        const match = (c) => Math.abs(c.value - value) < 1e-9;
        for (let attempt = 0; attempt < 3; attempt++) {
            const chips = listChipButtons();
            const row = chips.find(match);
            if (!row) return false;
            const cur = chips.find((c) => chipLooksSelected(c.el));
            if (cur && match(cur)) return true;
            // Ring nodes stay in the DOM for every enabled chip. Always click.
            await simulateClick(row.el);
            await humanSleep(attempt === 0 ? 70 : 110);
            const after = listChipButtons();
            const now = after.find((c) => chipLooksSelected(c.el));
            if (now && match(now)) return true;
            if (now && !match(now)) continue;
            // Tray does not expose selected state — we did click the chip we need.
            if (!after.some((c) => chipLooksSelected(c.el))) return true;
        }
        const last = selectedChipValue();
        return last > 0 ? Math.abs(last - value) < 1e-9 : true;
    };

    const formatChipPlan = (groups) => groups.map((g) => {
        const v = g.value >= 1 ? `$${g.value}` : `$${g.value.toFixed(2)}`;
        return g.count > 1 ? `${v}×${g.count}` : v;
    }).join(' + ') || '—';

    const placeBet = async (tile, betDollars, side, tableId, since) => {
        const selector = side === 'B' ? Config.BANKER_BTN : Config.PLAYER_BTN;
        const unitChip = Config.CHIP_VALUE;
        let target = Math.max(unitChip, Math.round(betDollars / unitChip) * unitChip);
        const gap = Config.CLICK_GAP_MS || 70;
        const waitMs = Config.CLICK_WIRE_WAIT_MS || 180;
        const settleMs = Config.BURST_SETTLE_MS || 160;
        const confirmMs = Config.PLACE_CONFIRM_MS || 700;
        const empty = { ok: false, amount: 0, target, clicks: 0 };

        const wired = () => {
            if (typeof pp?.lpbetStake === 'function') {
                return Number(pp.lpbetStake(tableId, { side, since })) || 0;
            }
            return 0;
        };

        const readSpotStake = (el) => {
            if (!el) return 0;
            const cell = el.parentElement || el;
            const bits = [
                el.getAttribute('data-amount'),
                el.getAttribute('data-bet-amount'),
                el.getAttribute('aria-label'),
                el.innerText,
                cell.innerText,
            ].filter(Boolean).join(' ');
            let best = 0;
            const re = /\$?\s*(\d+(?:\.\d{1,2})?)/g;
            let m;
            while ((m = re.exec(bits)) !== null) {
                const n = parseFloat(m[1]);
                if (!Number.isFinite(n) || n < unitChip - 1e-9) continue;
                const steps = n / unitChip;
                if (Math.abs(steps - Math.round(steps)) > 1e-6) continue;
                if (n > best) best = n;
            }
            return best;
        };

        let btn = null;
        const felt = () => roundCents(Math.max(wired(), readSpotStake(btn)));
        const atTarget = () => felt() + 1e-9 >= target;
        const bookedAmount = () => {
            const wireAmt = roundCents(wired());
            const spotAmt = roundCents(readSpotStake(btn));
            // Wire <lpbet> is the wager. Felt text is only a fallback while lpbet lags.
            return wireAmt > 0 ? wireAmt : spotAmt;
        };
        const windowOpen = () => {
            const t = pp?.get(tableId);
            return !t || t.canBet !== false;
        };
        const pollUntil = async (pred, ms) => {
            const deadline = Date.now() + ms;
            while (Date.now() < deadline) {
                if (pred()) return true;
                await sleep(20);
            }
            return pred();
        };
        const tap = async () => {
            btn = tile.querySelector(selector) || btn;
            await simulateClick(btn);
        };

        const chips = listChipButtons();
        let tray = chipsForStake(target, chips);
        if (!tray.length) {
            log('No chips in tray', 'error');
            return empty;
        }
        let { plan, leftover } = chipPlan(target, tray);
        if (leftover > 1e-9) {
            const made = roundCents(target - leftover);
            if (made + 1e-9 >= Math.max(unitChip, target >= 1 ? 1 : 0)) {
                log(`Tray leftover $${leftover.toFixed(2)} — staking $${made.toFixed(2)}`, 'info');
                target = made;
                leftover = 0;
                plan = chipPlan(target, tray).plan;
            }
        }
        const groups = groupChipPlan(plan);
        const maxClicks = Math.max(plan.length, 1) + (Config.CLICK_RETRY || 8);

        if (leftover > 1e-9) {
            log(`Can't make $${target.toFixed(2)} from tray [${tray.map((c) => c.value).join(', ')}] leftover $${leftover.toFixed(2)}`, 'error');
            return empty;
        }
        if (target + 1e-9 >= 1 && !plan.some((v) => v + 1e-9 >= 1)) {
            log(`Stake $${target.toFixed(2)} needs a $1 chip — none in tray`, 'error');
            return empty;
        }

        const lead = groups[0]?.value;
        const leadNote = target + 1e-9 < 1
            ? ' · $0.20 first'
            : (target + 1e-9 >= 1 ? ' · $1 first' : '');
        log(`Chip plan ${formatChipPlan(groups)} → $${target.toFixed(2)}${leadNote}`, 'info');

        for (let i = 0; i < 20; i++) {
            btn = tile.querySelector(selector);
            if (btn) break;
            await sleep(25);
        }
        if (!btn) return empty;

        if (Config.HUMANIZE !== false && Math.random() < (Config.HUMAN_THINK_CHANCE ?? 0.2)) {
            await sleep(randMs(Config.HUMAN_THINK_MIN_MS ?? 30, Config.HUMAN_THINK_MAX_MS ?? 140));
        }

        let clicks = 0;
        let armed = 0;
        const arm = async (value) => {
            const okSel = await selectChip(value);
            if (okSel) armed = value;
            return okSel;
        };

        // Always arm the chip we will click with. A leftover $1 chip would wager $1 on a $0.20 plan.
        if (lead == null || !(await arm(lead))) {
            log(`Could not select $${lead ?? unitChip} chip before P/B`, 'error');
            return empty;
        }

        for (const g of groups) {
            if (atTarget()) break;
            if (Math.abs(armed - g.value) > 1e-9 && !(await arm(g.value))) {
                log(`Could not select $${g.value} chip`, 'error');
                break;
            }
            const remain0 = roundCents(target - felt());
            if (armed > remain0 + 1e-9) {
                log(`Armed $${armed} > remain $${remain0.toFixed(2)} — will not click P/B`, 'error');
                break;
            }
            for (let i = 0; i < g.count && clicks < maxClicks; i++) {
                if (atTarget()) break;
                const before = felt();
                await tap();
                clicks++;
                await pollUntil(() => atTarget() || felt() > before + 1e-9, waitMs);
                const got = felt();
                if (got > target + 1e-9 && g.value + 1e-9 < 1 && got + 1e-9 >= 1) {
                    log(`P/B used $1 chip (wanted $${g.value.toFixed(2)}) — booked $${got.toFixed(2)}`, 'error');
                    break;
                }
                if (i < g.count - 1 && !atTarget()) await humanSleep(gap);
            }
        }

        if (!atTarget()) await pollUntil(atTarget, settleMs);

        while (clicks < maxClicks && !atTarget() && windowOpen()) {
            const remain = roundCents(target - felt());
            const one = tray.find((c) => Math.abs(c.value - 1) < 1e-9);
            const fit = tray.filter((c) => c.value <= remain + 1e-9);
            const chip = (remain + 1e-9 >= 1 && one && one.value <= remain + 1e-9)
                ? one
                : (fit.length ? fit[fit.length - 1] : null);
            // Do not tap with a leftover $1 while we still need $0.20.
            if (!chip || chip.value > remain + 1e-9) break;
            if (Math.abs(armed - chip.value) > 1e-9 && !(await arm(chip.value))) break;
            const before = felt();
            await tap();
            clicks++;
            await pollUntil(() => atTarget() || felt() > before + 1e-9, waitMs);
            const got = felt();
            if (got > target + 1e-9 && chip.value + 1e-9 < 1 && got + 1e-9 >= 1) {
                log(`P/B used $1 chip (wanted $${chip.value.toFixed(2)}) — booked $${got.toFixed(2)}`, 'error');
                break;
            }
        }

        if (!atTarget()) await pollUntil(atTarget, confirmMs);
        if (atTarget() && wired() <= 0) await pollUntil(() => wired() > 0, confirmMs);

        const amount = bookedAmount();
        const over = amount > target + 1e-9;
        const ok = amount + 1e-9 >= target && !over;
        log(
            `${ok ? 'Placed' : (over ? 'Overshot after' : 'Short stake after')} ${clicks} P/B · ${formatChipPlan(groups)} · booked $${amount.toFixed(2)} · wire $${wired().toFixed(2)} · spot $${readSpotStake(btn).toFixed(2)} / $${target.toFixed(2)}`,
            ok ? 'info' : 'error',
        );
        return { ok, amount, target, clicks };
    };

    // ═══════════════════════════════════════════════════════════════════════
    // RESULT DETECTION
    // ═══════════════════════════════════════════════════════════════════════

    const getTableLastResult = (tableId) => {
        if (!pp || !tableId) return null;
        const pbt = pp.lastN(tableId, 1) || [];
        const fromSeq = pbt[pbt.length - 1];
        if (fromSeq === 'P' || fromSeq === 'B' || fromSeq === 'T') return fromSeq;

        const t = pp.get(tableId);
        const g = t?.lastGameresult;
        if (g && typeof g === 'object') {
            const w = String(g.winner || g.result || g.outcome || '').toUpperCase();
            if (w.includes('TIE')) return 'T';
            if (w.includes('PLAYER')) return 'P';
            if (w.includes('BANKER')) return 'B';
        }
        return fromSeq || null;
    };

    const waitForResult = async (tableId, lastKnownCount) => {
        const startTime = Date.now();
        let lastLoggedTotal = null;

        while (Date.now() - startTime < Config.WAIT_FOR_RESULT) {
            if (!State.running) return 'STOPPED';
            const t = pp?.get(tableId);
            if (!t) {
                log(`Table ${tableId} not found in pp`, 'error');
                await sleep(500);
                continue;
            }

            // Log when total changes (for debugging)
            if (t.total !== lastLoggedTotal) {
                console.log(`[DEBUG] ${tableId}: total=${t.total} (waiting for >${lastKnownCount}), updates=${t.updates}`);
                lastLoggedTotal = t.total;
            }

            // Detect shoe reset during wait (total dropped to 0 or 1)
            if (lastKnownCount > 5 && t.total <= 1) {
                log(`Shoe reset during wait (total: ${lastKnownCount} → ${t.total})`, 'info');
                return 'SHOE_RESET';
            }

            if (Config.LEAVE_ON_SHUFFLE && tableIsShuffling(tableId)) {
                log(
                    'Shuffle started while waiting for result — leaving table (outcome not applied)',
                    'info'
                );
                return 'SHUFFLE';
            }

            if (t.total > lastKnownCount) {
                // New result arrived
                const result = getTableLastResult(tableId);
                log(`Result detected: ${result} (total: ${lastKnownCount} → ${t.total})`, 'info');
                return result;
            }
            await sleep(200);
        }
        log(`Timeout after ${Config.WAIT_FOR_RESULT/1000}s - total still ${lastLoggedTotal}, needed >${lastKnownCount}`, 'error');
        return null; // Timeout
    };

    // ═══════════════════════════════════════════════════════════════════════
    // EXIT CONDITIONS
    // ═══════════════════════════════════════════════════════════════════════

    const checkExitConditions = () => {
        // Session stop-loss / take-profit — disabled for now (uncomment to restore)
        // if (State.sessionUnits <= Config.SESSION_STOP_LOSS) {
        //     log(`SESSION STOP-LOSS reached: ${State.sessionUnits} units`, 'exit');
        //     return { exit: true, reason: 'stop-loss' };
        // }
        // if (State.sessionUnits >= Config.SESSION_STOP_WIN) {
        //     log(`TAKE PROFIT: +${State.sessionUnits} units`, 'win');
        //     return { exit: true, reason: 'take-profit' };
        // }

        return { exit: false };
    };

    // Start a new session (after taking profit)
    const startNewSession = () => {
        const balance = getBalance();
        const oldUnits = State.sessionUnits;
        
        // Reset session state
        State.sessionUnits = 0;
        State.sessionProfitDollars = 0;
        State.sessionBets = 0;
        State.sessionWins = 0;
        State.sessionLosses = 0;
        State.currentStep = 0;
        State.sequenceUnits = 0;
        State.focusedTable = null;
        State.usedTables.clear();
        State.stakedRoadTotal.clear();
        State.pendingBets.clear();
        State.tableBetCount = 0;
        
        // Recalculate unit size based on new balance
        State.sessionStartBalance = balance;
        State.sessionUnitSize = calcUnitSize(balance);
        
        console.log(`%c[NEW SESSION] Balance: $${balance.toFixed(2)} | Unit: $${State.sessionUnitSize.toFixed(2)} | Previous: ${fmtUnitCount(oldUnits, true)}`, 'background: #4CAF50; color: white; font-weight: bold; padding: 2px 6px; border-radius: 3px;');
    };

    /**
     * @param resetProgression true only for sequence exit (max-loss path); false when switching tables mid-progression
     */
    const markTableDone = (tableId, reason, resetProgression = false) => {
        State.usedTables.add(tableId);
        log(
            `Table ${tableId} DONE (${reason})${resetProgression ? ' · progression reset' : ' · step unchanged'}`,
            'exit'
        );
        State.focusedTable = null;
        if (resetProgression) {
            State.currentStep = 0;
            State.sequenceUnits = 0;
        }
        State.tableBetCount = 0;
    };

    /**
     * Walk pick order; first table with bets open, OK shoe, not shuffling, meets min bet.
     * When BET_AFTER_TIE, last road result must be T (next hand is the after-T bet).
     */
    const findFirstOpenTableForBet = (ordered) => {
        for (const row of ordered) {
            const id = row.gameId || row.id;
            if (!id) continue;

            const fresh = pp?.get(id);
            if (!fresh) continue;
            if ((fresh.total || 0) <= 1) continue;
            if (Config.LEAVE_ON_SHUFFLE && tableIsShuffling(id)) continue;
            if (!fresh.canBet) continue;
            if (Config.BET_AFTER_TIE && getTableLastResult(id) !== 'T') continue;
            if (State.stakedRoadTotal.get(id) === (fresh.total || 0)) continue;
            if (State.pendingBets.has(id)) continue;

            const stake = stakeForTable(fresh);
            if (getBalance() + 1e-9 < stake) continue;

            return { freshTable: fresh, pickRow: row, stake };
        }
        return null;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // PROGRESSION LOGIC (Martingale + Paroli)
    // ═══════════════════════════════════════════════════════════════════════

    const useParoli = () => Config.PROGRESSION_MODE === 'paroli';

    const getCurrentBetUnits = () => {
        const idx = Math.min(Math.max(0, State.currentStep), Config.STEPS.length - 1);
        return Config.STEPS[idx] ?? Config.STEPS[0];
    };

    const processResult = (result, bet = null) => {
        const rec = bet || State.lastBet || {};
        const betUnits = rec.units || getCurrentBetUnits();
        const betSide = rec.side || 'B';
        const unitSize = rec.unitSize || getUnitSize();
        const prefix = rec.table ? `${rec.table} | ` : '';
        const won = (result === betSide);
        const concurrent = Config.CONCURRENT !== false;

        if (result === 'T') {
            log(`${prefix}TIE - push (no units change)`, 'info');
            State.lastResult = 'T';
            return;
        }

        const stakeDollars = rec.dollars != null ? rec.dollars : betUnits * unitSize;
        const credit = (didWin) => {
            State.sessionProfitDollars += didWin ? stakeDollars : -stakeDollars;
        };

        if (concurrent) {
            if (won) {
                credit(true);
                State.sessionUnits += betUnits;
                State.sessionWins++;
                State.lastResult = 'W';
                log(
                    `${prefix}WON +$${stakeDollars.toFixed(2)} (${fmtUnitCount(betUnits)}) (${betSide}) | Session: ${fmtUnitCount(State.sessionUnits, true)}`,
                    'win'
                );
            } else {
                credit(false);
                State.sessionUnits -= betUnits;
                State.sequenceUnits -= betUnits;
                State.sessionLosses++;
                State.lastResult = 'L';
                log(
                    `${prefix}LOST -$${stakeDollars.toFixed(2)} (${fmtUnitCount(betUnits)}) | Session: ${fmtUnitCount(State.sessionUnits, true)}`,
                    'loss'
                );
            }
            refreshUnitAfterRound();
            return;
        }

        if (useParoli()) {
            if (won) {
                credit(true);
                State.sessionUnits += betUnits;
                State.sessionWins++;
                State.lastResult = 'W';
                State.sequenceUnits = 0;
                State.currentStep += 1;
                const cap = Math.min(Config.PAROLI_MAX_WIN_STREAK, Config.STEPS.length);
                if (State.currentStep >= cap) {
                    log(
                        `${prefix}WON +$${stakeDollars.toFixed(2)} (${fmtUnitCount(betUnits)}) (${betSide}) | Session: ${fmtUnitCount(State.sessionUnits, true)} | Paroli: ${cap} wins — reset → 1 unit next`,
                        'win'
                    );
                    State.currentStep = 0;
                    refreshUnitAfterRound();
                } else {
                    const nextU = Config.STEPS[State.currentStep] ?? Config.STEPS[0];
                    log(
                        `${prefix}WON +$${stakeDollars.toFixed(2)} (${fmtUnitCount(betUnits)}) (${betSide}) | Session: ${fmtUnitCount(State.sessionUnits, true)} | Next bet: ${nextU} unit (win ${State.currentStep}/${cap})`,
                        'win'
                    );
                }
            } else {
                credit(false);
                State.sessionUnits -= betUnits;
                State.sequenceUnits -= betUnits;
                State.sessionLosses++;
                State.lastResult = 'L';
                State.currentStep = 0;
                log(
                    `${prefix}LOST -$${stakeDollars.toFixed(2)} (${fmtUnitCount(betUnits)}) | Session: ${fmtUnitCount(State.sessionUnits, true)} | Paroli reset → next 1 unit`,
                    'loss'
                );
                refreshUnitAfterRound();
            }
            return;
        }

        if (won) {
            credit(true);
            State.sessionUnits += betUnits;
            State.sessionWins++;
            State.lastResult = 'W';
            State.currentStep = 0;
            State.sequenceUnits = 0;
            log(`${prefix}WON +$${stakeDollars.toFixed(2)} (${fmtUnitCount(betUnits)}) (${betSide}) | Session: ${fmtUnitCount(State.sessionUnits, true)} | Next bet: 1 unit`, 'win');
            refreshUnitAfterRound();
        } else {
            credit(false);
            State.sessionUnits -= betUnits;
            State.sequenceUnits -= betUnits;
            State.sessionLosses++;
            State.currentStep++;
            State.lastResult = 'L';

            log(`${prefix}LOST -$${stakeDollars.toFixed(2)} (${fmtUnitCount(betUnits)}) | Session: ${fmtUnitCount(State.sessionUnits, true)}`, 'loss');

            if (State.currentStep >= Config.STEPS.length) {
                log(`Max step reached (lost 7 units) | Finding new table`, 'loss');
                const tableId =
                    rec.tableId || State.focusedTable?.gameId || State.focusedTable?.id;
                if (tableId) {
                    markTableDone(tableId, 'max-loss', true);
                }
                refreshUnitAfterRound();
            } else {
                log(`Next bet: ${getCurrentBetUnits()} units (doubling)`, 'info');
            }
        }
    };

    // ═══════════════════════════════════════════════════════════════════════
    // MAIN BETTING LOOP
    // ═══════════════════════════════════════════════════════════════════════

    const betCycle = async () => {
        if (!State.running) return;

        // Check session exit conditions
        const exit = checkExitConditions();
        if (exit.exit) {
            // Check if we can start a new session (have minimum unit)
            const balance = getBalance();
            const minUnit = calcUnitSize(balance);
            if (balance >= minUnit) {
                // Start new session
                startNewSession();
                scheduleNext();
                return;
            }
            // Not enough balance - stop completely
            stop();
            return;
        }

        // Check balance (wait for UI to update after wins)
        const neededUnits = getCurrentBetUnits();
        const unitSize = getUnitSize();
        const neededDollars = neededUnits * unitSize;

        let balance = getBalance();
        if (balance < neededDollars) {
            if (State.pendingBets.size > 0) {
                scheduleNext(Config.CONCURRENT_SCAN_MS ?? 450);
                return;
            }
            log(`Balance low ($${balance.toFixed(2)}) - waiting 6s for UI update...`, 'info');
            await sleep(6000);
            balance = getBalance();
            if (balance < neededDollars) {
                // Can't afford current step - check if we can afford minimum unit
                const minBet = unitSize; // 1 unit
                if (balance >= minBet) {
                    // Reset to step 1 and start new session
                    log(
                        `Can't cover next stake ($${balance.toFixed(2)} < $${neededDollars.toFixed(2)}) — reset to 1 unit, new table`,
                        'info'
                    );
                    State.currentStep = 0;
                    State.sequenceUnits = 0;
                    if (State.focusedTable) {
                        const tableId = State.focusedTable.gameId || State.focusedTable.id;
                        markTableDone(tableId, 'cant-double', false);
                    }
                    scheduleNext();
                    return;
                }
                log(`Balance too low: $${balance.toFixed(2)} < $${minBet.toFixed(2)} minimum`, 'exit');
                stop();
                return;
            }
            log(`Balance updated: $${balance.toFixed(2)} - continuing`, 'info');
        }

        // Multi-table: each cycle, first pick.eligible() row with canBet (progression state global)
        const ordered = buildOrderedEligible();
        if (!ordered.length) {
            log('No tables (pp empty or all in usedTables)', 'exit');
            stop();
            return;
        }

        const maxLive = Number(Config.MAX_CONCURRENT) || 0;
        if (maxLive > 0 && State.pendingBets.size >= maxLive) {
            scheduleNext(Config.CONCURRENT_SCAN_MS ?? 450);
            return;
        }

        const picked = findFirstOpenTableForBet(ordered);
        if (!picked) {
            if (Config.BET_AFTER_TIE) {
                const now = Date.now();
                if (!State._afterTWaitLog || now - State._afterTWaitLog > 12000) {
                    State._afterTWaitLog = now;
                    log('Waiting for last road = T on any open table', 'info');
                }
            }
            scheduleNext(500);
            return;
        }

        let freshTable = picked.freshTable;
        const tableId = freshTable.gameId || freshTable.id;
        State.focusedTable = freshTable;

        const chop = getChopDepth(pp.get(tableId) || freshTable);
        log(
            `Open: ${displayTableName(freshTable.name || tableId)} | chop:${chop} | score:${picked.pickRow.score} | ` +
                `P:${freshTable.P} B:${freshTable.B} T:${freshTable.T}`,
            'info'
        );

        if (!tableId) {
            log('Table has no valid ID', 'error');
            State.focusedTable = null;
            scheduleNext();
            return;
        }

        if ((freshTable.total || 0) <= 1) {
            markTableDone(tableId, 'new-shoe', false);
            scheduleNext();
            return;
        }

        if (Config.LEAVE_ON_SHUFFLE && tableIsShuffling(tableId)) {
            leaveTableForShuffle(tableId);
            scheduleNext(Config.SHUFFLE_SWITCH_DELAY_MS);
            return;
        }

        await sleep(
            Config.HUMANIZE === false
                ? Config.PRE_BET_DELAY_MS
                : randMs(Config.HUMAN_PRE_BET_MIN_MS ?? 70, Config.HUMAN_PRE_BET_MAX_MS ?? 210),
        );

        freshTable = pp?.get(tableId) || freshTable;
        if (!freshTable || !freshTable.canBet) {
            scheduleNext(400);
            return;
        }
        if (Config.LEAVE_ON_SHUFFLE && tableIsShuffling(tableId)) {
            leaveTableForShuffle(tableId);
            scheduleNext(Config.SHUFFLE_SWITCH_DELAY_MS);
            return;
        }

        const tile = findTile(freshTable.gameId) || findTile(freshTable.lobbyId) || findTile(freshTable.id);
        if (!tile) {
            log(`Tile not found for ${displayTableName(freshTable.name || tableId)} (gameId:${freshTable.gameId}, lobbyId:${freshTable.lobbyId})`, 'error');
            scheduleNext();
            return;
        }

        const countBefore = freshTable.total || 0;
        const betSide = chooseSide(tableId);
        tile.scrollIntoView({
            block: Config.HUMANIZE === false || Math.random() < 0.45 ? 'center' : 'nearest',
            inline: 'nearest',
        });
        for (let i = 0; i < 24; i++) {
            if (tile.querySelector(Config.PLAYER_BTN) && tile.querySelector(Config.BANKER_BTN)) break;
            await sleep(50);
        }
        const betUnits = getCurrentBetUnits();
        const tableMin = tableMinBet(freshTable);
        let actualBet = picked.stake != null ? picked.stake : stakeForTable(freshTable);
        if (tableMin > 0 && actualBet + 1e-9 < tableMin) {
            actualBet = stakeForTable(freshTable);
        }
        if (tableMin > 0 && plannedDollars() + 1e-9 < actualBet) {
            log(
                `${displayTableName(freshTable.name || tableId)} | table min $${tableMin.toFixed(2)} → stake $${actualBet.toFixed(2)} ($1 chip)`,
                'info',
            );
        }

        const afterT = Config.BET_AFTER_TIE ? 'after T | ' : '';
        log(`${displayTableName(freshTable.name || tableId)} | ${afterT}Step ${State.currentStep + 1} | ${betSide} ${fmtUnitCount(betUnits)} ($${actualBet.toFixed(2)})`, 'bet');

        const wireSince = Date.now();
        const placed = await placeBet(tile, actualBet, betSide, tableId, wireSince);
        let landed = Number(placed?.amount) || 0;
        const minChip = Config.CHIP_VALUE;
        const readWire = () => (typeof pp?.lpbetStake === 'function'
            ? Number(pp.lpbetStake(tableId, { side: betSide, since: wireSince })) || 0
            : 0);

        if (landed + 1e-9 < actualBet && typeof pp?.waitLpbet === 'function') {
            await pp.waitLpbet(tableId, {
                side: betSide,
                since: wireSince,
                minTotal: actualBet,
                timeoutMs: 600,
            });
        }
        const wireAmt = readWire();
        if (wireAmt > 0) {
            if (Math.abs(wireAmt - landed) > 1e-9) {
                log(`Wire stake $${wireAmt.toFixed(2)} (felt booked $${landed.toFixed(2)})`, 'info');
            }
            landed = wireAmt;
        }
        landed = roundCents(landed);

        if (landed + 1e-9 < minChip) {
            log('Bet placement failed', 'error');
            scheduleNext();
            return;
        }
        if (landed > actualBet + 1e-9) {
            log(`Overshot stake $${landed.toFixed(2)} / $${actualBet.toFixed(2)} — watching result`, 'error');
        } else if (landed + 1e-9 < actualBet) {
            log(`Keeping short stake $${landed.toFixed(2)} / $${actualBet.toFixed(2)} — watching result`, 'info');
        }
        State.stakedRoadTotal.set(tableId, countBefore);

        const landedUnits = unitSize > 0 ? landed / unitSize : betUnits;
        State.sessionBets++;
        const betRec = {
            table: displayTableName(freshTable.name || tableId),
            tableId,
            side: betSide,
            units: landedUnits,
            unitSize,
            dollars: landed,
            countBefore,
            step: State.currentStep + 1,
            time: Date.now(),
        };
        State.lastBet = betRec;
        State.stakedRoadTotal.set(tableId, countBefore);

        if (Config.CONCURRENT === false) {
            State.waitingForResult = true;
            log('Waiting for result...', 'info');
            const result = await waitForResult(tableId, countBefore);
            State.waitingForResult = false;
            if (result === 'STOPPED') return;
            if (result === 'SHOE_RESET') {
                log('Shoe reset - moving to new table (bet voided)', 'info');
                markTableDone(tableId, 'shoe-reset', false);
                scheduleNext();
                return;
            }
            if (result === 'SHUFFLE') {
                leaveTableForShuffle(tableId);
                scheduleNext(Config.SHUFFLE_SWITCH_DELAY_MS);
                return;
            }
            if (result === null) {
                log('Result timeout - treating as loss', 'error');
                processResult(betRec.side === 'B' ? 'P' : 'B', betRec);
            } else {
                processResult(result, betRec);
            }
            await sleep(3000);
            const tableAfter = pp?.get(tableId);
            if (tableAfter && tableAfter.total === 0) {
                log(`New shoe detected (total=0) - moving to new table`, 'info');
                markTableDone(tableId, 'new-shoe', false);
                scheduleNext();
                return;
            }
            const exitAfter = checkExitConditions();
            if (exitAfter.exit) {
                const balanceAfter = getBalance();
                const minUnitAfter = calcUnitSize(balanceAfter);
                if (balanceAfter >= minUnitAfter) {
                    startNewSession();
                    scheduleNext();
                    return;
                }
                stop();
                return;
            }
            scheduleNext();
            return;
        }

        State.pendingBets.set(tableId, betRec);
        State.waitingForResult = true;
        log(`${betRec.table} | watching result · ${State.pendingBets.size} live · hunting next`, 'info');
        void watchPending(betRec);
        scheduleNext(Config.CONCURRENT_SCAN_MS ?? 450);
    };

    const watchPending = async (bet) => {
        const result = await waitForResult(bet.tableId, bet.countBefore);
        if (State.pendingBets.get(bet.tableId) !== bet) return;
        State.pendingBets.delete(bet.tableId);
        State.waitingForResult = State.pendingBets.size > 0;
        if (!State.running || result === 'STOPPED') return;
        if (result === 'SHOE_RESET') {
            log(`${bet.table} | Shoe reset — stake voided`, 'info');
            markTableDone(bet.tableId, 'shoe-reset', false);
            return;
        }
        if (result === 'SHUFFLE') {
            leaveTableForShuffle(bet.tableId);
            return;
        }
        if (result === null) {
            log(`${bet.table} | Result timeout - treating as loss`, 'error');
            processResult(bet.side === 'B' ? 'P' : 'B', bet);
            return;
        }
        processResult(result, bet);
    };

    const scheduleNext = (delay) => {
        if (!State.running) return;
        const fallback = Config.CONCURRENT === false
            ? Config.BET_DELAY
            : (Config.CONCURRENT_SCAN_MS ?? 450);
        let ms = delay != null ? delay : fallback;
        if (Config.HUMANIZE !== false) {
            ms = jitterMs(delay, delay === Config.BET_DELAY ? (Config.HUMAN_BET_DELAY_JITTER ?? 0.28) : 0.12);
        }
        State.intervalId = setTimeout(betCycle, Math.max(0, ms));
    };

    // ═══════════════════════════════════════════════════════════════════════
    // POPUP HANDLING
    // ═══════════════════════════════════════════════════════════════════════

    const SUPPORT_RE = /please contact customer support|contact\s+customer\s+support/i;
    const INSUFFICIENT_RE = /insufficient\s+funds/i;

    const normPopupText = (el) => (el?.textContent || '').replace(/\s+/g, ' ').trim();

    const isOkLabel = (el) => /^\s*ok\s*$/i.test((el.textContent || '').replace(/\s+/g, ' ').trim());

    const ancestorWith = (el, re) => {
        let n = el;
        for (let i = 0; i < 10 && n && n !== document.body; i++) {
            if (re.test(normPopupText(n))) return n;
            n = n.parentElement;
        }
        return null;
    };

    const findPopupButton = (kind) => {
        const re = kind === 'insufficient' ? INSUFFICIENT_RE : SUPPORT_RE;
        for (const sel of Config.POPUP_ROOT_SELS) {
            for (const el of document.querySelectorAll(sel)) {
                if (!re.test(normPopupText(el))) continue;
                const btn = el.querySelector(Config.POPUP_BUTTON_SEL)
                    || [...el.querySelectorAll('button, [role="button"]')].find(isOkLabel);
                if (btn) return btn;
            }
        }
        for (const btn of document.querySelectorAll('button, [role="button"]')) {
            if (!isOkLabel(btn)) continue;
            if (ancestorWith(btn, re)) return btn;
        }
        return null;
    };

    const clickThroughHud = async (el) => {
        const hud = document.getElementById('sb-play-hud');
        const prev = hud ? hud.style.pointerEvents : '';
        if (hud) hud.style.pointerEvents = 'none';
        try {
            return await simulateClick(el);
        } finally {
            if (hud) hud.style.pointerEvents = prev;
        }
    };

    const handlePopup = () => {
        if (State.popupBusy) return;

        const supportBtn = findPopupButton('support');
        const insufficientBtn = supportBtn ? null : findPopupButton('insufficient');
        const btn = supportBtn || insufficientBtn;
        if (!btn) return;

        State.popupBusy = true;
        if (supportBtn) {
            log('Support popup — OK, will resume after iframe reload', 'info');
            setResumeWanted(true);
            void (async () => {
                await clickThroughHud(btn);
                stop({ keepResume: true, silent: true });
                await util.sleep(1600);
                if (findPopupButton('support')) {
                    log('Support popup still up — will retry OK', 'info');
                    State.popupBusy = false;
                }
            })();
            return;
        }

        log('Insufficient funds popup - stopping', 'exit');
        void (async () => {
            await clickThroughHud(btn);
            stop();
            State.popupBusy = false;
        })();
    };

    const watchForPopup = () => {
        const attach = () => {
            if (!document.body) {
                setTimeout(attach, 50);
                return;
            }
            handlePopup();
            const observer = new MutationObserver(handlePopup);
            observer.observe(document.body, { childList: true, subtree: true });
        };
        attach();
    };

    // ═══════════════════════════════════════════════════════════════════════
    // CONTROL API
    // ═══════════════════════════════════════════════════════════════════════

    const start = async () => {
        if (State.running) {
            log('Already running');
            return;
        }
        const attached = await util.ensureDebugger();
        if (!attached) log('Debugger attach failed — clicks fall back to dispatchEvent', 'error');

        // Pre-flight checks
        if (!pp) {
            log('pp API missing', 'error');
            return;
        }
        if (!pick) {
            log('pick API missing', 'error');
            return;
        }

        const balance = getBalance();
        if (balance < Config.MIN_UNIT) {
            log(`Balance too low: $${balance.toFixed(2)}`, 'error');
            return;
        }

        // Calculate unit size for this session (1/8 of balance, min 0.2)
        State.sessionStartBalance = balance;
        State.sessionUnitSize = calcUnitSize(balance);

        State.running = true;
        State.pendingBets.clear();
        State.waitingForResult = false;
        setResumeWanted(true);
        const sideMode =
            Config.SIDE === null
                ? `RANDOM 50/50 (${sideEngineLabel(Config.RANDOM_SIDE_ENGINE)})`
                : Config.SIDE;
        const paroliCap = Math.min(Config.PAROLI_MAX_WIN_STREAK, Config.STEPS.length);
        const modeLine = useParoli()
            ? `Paroli (${paroliCap} wins cap) WIN→raise rung · LOSE→reset`
            : `Martingale WIN→1 unit · LOSE→double (${Config.STEPS.join('→')} units)`;
        log(`STARTED | Balance: $${balance.toFixed(2)} | Unit: $${State.sessionUnitSize.toFixed(2)} (1/${Math.round(1/Config.UNIT_FRACTION)} of balance)`, 'info');
        log(`${modeLine} | Side: ${sideMode} | After T only: ${Config.BET_AFTER_TIE ? 'YES (all tables)' : 'no'} | Concurrent: ${Config.CONCURRENT === false ? 'no' : 'YES'} | Stop-loss: ${fmtUnitCount(Config.SESSION_STOP_LOSS, true)} | Stop-win: ${fmtUnitCount(Config.SESSION_STOP_WIN, true)}`);

        betCycle();
    };

    const stop = (opts = {}) => {
        State.running = false;
        State.pendingBets.clear();
        State.waitingForResult = false;
        if (State.intervalId) {
            clearTimeout(State.intervalId);
            State.intervalId = null;
        }
        if (!opts.keepResume) setResumeWanted(false);
        if (!opts.silent) {
            log(`STOPPED | Session: ${State.sessionUnits > 0 ? '+' : ''}${State.sessionUnits} units | W:${State.sessionWins} L:${State.sessionLosses}`, 'info');
        }
    };

    const reset = () => {
        stop();
        State.sessionUnits = 0;
        State.sessionProfitDollars = 0;
        State.sessionBets = 0;
        State.sessionWins = 0;
        State.sessionLosses = 0;
        State.sessionUnitSize = 0;
        State.sessionStartBalance = 0;
        State.currentStep = 0;
        State.sequenceUnits = 0;
        State.focusedTable = null;
        State.usedTables.clear();
        State.stakedRoadTotal.clear();
        State.pendingBets.clear();
        State.tableBetCount = 0;
        State.lastBet = null;
        State.lastResult = null;
        sideShoe = [];
        log('Session RESET', 'info');
    };

    const snapshot = () => {
        const balance = getBalance();
        const unitSize = getUnitSize();
        const profitDollars = State.sessionProfitDollars;
        const nextUnits = getCurrentBetUnits();
        const nextBetDollars = nextUnits * unitSize;
        const table = State.focusedTable;
        let tableRows = [];
        try {
            let rows = [];
            if (Config.BET_AFTER_TIE && typeof pick?.all === 'function') {
                const all = pick.all() || [];
                const withT = [];
                const rest = [];
                for (const t of all) {
                    const id = t.gameId || t.id;
                    if (id && getTableLastResult(id) === 'T') withT.push(t);
                    else rest.push(t);
                }
                rows = withT.concat(rest).slice(0, 8);
            } else {
                rows = pick?.top?.(6) || [];
            }
            tableRows = rows.map((t) => {
                const id = t.gameId || t.id;
                const live = State.pendingBets.has(id);
                const last = (() => {
                    try { return pp?.lastN?.(id, 1)?.[0] || ''; } catch { return ''; }
                })();
                return {
                    id,
                    name: displayTableName(t.name || id || '?'),
                    chip: `chop ${t.pingPong?.effective ?? 0}${last ? ` · ${last}` : ''}`,
                    open: live ? 'live' : (t.canBet ? 'open' : 'wait'),
                    ok: live || !!t.canBet,
                };
            });
        } catch (_) {
            tableRows = [];
        }
        const ppN = typeof pp?.count === 'function' ? pp.count() : 0;
        return {
            running: State.running,
            waiting: State.pendingBets.size > 0 || State.waitingForResult,
            pending: State.pendingBets.size,
            pendingIds: [...State.pendingBets.keys()],
            concurrent: Config.CONCURRENT !== false,
            mode: useParoli() ? 'paroli' : 'martingale',
            side: Config.SIDE,
            sideEngine: normalizeSideEngine(Config.RANDOM_SIDE_ENGINE),
            balance,
            startBalance: State.sessionStartBalance || balance,
            unitSize,
            sessionUnits: State.sessionUnits,
            profitDollars,
            bets: State.sessionBets,
            wins: State.sessionWins,
            losses: State.sessionLosses,
            currentStep: State.currentStep,
            nextUnits,
            nextBetDollars,
            sequenceUnits: State.sequenceUnits,
            tableName: displayTableName(table?.name || table?.gameId || ''),
            tableId: table?.gameId || table?.id || null,
            lastBet: State.lastBet,
            lastResult: State.lastResult,
            afterTie: !!Config.BET_AFTER_TIE,
            usedTables: [...State.usedTables],
            events: uiEvents.slice(0, 60),
            tableRows,
            readyLine: `pp ${ppN} tables · ${Config.BET_AFTER_TIE ? 'after T' : 'pick'} · ${State.usedTables.size} skipped`,
            iframe: true,
        };
    };

    const status = () => {
        const s = snapshot();
        console.log(`
╔══════════════════════════════════════════════════════════════╗
║               PLAY STATUS: ${(s.mode === 'paroli' ? 'Paroli' : 'Martingale').padEnd(10)}                               ║
╠══════════════════════════════════════════════════════════════╣
║  Running: ${s.running ? 'YES' : 'NO '}                                              ║
║  Balance: $${s.balance.toFixed(2).padEnd(8)}  Start: $${s.startBalance.toFixed(2).padEnd(8)}         ║
║  Unit: $${s.unitSize.toFixed(2)} (1/${Math.round(1 / Config.UNIT_FRACTION)} of wallet each round, min $${Config.MIN_UNIT})          ║
╠══════════════════════════════════════════════════════════════╣
║  Session Units: ${String((s.sessionUnits > 0 ? '+' : '') + s.sessionUnits).padEnd(5)}  ($${(s.profitDollars > 0 ? '+' : '') + s.profitDollars.toFixed(2)})                    ║
║  Bets: ${String(s.bets).padEnd(3)} Wins: ${String(s.wins).padEnd(3)} Losses: ${String(s.losses).padEnd(3)}                      ║
╠══════════════════════════════════════════════════════════════╣
║  Next Bet: ${fmtUnitCount(s.nextUnits)} ($${s.nextBetDollars.toFixed(2)})                                    ║
║  Sequence P/L: ${s.sequenceUnits} units                                   ║
║  Table: ${String(s.tableName || 'None').slice(0, 25).padEnd(25)}                   ║
╠══════════════════════════════════════════════════════════════╣
║  Stop-Loss: ${Config.SESSION_STOP_LOSS} units | Stop-Win: +${Config.SESSION_STOP_WIN} units               ║
╚══════════════════════════════════════════════════════════════╝
`);
        return s;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // API
    // ═══════════════════════════════════════════════════════════════════════

    const setTable = (uidOrId) => {
        const t = pp?.get(uidOrId);
        if (t) {
            State.focusedTable = t;
            State.tableBetCount = 0;
            log(`Manually set table: ${displayTableName(t.name || t.gameId)}`);
        }
        return t || null;
    };

    const clearUsed = () => {
        State.usedTables.clear();
        log('Cleared used tables list - can reuse all tables');
    };

    // ═══════════════════════════════════════════════════════════════════════
    // ON-PAGE HUD
    // ═══════════════════════════════════════════════════════════════════════

    const HUD_POS_KEY = 'sb-play-hud-pos';
    const HUD_MIN_KEY = 'sb-play-hud-min';
    const HUD_HUNT_KEY = 'sb-play-hud-hunt';
    const HUD_RNG_KEY = 'sb-play-hud-rng';

    const esc = util.esc;
    const fmtSigned = util.signed;

    const mountHud = () => {
        if (document.getElementById('sb-play-hud')) return;

        const host = document.createElement('div');
        host.id = 'sb-play-hud';
        const saved = (() => {
            try { return JSON.parse(localStorage.getItem(HUD_POS_KEY) || 'null'); } catch { return null; }
        })();
        Object.assign(host.style, {
            position: 'fixed',
            zIndex: '2147483646',
            top: saved?.top || '12px',
            left: saved?.left || '',
            right: saved?.left ? '' : '16px',
            width: `${HUD_WIDTH}px`,
            height: `${HUD_HEIGHT}px`,
            maxHeight: 'calc(100dvh - 16px)',
            fontFamily: 'Inter, Segoe UI, system-ui, sans-serif',
        });
        const shadow = host.attachShadow({ mode: 'open' });

        shadow.innerHTML = `
<style>
  :host { display: block; max-height: inherit; }
  * { box-sizing: border-box; }
  .wrap {
    background: linear-gradient(180deg, #15243f 0%, #0c1628 100%);
    color: #e8eef8;
    border: 1px solid #2a3a56;
    border-radius: 14px;
    box-shadow: 0 12px 36px rgba(0,0,0,.5);
    overflow: hidden;
    user-select: none;
    display: flex;
    flex-direction: column;
    position: relative;
    height: 100%;
    min-height: 0;
    max-height: none;
  }
  .wrap.collapsed { min-height: 0; height: auto; max-height: none; }
  .wrap.collapsed .bar { border-bottom: none; }
  .rsz { position: absolute; z-index: 4; }
  .rsz.e { top: 22px; right: 0; width: 10px; bottom: 18px; cursor: ew-resize; }
  .rsz.s { left: 18px; bottom: 0; right: 18px; height: 10px; cursor: ns-resize; }
  .rsz.se { right: 0; bottom: 0; width: 18px; height: 18px; cursor: nwse-resize; }
  .rsz.se::after {
    content: ''; position: absolute; right: 4px; bottom: 4px;
    width: 9px; height: 9px; border-right: 2px solid #8aa0bd; border-bottom: 2px solid #8aa0bd;
  }
  .wrap.collapsed .rsz { display: none; }
  .bar {
    display: flex; align-items: center; gap: 8px;
    padding: 6px 8px; cursor: move;
    background: #0f1a2d; border-bottom: 1px solid #22314d;
    flex: 0 0 auto;
  }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: #64748b; flex: 0 0 auto; }
  .dot.on { background: #34d399; box-shadow: 0 0 8px #34d399; }
  .dot.wait { background: #fbbf24; box-shadow: 0 0 8px #fbbf24; }
  .title { font-size: 12px; font-weight: 700; letter-spacing: .3px; flex: 1; }
  .phase { font-size: 11px; color: #9aa9c2; white-space: nowrap; }
  .icon {
    background: #111a2c; color: #e8eef8; border: 1px solid #2a3a56;
    border-radius: 5px; width: 22px; height: 20px; cursor: pointer; font-size: 12px;
  }
  .body { padding: 8px; overflow: hidden; min-height: 0; flex: 1 1 auto; display: flex; flex-direction: column; }
  .row { display: flex; gap: 6px; margin-bottom: 6px; flex: 0 0 auto; }
  button.act {
    flex: 1; border: 1px solid #2a3a56; border-radius: 6px;
    padding: 5px 8px; font-size: 12px; font-weight: 700; cursor: pointer; color: #e8eef8;
    background: #111a2c;
  }
  button.start { background: #0d3d2b; border-color: #1f7b57; color: #8fffd0; }
  button.stop { background: #3a1225; border-color: #7e2d4f; color: #ffc0db; }
  button:disabled { opacity: .45; cursor: default; }
  label.fld { flex: 1; min-width: 0; font-size: 10px; color: #9aa9c2; display: flex; flex-direction: column; gap: 2px; }
  select {
    background: #111a2c; color: #e8eef8; border: 1px solid #2a3a56;
    border-radius: 6px; padding: 4px 4px; font-size: 11px;
  }
  select:disabled { opacity: .45; cursor: default; }
  .grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 5px; margin-bottom: 6px; flex: 0 0 auto; }
  .box { background: #0b1527; border: 1px solid #22314d; border-radius: 6px; padding: 4px 6px; }
  .k { font-size: 10px; color: #9aa9c2; }
  .v { font-size: 13px; font-weight: 700; }
  .v.up { color: #8fffd0; }
  .v.down { color: #ffc0db; }
  .table { font-size: 11px; color: #d5e2f7; margin: 0 0 4px; min-height: 14px; flex: 0 0 auto; }
  .tables { max-height: 72px; overflow: auto; margin-bottom: 6px; flex: 0 0 auto; }
  .trow {
    display: flex; align-items: center; gap: 6px;
    font-size: 11px; padding: 2px 6px; border-radius: 4px; cursor: pointer;
  }
  .trow:hover, .trow.active { background: #17365f; }
  .tname { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .chip { font-size: 10px; color: #9cd0ff; }
  .ok { color: #8fffd0; }
  .no { color: #9aa9c2; }
  .log {
    background: #050b16; border: 1px solid #1d2d45; border-radius: 6px;
    padding: 8px 10px; min-height: 0; flex: 1 1 auto; overflow: auto;
    font-family: ui-monospace, Consolas, "Cascadia Mono", monospace;
    font-size: 12px; line-height: 1.45; cursor: text;
    user-select: text; -webkit-user-select: text;
    overflow-wrap: anywhere; word-break: break-word;
  }
  .log div { color: #e8eef8; user-select: text; -webkit-user-select: text; margin: 0 0 2px; }
  .log .win { color: #8fffd0; }
  .log .loss { color: #ffc3d1; }
  .log .bet { color: #9cd0ff; }
  .log .error, .log .exit { color: #ffd6a1; }
  .ready { font-size: 10px; color: #9aa9c2; margin-top: 4px; flex: 0 0 auto; }
</style>
<div class="wrap">
  <div class="bar" id="bar">
    <span class="dot" id="dot"></span>
    <span class="title" id="hudTitle">Play HUD</span>
    <span class="phase" id="phase">stopped</span>
    <button class="icon" id="min" type="button" title="Minimize">–</button>
  </div>
  <div class="body" id="body">
    <div class="row">
      <button class="act start" id="start" type="button">Start</button>
      <button class="act stop" id="stop" type="button">Stop</button>
      <button class="act" id="reset" type="button">Reset</button>
    </div>
    <div class="row">
      <label class="fld">Mode
        <select id="mode">
          <option value="paroli">Paroli</option>
          <option value="martingale">Martingale</option>
        </select>
      </label>
      <label class="fld">Side
        <select id="side">
          <option value="random">Random</option>
          <option value="P">Player</option>
          <option value="B">Banker</option>
        </select>
      </label>
      <label class="fld">Hunt
        <select id="hunt">
          <option value="concurrent">Concurrent</option>
          <option value="serial">One by one</option>
        </select>
      </label>
      <label class="fld">P/B random
        <select id="rng" title="Only used when Side is Random. All methods are 50/50.">
          <option value="math">Math.random</option>
          <option value="crypto">Crypto bit</option>
          <option value="fair">Von Neumann</option>
          <option value="mix">Mix hash</option>
          <option value="shuffle">Shuffle 4+4</option>
        </select>
      </label>
    </div>
    <div class="grid">
      <div class="box"><div class="k">Balance</div><div class="v" id="bal">$0.00</div></div>
      <div class="box"><div class="k">Unit</div><div class="v" id="unit">$0.00</div></div>
      <div class="box"><div class="k">Session</div><div class="v" id="units">0 units</div></div>
      <div class="box"><div class="k">P/L</div><div class="v" id="pl">$0.00</div></div>
      <div class="box"><div class="k">W / L / Bets</div><div class="v" id="wlb">0 / 0 / 0</div></div>
      <div class="box"><div class="k">Next</div><div class="v" id="next">1 unit</div></div>
    </div>
    <div class="table" id="table">Table: —</div>
    <div class="tables" id="tables"></div>
    <div class="log" id="log"></div>
    <div class="ready" id="ready">Waiting for pp + pick…</div>
  </div>
</div>`;

        const $ = (id) => shadow.getElementById(id);
        const body = $('body');
        const minBtn = $('min');
        $('hudTitle').textContent = 'Play HUD';

        const applyStore = (store) => {
            Config.SIDE = store.side === 'P' || store.side === 'B' ? store.side : null;
            Config.PROGRESSION_MODE = store.mode === 'martingale' ? 'martingale' : 'paroli';
            Config.CONCURRENT = store.hunt !== 'serial';
            Config.RANDOM_SIDE_ENGINE = normalizeSideEngine(store.rng);
            $('mode').value = Config.PROGRESSION_MODE === 'martingale' ? 'martingale' : 'paroli';
            $('side').value = Config.SIDE || 'random';
            $('hunt').value = Config.CONCURRENT === false ? 'serial' : 'concurrent';
            $('rng').value = normalizeSideEngine(Config.RANDOM_SIDE_ENGINE);
        };

        let minimized = false;
        let hudSize = { width: HUD_WIDTH, height: HUD_HEIGHT };
        const persistHud = (patch) => { void writeHudStore(patch); };
        void readHudStore().then((store) => {
            applyStore(store);
            minimized = !!store.min;
            hudSize = { width: store.width || HUD_WIDTH, height: store.height || HUD_HEIGHT };
            if (store.left) {
                host.style.left = store.left;
                host.style.right = '';
            }
            if (store.top) host.style.top = store.top;
            applyMin();
            persistHud({ width: hudSize.width, height: hudSize.height, sizeGen: HUD_SIZE_GEN });
        });

        const FOOTER_PAD = 16;
        const clampHud = () => {
            const r = host.getBoundingClientRect();
            const maxLeft = Math.max(8, window.innerWidth - r.width - 8);
            const maxTop = Math.max(8, window.innerHeight - Math.min(r.height, window.innerHeight - FOOTER_PAD) - FOOTER_PAD);
            let left = r.left;
            let top = r.top;
            if (!Number.isFinite(left) || left < 8) left = 8;
            if (left > maxLeft) left = maxLeft;
            if (!Number.isFinite(top) || top < 8) top = 8;
            if (top > maxTop) top = maxTop;
            host.style.left = `${Math.round(left)}px`;
            host.style.top = `${Math.round(top)}px`;
            host.style.right = '';
            host.style.maxHeight = minimized
                ? 'none'
                : `${Math.max(200, window.innerHeight - top - FOOTER_PAD)}px`;
        };

        const wrap = shadow.querySelector('.wrap');
        const applyMin = () => {
            body.style.display = minimized ? 'none' : '';
            wrap.classList.toggle('collapsed', minimized);
            minBtn.textContent = minimized ? '+' : '–';
            minBtn.title = minimized ? 'Expand' : 'Collapse';
            if (minimized) {
                host.style.width = 'auto';
                host.style.height = 'auto';
                host.style.minWidth = '220px';
                host.style.minHeight = '0';
                host.style.maxHeight = 'none';
            } else {
                host.style.width = hudSize.width + 'px';
                host.style.height = hudSize.height + 'px';
                host.style.minWidth = '';
                host.style.minHeight = '';
                host.style.maxHeight = '';
            }
            requestAnimationFrame(clampHud);
        };
        bindHudResize(host, wrap, {
            isCollapsed: () => minimized,
            onSave: (box) => {
                hudSize = box;
                persistHud({ width: box.width, height: box.height, sizeGen: HUD_SIZE_GEN });
            },
        });
        applyMin();
        minBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            minimized = !minimized;
            persistHud({ min: minimized });
            applyMin();
        });
        $('bar').addEventListener('dblclick', (e) => {
            if (e.target.closest('button')) return;
            minimized = !minimized;
            persistHud({ min: minimized });
            applyMin();
        });

        $('start').addEventListener('click', () => start());
        $('stop').addEventListener('click', () => stop());
        $('reset').addEventListener('click', () => reset());
        $('mode').addEventListener('change', (e) => {
            Config.PROGRESSION_MODE = e.target.value === 'martingale' ? 'martingale' : 'paroli';
            persistHud({ mode: Config.PROGRESSION_MODE });
            log(`Mode → ${Config.PROGRESSION_MODE}`, 'info');
        });
        $('side').addEventListener('change', (e) => {
            Config.SIDE = e.target.value === 'random' ? null : e.target.value;
            persistHud({ side: e.target.value });
            log(`Side → ${Config.SIDE || 'random'}`, 'info');
        });
        $('hunt').addEventListener('change', (e) => {
            const concurrent = e.target.value !== 'serial';
            Config.CONCURRENT = concurrent;
            persistHud({ hunt: concurrent ? 'concurrent' : 'serial' });
            log(`Hunt → ${concurrent ? 'concurrent' : 'one by one'}`, 'info');
        });
        $('rng').addEventListener('change', (e) => {
            Config.RANDOM_SIDE_ENGINE = normalizeSideEngine(e.target.value);
            persistHud({ rng: Config.RANDOM_SIDE_ENGINE });
            log(`P/B random → ${sideEngineLabel(Config.RANDOM_SIDE_ENGINE)}`, 'info');
        });

        const bar = $('bar');
        let drag = null;
        bar.addEventListener('mousedown', (e) => {
            if (e.target.closest('button')) return;
            const r = host.getBoundingClientRect();
            drag = { dx: e.clientX - r.left, dy: e.clientY - r.top };
            e.preventDefault();
        });
        const onMove = (e) => {
            if (!drag) return;
            const left = Math.max(8, e.clientX - drag.dx);
            const top = Math.max(8, e.clientY - drag.dy);
            host.style.left = `${left}px`;
            host.style.top = `${top}px`;
            host.style.right = '';
        };
        const onUp = () => {
            if (!drag) return;
            drag = null;
            clampHud();
            persistHud({
                left: host.style.left,
                top: host.style.top,
            });
        };
        window.addEventListener('mousemove', onMove);
        window.addEventListener('mouseup', onUp);
        window.addEventListener('resize', clampHud);
        requestAnimationFrame(clampHud);

        const paint = () => {
            const s = snapshot();
            const ready = !!(pp && pick);
            const phase = !s.running
                ? 'stopped'
                : (s.pending > 0 ? `${s.pending} live` : (s.waiting ? 'waiting' : (s.afterTie ? 'wait T' : 'running')));
            const dot = $('dot');
            dot.className = `dot${s.running ? (s.waiting ? ' wait' : ' on') : ''}`;
            $('phase').textContent = phase;
            $('start').disabled = s.running;
            $('stop').disabled = !s.running;
            const focused = shadow.activeElement;
            if (focused !== $('mode')) $('mode').value = s.mode;
            if (focused !== $('side')) $('side').value = s.side || 'random';
            if (focused !== $('hunt')) $('hunt').value = s.concurrent ? 'concurrent' : 'serial';
            if (focused !== $('rng')) $('rng').value = s.sideEngine || 'math';
            $('bal').textContent = `$${s.balance.toFixed(2)}`;
            $('unit').textContent = `$${s.unitSize.toFixed(2)}`;
            const unitsEl = $('units');
            unitsEl.textContent = fmtUnitCount(s.sessionUnits, true);
            unitsEl.className = `v${s.sessionUnits > 0 ? ' up' : s.sessionUnits < 0 ? ' down' : ''}`;
            const plEl = $('pl');
            plEl.textContent = `$${fmtSigned(s.profitDollars)}`;
            plEl.className = `v${s.profitDollars > 0 ? ' up' : s.profitDollars < 0 ? ' down' : ''}`;
            $('wlb').textContent = `${s.wins} / ${s.losses} / ${s.bets}`;
            $('next').textContent = `${fmtUnitCount(s.nextUnits)} ($${s.nextBetDollars.toFixed(2)})`;
            const last = s.lastResult ? ` · last ${s.lastResult}` : '';
            const betSide = s.lastBet?.side ? ` · ${s.lastBet.side}` : '';
            $('table').textContent = `Table: ${s.tableName || '—'} · step ${s.currentStep + 1}${betSide}${last}`;

            let rows = [];
            try {
                if (s.afterTie && typeof pick?.all === 'function') {
                    const all = pick.all() || [];
                    const withT = [];
                    const rest = [];
                    for (const t of all) {
                        const id = t.gameId || t.id;
                        if (id && getTableLastResult(id) === 'T') withT.push(t);
                        else rest.push(t);
                    }
                    rows = withT.concat(rest).slice(0, 4);
                } else {
                    rows = pick?.top?.(4) || [];
                }
            } catch { rows = []; }
            $('tables').innerHTML = rows.length
                ? rows.map((t) => {
                    const id = t.gameId || t.id;
                    const name = displayTableName(t.name || id || '?');
                    const chop = t.pingPong?.effective ?? 0;
                    const live = Array.isArray(s.pendingIds) && s.pendingIds.includes(id);
                    const open = live ? 'live' : (t.canBet ? 'open' : 'wait');
                    const active = id && (id === s.tableId || live) ? ' active' : '';
                    const last = (() => {
                        try { return pp?.lastN?.(id, 1)?.[0] || ''; } catch { return ''; }
                    })();
                    const lastMark = last ? ` · ${last}` : '';
                    return `<div class="trow${active}" data-id="${esc(id)}">` +
                        `<span class="tname">${esc(name)}</span>` +
                        `<span class="chip">chop ${chop}${lastMark}</span>` +
                        `<span class="${live || t.canBet ? 'ok' : 'no'}">${open}</span></div>`;
                }).join('')
                : '<div class="trow"><span class="tname">No tables yet</span></div>';

            const logEl = $('log');
            const logHtml = (s.events || []).map((ev) =>
                `<div class="${esc(ev.type)}">${esc(ev.msg)}</div>`
            ).join('') || '<div>Ready — press Start</div>';
            const logKey = (s.events || []).map((ev) => `${ev.at}|${ev.msg}`).join('\n');
            const sel = (typeof shadow.getSelection === 'function' && shadow.getSelection())
                || document.getSelection();
            const selectingLog = !!(sel && !sel.isCollapsed && sel.rangeCount
                && logEl.contains(sel.anchorNode));
            if (!selectingLog && logEl.dataset.key !== logKey) {
                logEl.innerHTML = logHtml;
                logEl.dataset.key = logKey;
            }

            const ppN = typeof pp?.count === 'function' ? pp.count() : 0;
            $('ready').textContent = ready
                ? `pp ${ppN} tables · ${s.afterTie ? 'all' : 'pick'} ${rows.length} shown · ${s.usedTables.length} skipped${s.afterTie ? ' · bet after T (all tables)' : ''}`
                : 'Waiting for pp + pick…';
        };

        shadow.getElementById('tables').addEventListener('click', (e) => {
            const row = e.target.closest('[data-id]');
            if (!row) return;
            setTable(row.getAttribute('data-id'));
            paint();
        });

        hudRefresh = paint;
        paint();
        setInterval(paint, 500);
        document.documentElement.appendChild(host);
        return {
            show: () => { host.style.display = ''; },
            hide: () => { host.style.display = 'none'; },
            toggle: () => { host.style.display = host.style.display === 'none' ? '' : 'none'; },
            refresh: paint,
        };
    };

    let hudApi = null;
    const ensureHud = () => {
        if (hudApi) return hudApi;
        if (!document.documentElement) return null;
        hudApi = mountHud();
        return hudApi;
    };

    const api = {
        start,
        stop,
        reset,
        status,
        snapshot,
        s: status,
        config: Config,
        state: () => ({ ...State, usedTables: [...State.usedTables] }),
        setTable,
        clearUsed,
        balance: getBalance,
        units: () => State.sessionUnits,
        unitSize: getUnitSize,
        profit: () => State.sessionProfitDollars,
        hud: {
            show: () => ensureHud()?.show(),
            hide: () => hudApi?.hide(),
            toggle: () => ensureHud()?.toggle(),
        },
    };

    // ═══════════════════════════════════════════════════════════════════════
    // INITIALIZATION
    // ═══════════════════════════════════════════════════════════════════════

    watchForPopup();

    const applyIncomingConfig = (cfg) => {
        if (!cfg || typeof cfg !== 'object') return;
        if ('SIDE' in cfg) Config.SIDE = cfg.SIDE === 'P' || cfg.SIDE === 'B' ? cfg.SIDE : null;
        if (cfg.PROGRESSION_MODE === 'paroli' || cfg.PROGRESSION_MODE === 'martingale') {
            Config.PROGRESSION_MODE = cfg.PROGRESSION_MODE;
        }
        if ('CONCURRENT' in cfg) Config.CONCURRENT = cfg.CONCURRENT !== false;
        if (cfg.RANDOM_SIDE_ENGINE) Config.RANDOM_SIDE_ENGINE = normalizeSideEngine(cfg.RANDOM_SIDE_ENGINE);
    };

    const pushHudState = () => {
        try { hudBusSend({ kind: 'state', snapshot: snapshot() }); } catch (_) {}
    };

    window.addEventListener('message', (e) => {
        if (e.source !== window) return;
        const d = e.data;
        if (!d || d.source !== 'sb-ext-hud' || !d.payload) return;
        const p = d.payload;
        if (p.kind === 'wallet') {
            remoteWallet = Number(p.balance) || 0;
            return;
        }
        if (p.kind !== 'cmd') return;
        if (p.cmd === 'config') applyIncomingConfig(p.config);
        if (p.cmd === 'start') start();
        if (p.cmd === 'stop') stop();
        if (p.cmd === 'reset') reset();
        if (p.cmd === 'setTable' && p.id) setTable(p.id);
        if (p.cmd === 'ping') pushHudState();
    });

    const tryResumeAfterReload = async () => {
        if (Config.RESUME_AFTER_RELOAD === false) return;
        if (!resumeWanted()) return;
        log('Reload resume armed — waiting for tables + wallet', 'info');
        const deadline = Date.now() + (Config.RESUME_WAIT_MS || 25000);
        while (Date.now() < deadline) {
            ensureHud();
            const n = typeof pp?.count === 'function' ? pp.count() : 0;
            const bal = getBalance();
            if (n > 0 && bal >= Config.MIN_UNIT) {
                log('Resuming after iframe reload', 'info');
                start();
                return;
            }
            await sleep(400);
        }
        log('Resume wait timed out — press Start', 'error');
        setResumeWanted(false);
    };

    const bootHud = () => {
        void util.ensureDebugger();
        void readHudStore().then((store) => {
            Object.assign(Config, storeToConfigPatch(store));
            pushHudState();
        });
        if (document.documentElement) ensureHud();
        else document.addEventListener('DOMContentLoaded', ensureHud, { once: true });
        hudBusSend({ kind: 'hello', snapshot: snapshot() });
        setInterval(pushHudState, 400);
        const kick = () => { void tryResumeAfterReload(); };
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', kick, { once: true });
        } else {
            kick();
        }
    };
    bootHud();
    return api;

    };

    const pp = createPp();
    const pick = createPick(pp);
    const play = createPlay(pp, pick);

    global.pp = pp;
    global.pick = pick;
    global.play = play;
    global.sb = { version: VERSION, util, pp, pick, play };

    console.log(`[SB] v${VERSION} · extension · pp + pick + play HUD · trusted CDP clicks · sb.version`);
})(typeof window !== 'undefined' ? window : this);
