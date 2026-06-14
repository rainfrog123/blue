// ==UserScript==
// @name         pick-telegram-monitor
// @namespace    http://tampermonkey.net/
// @version      1.3.0
// @description  Telegram: on WIN/LOSS from play, only DOM wallet line after WIN_LOSS_UI_DELAY_MS (+ balance/session lines).
// @author       You
// @match        *://client.pragmaticplaylive.net/desktop/multibaccarat*
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @connect      api.telegram.org
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    /** Page globals + console live here when Tampermonkey uses a sandbox (GM_* grants). */
    const UW = typeof unsafeWindow !== 'undefined' ? unsafeWindow : window;

    const Config = {
        TELEGRAM_BOT_TOKEN: '7580665549:AAEiILYjLzZg34wIFOBZB-FtfUhsjQMBUrA',
        TELEGRAM_CHAT_ID: '1968437033',

        /**
         * Forward play.js `log()` lines that hit the page console.
         * Default = balance-only: leave PLAY_LOG_TAGS empty (no WIN/LOSS/ERR). Set tags to re-enable.
         */
        PLAY_LOG_TO_TELEGRAM: true,
        /** Empty = Telegram only wallet lines (below). Ex: ['[WIN]','[LOSS]','[EXIT]','[ERR]'] for full alerts. */
        PLAY_LOG_TAGS: [],
        /** `[NEW SESSION] Balance:` + `[Play]` rows matching PLAY_BALANCE_LINE_TEST (STARTED Balance, Balance low…). */
        PLAY_FORWARD_BALANCE: true,
        /** [Play] must match here; `[NEW SESSION]` always forwarded when PLAY_FORWARD_BALANCE is true. */
        PLAY_BALANCE_LINE_TEST:
            /\bBalance:\s*\$|\bBalance updated|Balance low|Can't cover next stake \(\$|\bUnit:\s*\$/i,

        /** Full pick table snapshot on an interval (off by default — “important only”). */
        TABLE_HEARTBEAT_ENABLED: false,
        STATS_INTERVAL_MS: 120000,
        TOP_ELIGIBLE: 12,
        TOP_REJECTED: 5,
        AUTO_START_TABLE_HEARTBEAT: false,

        MONITOR_TITLE: 'PP TABLE MONITOR',
        /** One boot message — off for balance-only (no chatter). */
        SEND_STARTUP_TELEGRAM: false,

        /** On each [WIN]/[LOSS] from play, send **only** delayed UI wallet (no `[WIN]`/`[LOSS]` text to Telegram). */
        WALLET_AFTER_WIN_LOSS: true,
        /**
         * Winning Banker profit / stake (commission). Stake $0.20 → profit $0.19 →Wallet line +$0.19 (not +$0.20).
         * Match your table: e.g. 0.39 back from 0.20 stake ⇒ (0.39 − 0.20) / 0.20 = 0.95.
         */
        BANKER_WIN_PROFIT_RATIO: 0.95,
        /** DOM wallet read waits this long **after** the first WIN/LOSS Telegram (`ui` / `both`). */
        /** After play logs [WIN]/[LOSS], read DOM wallet and Telegram once (ms). */
        WIN_LOSS_UI_DELAY_MS: 5000,
    };

    /** Tracks wallet from play logs (not DOM), same math as session units × session $/unit. */
    const ledger = { balanceUsd: null, unitUsd: null };

    const state = {
        sessionStart: Date.now(),
        ticks: 0,
        playLines: 0,
        sendsOk: 0,
        sendsFail: 0,
        lastSendAt: null,
        lastError: null,
        running: false,
    };

    let timer = null;
    let heartbeatSending = false;

    /** Use page console original so play’s logs hit our wrapper; our logs bypass the wrapper logic safely. */
    const origPageLog = UW.console.log.bind(UW.console);
    const _log = (...a) => origPageLog.apply(UW.console, a);
    const _warn = UW.console.warn.bind(UW.console);

    const displayName = (s) => String(s ?? '').replace(/_/g, ' ');

    const fmtUptime = (ms) => {
        const s = Math.floor(ms / 1000);
        const m = Math.floor(s / 60);
        const h = Math.floor(m / 60);
        if (h > 0) return `${h}h${m % 60}m`;
        if (m > 0) return `${m}m${s % 60}s`;
        return `${s}s`;
    };

    const send = (text) =>
        new Promise((resolve) => {
            const token = (Config.TELEGRAM_BOT_TOKEN || '').trim();
            const chatId = (Config.TELEGRAM_CHAT_ID || '').trim();
            if (!token || !chatId) {
                state.lastError = 'missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID';
                resolve(false);
                return;
            }
            const body = String(text).slice(0, 4000);
            GM_xmlhttpRequest({
                method: 'POST',
                url: `https://api.telegram.org/bot${encodeURIComponent(token)}/sendMessage`,
                headers: { 'Content-Type': 'application/json' },
                data: JSON.stringify({ chat_id: chatId, text: body, disable_web_page_preview: true }),
                onload(r) {
                    const ok = r.status >= 200 && r.status < 300;
                    if (!ok) state.lastError = `HTTP ${r.status} ${(r.responseText || '').slice(0, 100)}`;
                    else state.lastError = null;
                    resolve(ok);
                },
                onerror() {
                    state.lastError = 'network / GM xhr error';
                    resolve(false);
                },
            });
        });

    const recordSend = (ok) => {
        state.lastSendAt = Date.now();
        if (ok) state.sendsOk += 1;
        else state.sendsFail += 1;
    };

    /**
     * play.js styles:
     * · log(): `%c[LABEL]%c ${msg}` (two %c)
     * · new session: `%c[NEW SESSION] Balance: …` (one %c, rest is body)
     */
    /** Mirrors play.js `getBalance()` selector (Stake / PP launcher wallet chip). */
    const syncLedgerFromPlayBody = (tag, body) => {
        const s = String(body);
        const isWinLoss = tag === '[WIN]' || tag === '[LOSS]';

        if (!isWinLoss) {
            const bm = s.match(/\bBalance:\s*\$([\d.]+)/);
            const um = s.match(/\bUnit:\s*\$([\d.]+)/);
            if (bm) {
                const b = parseFloat(bm[1]);
                if (Number.isFinite(b)) ledger.balanceUsd = b;
            }
            if (um) {
                const u = parseFloat(um[1]);
                if (Number.isFinite(u)) ledger.unitUsd = u;
            }
            return;
        }

        if (ledger.balanceUsd == null || !Number.isFinite(ledger.unitUsd)) return;

        if (tag === '[WIN]') {
            const wm = s.match(/\bWON\s*\+(\d+)\s+units(?:\s*\(([BP])\))?/i);
            if (wm) {
                const n = parseInt(wm[1], 10);
                if (Number.isFinite(n)) {
                    const side = (wm[2] || 'P').toUpperCase();
                    const mult =
                        side === 'B' ? Number(Config.BANKER_WIN_PROFIT_RATIO) : 1;
                    const r = Number.isFinite(mult) && mult > 0 ? mult : 1;
                    ledger.balanceUsd += n * ledger.unitUsd * r;
                }
            }
        } else if (tag === '[LOSS]') {
            const lm = s.match(/\bLOST\s*-(\d+)\s+units/i);
            if (lm) {
                const n = parseInt(lm[1], 10);
                if (Number.isFinite(n)) ledger.balanceUsd -= n * ledger.unitUsd;
            }
        }
    };

    const readWalletUsd = () => {
        try {
            const el = UW.document.querySelector(
                '[data-testid="wallet-mobile-balance"] [data-testid="wallet-mobile-value"] span'
            );
            if (!el) return null;
            const x = parseFloat(String(el.textContent).replace(/[^0-9.]/g, ''));
            return Number.isFinite(x) ? x : null;
        } catch (_) {
            return null;
        }
    };

    const parsePlayConsoleFirstArg = (s0) => {
        if (typeof s0 !== 'string' || s0.indexOf('%c[') !== 0) return null;
        let m = s0.match(/^%c(\[[^\]]+\])%c\s*(.+)$/);
        if (m) return { tag: m[1], body: m[2].trim() };
        m = s0.match(/^%c(\[[^\]]+\])\s*(.+)$/);
        if (m) return { tag: m[1], body: m[2].trim() };
        return null;
    };

    const tryForwardPlayConsoleLog = (args) => {
        const s0 = args[0];
        const parsed = parsePlayConsoleFirstArg(s0);
        if (!parsed) return;

        const { tag, body } = parsed;
        syncLedgerFromPlayBody(tag, body);

        if (!Config.PLAY_LOG_TO_TELEGRAM) return;

        const allow = Config.PLAY_LOG_TAGS;
        const tagAllowed = Array.isArray(allow) && allow.includes(tag);

        const balRe =
            Config.PLAY_BALANCE_LINE_TEST instanceof RegExp
                ? Config.PLAY_BALANCE_LINE_TEST
                : /\bBalance\b|\bUnit:\s*\$|Can't cover next stake \(\$|Balance updated|Balance low/i;

        const balanceLine =
            !!Config.PLAY_FORWARD_BALANCE &&
            (tag === '[NEW SESSION]' || (tag === '[Play]' && balRe.test(body)));

        const winLossWallet =
            !!Config.WALLET_AFTER_WIN_LOSS && (tag === '[WIN]' || tag === '[LOSS]');

        if (!tagAllowed && !balanceLine && !winLossWallet) return;

        if (winLossWallet) {
            const uiDelayRaw = Number(Config.WIN_LOSS_UI_DELAY_MS);
            const uiDelayMs =
                Number.isFinite(uiDelayRaw) && uiDelayRaw >= 0 ? uiDelayRaw : 5000;
            const uiDelaySec = uiDelayMs / 1000;

            setTimeout(() => {
                state.playLines += 1;
                const w = readWalletUsd();
                const uiPart =
                    w != null ? `$${w.toFixed(2)}` : '— (selector empty / not ready)';
                const lineUi = `Wallet (UI · +${uiDelaySec}s): ${uiPart}`;
                send(lineUi).then((ok) => {
                    recordSend(ok);
                    if (!ok) _warn('[pick-telegram-monitor] UI balance send failed');
                });
            }, uiDelayMs);

            return;
        }

        state.playLines += 1;
        const line = `${tag} ${body}`;
        send(line).then((ok) => {
            recordSend(ok);
            if (!ok) _warn('[pick-telegram-monitor] play-line send failed');
        });
    };

    UW.console.log = function hookedPageLog(...args) {
        try {
            tryForwardPlayConsoleLog(args);
        } catch (_) {}
        return origPageLog.apply(UW.console, args);
    };

    const buildTableMessage = ({ previewMode } = {}) => {
        const tick = previewMode ? Math.max(1, state.ticks + 1) : state.ticks;
        const uptime = fmtUptime(Date.now() - state.sessionStart);
        const everySec = Math.max(30, (Config.STATS_INTERVAL_MS || 120000) / 1000);
        const title = Config.MONITOR_TITLE || 'MONITOR';

        const okRate =
            state.sendsOk + state.sendsFail > 0
                ? `${state.sendsOk}/${state.sendsOk + state.sendsFail} ok`
                : '—';

        let header =
            `═══ ${title} ═══\n` +
            `#${tick} · up ${uptime} · every ${everySec}s\n` +
            `play lines → TG: ${state.playLines} · prev: ${okRate}`;
        if (state.lastSendAt) header += ` · last TX ${fmtUptime(Date.now() - state.lastSendAt)} ago`;
        if (state.lastError) header += `\n⚠ last err: ${state.lastError.slice(0, 120)}`;

        header += `\n${new Date().toLocaleString()}`;

        if (!UW.pp) return `${header}\n\n[deps] pp missing — load socks first`;
        if (!UW.pick || typeof UW.pick.all !== 'function') {
            return `${header}\n\n[deps] pick missing`;
        }

        const wsMsgs = typeof UW.pp.msgs === 'function' ? UW.pp.msgs() : null;
        const seq = typeof UW.pp.seq === 'function' ? UW.pp.seq() : null;
        const stats = typeof UW.pp.stats === 'function' ? UW.pp.stats() : null;
        const lobbyN = stats?.lobbyPlayersCount?.total_seated_players;

        header += `\nstream: msgs${wsMsgs != null ? wsMsgs : '?'} seq${seq != null ? seq : '?'}`;
        if (lobbyN != null) header += ` · lobbyΣ${lobbyN}`;
        if (previewMode) header += `\n(preview — no send)`;

        const all = UW.pick.all();
        const eligible = all.filter((x) => x.eligible);
        let body = `\n── Tables ──\neligible ${eligible.length} / tracked ${all.length}\n`;

        const topE = eligible.slice(0, Config.TOP_ELIGIBLE);
        if (topE.length) {
            body += `\n★ Top eligible (sort: chop → balance → tie)\n`;
            topE.forEach((t, i) => {
                const bet = t.canBet ? '●' : '○';
                const gap = `${(Math.abs((t.P || 0) - (t.B || 0)) / (t.total || 1) * 100).toFixed(0)}`;
                const tieP = parseFloat(String(t.tieRatioStr).replace('%', ''));
                const name = displayName(t.name || t.gameId || '?').slice(0, 22);
                const chop = t.pingPong?.effective ?? 0;
                body +=
                    `${bet} ${i + 1}. s${String(t.score).padStart(3)} chop${String(chop).padStart(2)} ` +
                    `gap${gap.padStart(2)}% T${Number.isFinite(tieP) ? String(tieP.toFixed(0)).padStart(2) : '?'}% #${t.uid} ${name}\n`;
            });
        } else {
            body += `\n(no eligible this tick)\n`;
        }

        const rej = all.filter((x) => !x.eligible).slice(0, Config.TOP_REJECTED);
        if (rej.length) {
            body += `\n★ Sample firewall rejects\n`;
            rej.forEach((t) => {
                const r0 = (t.reasons && t.reasons[0]) || (t.firewall && t.firewall[0]) || '?';
                const name = displayName(t.name || t.gameId || '?').slice(0, 18);
                body += `· #${t.uid} ${name}\n  ${String(r0).slice(0, 90)}\n`;
            });
        }

        body += `\n── pickTelegram.stopHeartbeat() ──`;

        let out = header + body;
        if (out.length > 4000) out = `${out.slice(0, 3975)}\n…(truncated)`;
        return out;
    };

    const heartbeatTick = async () => {
        if (!Config.TELEGRAM_BOT_TOKEN || !Config.TELEGRAM_CHAT_ID || heartbeatSending) return;
        if (!UW.pp || !UW.pick?.all) return;

        heartbeatSending = true;
        try {
            state.ticks += 1;
            const text = buildTableMessage();
            const ok = await send(text);
            recordSend(ok);
            _log(`[${Config.MONITOR_TITLE}] heartbeat #${state.ticks} ${ok ? 'sent' : 'FAIL'}`);
        } finally {
            heartbeatSending = false;
        }
    };

    const startHeartbeat = () => {
        stopHeartbeat();
        if (!(Config.TELEGRAM_BOT_TOKEN && Config.TELEGRAM_CHAT_ID)) {
            _warn('[pick-telegram-monitor] missing token/chat_id');
            return;
        }
        state.running = true;
        state.sessionStart = Date.now();
        const ms = Math.max(30000, Config.STATS_INTERVAL_MS);
        heartbeatTick();
        timer = setInterval(heartbeatTick, ms);
        _log(
            `%c[${Config.MONITOR_TITLE}]`,
            'color:#0ea5e9;font-weight:700;',
            `table heartbeat · every ${ms / 1000}s · pickTelegram.stopHeartbeat()`
        );
    };

    const stopHeartbeat = () => {
        state.running = false;
        if (timer) {
            clearInterval(timer);
            timer = null;
        }
    };

    const api = {
        config: Config,
        state: () => ({ ...state, ledger: { ...ledger } }),
        /** Full table snapshot once */
        sendTableSnapshot: heartbeatTick,
        startHeartbeat,
        stopHeartbeat,
        /** Aliases */
        start: startHeartbeat,
        stop: stopHeartbeat,
        preview: () => _log(buildTableMessage({ previewMode: true })),
        status: () => {
            _log(JSON.stringify({ ...state, config: { intervalMs: Config.STATS_INTERVAL_MS } }, null, 2));
        },
        /** One Telegram line to verify token + @connect */
        testPing: () =>
            send(`pick-telegram-monitor ping · ${new Date().toISOString()}`).then((ok) => {
                _warn(ok ? '[pick-telegram-monitor] testPing OK' : '[pick-telegram-monitor] testPing FAIL');
                return ok;
            }),
    };

    UW.pickTelegram = api;
    try {
        if (typeof window !== 'undefined' && window !== UW) window.pickTelegram = api;
    } catch (_) {}

    const waitDeps = () =>
        new Promise((resolve) => {
            const t0 = Date.now();
            const check = () => {
                if (UW.pick?.all && UW.pp) return resolve(true);
                if (Date.now() - t0 > 120000) return resolve(false);
                setTimeout(check, 400);
            };
            check();
        });

    const boot = () => {
        waitDeps().then((ready) => {
            if (!ready) _warn('[pick-telegram-monitor] deps timeout — table heartbeat needs socks + pick');
            _log(
                `%c[pick-telegram-monitor]`,
                'color:#64748b;font-weight:600;',
                `play → TG: ${Config.PLAY_LOG_TAGS.length ? Config.PLAY_LOG_TAGS.join(', ') : '(no extra tags)'}` +
                    `${Config.WALLET_AFTER_WIN_LOSS ? ' · WIN/LOSS→UI wallet only' : ''}` +
                    `${Config.PLAY_FORWARD_BALANCE ? ' · [NEW SESSION]/Balance [Play]' : ''} · ` +
                    `heartbeat: ${Config.TABLE_HEARTBEAT_ENABLED ? 'on' : 'off'} · pickTelegram.help()`
            );

            if (
                Config.SEND_STARTUP_TELEGRAM &&
                Config.TELEGRAM_BOT_TOKEN &&
                Config.TELEGRAM_CHAT_ID
            ) {
                const host = (() => {
                    try {
                        return UW.location?.hostname || '';
                    } catch (_) {
                        return '';
                    }
                })();
                const startMsg =
                    `▶ ${Config.MONITOR_TITLE} started\n` +
                    `deps: ${ready ? 'pp + pick OK' : 'WAIT TIMEOUT (check socks/pick order)'}\n` +
                    (host ? `${host}\n` : '') +
                    new Date().toISOString();
                send(startMsg).then((ok) => recordSend(ok));
            }

            if (
                Config.TABLE_HEARTBEAT_ENABLED &&
                Config.AUTO_START_TABLE_HEARTBEAT &&
                Config.TELEGRAM_BOT_TOKEN &&
                Config.TELEGRAM_CHAT_ID
            ) {
                startHeartbeat();
            }
        });
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot, { once: true });
    } else {
        boot();
    }

    api.help = () => {
        _log(`
pickTelegram · v1.3.0 · WIN/LOSS: Telegram = UI wallet only (after WIN_LOSS_UI_DELAY_MS); ledger still from logs in state().ledger
  · WON (B)×BANKER_WIN_PROFIT_RATIO · set WALLET_AFTER_WIN_LOSS false to skip`);
    };
})();
