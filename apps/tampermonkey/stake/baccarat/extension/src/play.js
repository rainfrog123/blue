'use strict';
/* Play HUD + hunt + chips. MAIN world. */
(function (SB) {
  SB.createPlay = function (pp, pick) {
    const util = SB.util;
    const VERSION = SB.VERSION;
    const normalizeSideEngine = SB.normalizeSideEngine;
    const readHudStore = SB.readHudStore;
    const writeHudStore = SB.writeHudStore;
    const storeToConfigPatch = SB.storeToConfigPatch;
    const hudBusSend = SB.hudBusSend;
    const bindHudResize = SB.bindHudResize;
    const readDomWallet = SB.readDomWallet;
    const HUD_WIDTH = SB.HUD_WIDTH;
    const HUD_HEIGHT = SB.HUD_HEIGHT;
    const HUD_SIZE_GEN = SB.HUD_SIZE_GEN;
    const WALLET_VALUE_SELS = SB.WALLET_VALUE_SELS;

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
        if (min > 0 && planned + 1e-9 < min) return null;
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
     * Walk pick order; first table with bets open, OK shoe, not shuffling,
     * planned stake ≥ table min (never bump a $0.20 unit up to a $1 table).
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
            if (stake == null) {
                const now = Date.now();
                if (!State._minSkipLog || now - State._minSkipLog > 12000) {
                    State._minSkipLog = now;
                    log(
                        `Skip ${displayTableName(fresh.name || id)} · planned $${plannedDollars().toFixed(2)} < min $${tableMinBet(fresh).toFixed(2)}`,
                        'info',
                    );
                }
                continue;
            }
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
        if (actualBet == null || (tableMin > 0 && actualBet + 1e-9 < tableMin)) {
            log(
                `Skip ${displayTableName(freshTable.name || tableId)} · planned $${plannedDollars().toFixed(2)} < min $${tableMin.toFixed(2)}`,
                'info',
            );
            scheduleNext(400);
            return;
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
        try {
            hudApi = mountHud() || hudApi;
        } catch (err) {
            console.error('[SB] mountHud failed', err);
            return null;
        }
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
    try {
        bootHud();
    } catch (err) {
        console.error('[SB] HUD boot failed', err);
    }
    return api;
  };
})(window.__SB);
