// ==UserScript==
// @name         play
// @namespace    http://tampermonkey.net/
// @version      5.7.3
// @description  Martingale or Paroli progression baccarat bot. multibaccarat page only.
// @author       You
// @match        *://client.pragmaticplaylive.net/desktop/multibaccarat*
// @grant        none
// @run-at       document-end
// ==/UserScript==

(function() {
    'use strict';

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
        /**
         * Used only when SIDE is null. Default `'math'` = `Math.random()` (non-crypto).
         * `'crypto'` = Web Crypto `getRandomValues` (CSPRNG, uniform bit → P/B).
         */
        RANDOM_SIDE_ENGINE: 'math',
        CHIP_VALUE: 0.20,           // Value per click ($0.20 chip)
        BET_DELAY: 2000,            // Delay between bet attempts (ms)
        /** After `canBet` is true, wait this long before clicking (ms) */
        PRE_BET_DELAY_MS: 500,
        WAIT_FOR_RESULT: 30000,     // Max wait for result (ms) - Speed Baccarat can be ~27s
        /** After clicks, wait for socks `pp.waitLpbet` (real <lpbet> on WS); requires socks ≥ 3.2.5 */
        LPBET_CONFIRM_MS: 3300,

        // DOM selectors
        PLAYER_BTN: '[data-betcode="0"]',
        BANKER_BTN: '[data-betcode="1"]',
        TILE_SEL: '[id^="TileHeight-"]',

        // Table order among pick.eligible(): chop depth (goodroadLive) first, then pick score
        SORT_ELIGIBLE_BY_CHOP: true,

        // PP game WS: startshuffling → leave this table, wait, pick.pick another (keeps progression step)
        LEAVE_ON_SHUFFLE: true,
        SHUFFLE_SWITCH_DELAY_MS: 2000,
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

    /** Log / status display — PP `name` often uses underscores */
    const displayTableName = (s) => String(s ?? '').replace(/_/g, ' ');

    /** Game WS reports shuffle (new shoe prep) — socks merges startshuffling/endshuffling. */
    const tableIsShuffling = (tableId) => {
        if (!tableId || !window.pp) return false;
        const row = window.pp.get(tableId);
        if (row?.shuffling) return true;
        const live = window.pp.live(tableId);
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
        sessionUnits: 0,            // +/- units this session
        sessionBets: 0,             // Total bets placed
        sessionWins: 0,             // Winning bets
        sessionLosses: 0,           // Losing bets
        sessionUnitSize: 0,         // Unit size for this session (calculated at start)
        sessionStartBalance: 0,     // Balance when session started

        // Current sequence
        currentStep: 0,             // Next STEPS index: Martingale advances on loss · Paroli advances on win (then cap reset)
        sequenceUnits: 0,           // Units in current sequence

        // Table focus (last / current bet target — multi mode picks open table each cycle)
        focusedTable: null,
        usedTables: new Set(),      // Skipped until play.clearUsed() (min bet, shuffle, etc.)
        tableBetCount: 0,

        // Execution
        running: false,
        waitingForResult: false,
        lastBet: null,
        lastResult: null,

        // Timers
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

    // Get current unit size (use session's fixed unit)
    const getUnitSize = () => State.sessionUnitSize || Config.MIN_UNIT;

    // ═══════════════════════════════════════════════════════════════════════
    // UTILITIES
    // ═══════════════════════════════════════════════════════════════════════

    const sleep = ms => new Promise(r => setTimeout(r, ms));

    const simulateClick = (el) => {
        if (!el) return false;
        ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'click'].forEach(type => {
            el.dispatchEvent(new MouseEvent(type, {
                bubbles: true, cancelable: true, view: window
            }));
        });
        return true;
    };

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

    const log = (msg, type = 'info') => {
        const cfg = LOG_STYLES[type] || LOG_STYLES.info;
        const bodyCss =
            type === 'exit'
                ? 'color:#92400e;font-weight:600;'
                : 'color:#0f172a;font-weight:500;';
        console.log(`%c${cfg.label}%c ${msg}`, cfg.labelCss, bodyCss);
    };

    // ═══════════════════════════════════════════════════════════════════════
    // BALANCE
    // ═══════════════════════════════════════════════════════════════════════

    const getBalance = () => {
        const el = document.querySelector('[data-testid="wallet-mobile-balance"] [data-testid="wallet-mobile-value"] span');
        return el ? parseFloat(el.textContent.replace(/[^0-9.]/g, '')) || 0 : 0;
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
        if (!window.pick || !window.pp) return [];

        let tables = window.pick.eligible().filter((t) => {
            const id = t.gameId || t.id;
            return id && !State.usedTables.has(id);
        });

        if (Config.SORT_ELIGIBLE_BY_CHOP) {
            tables = tables
                .map((t) => {
                    const id = t.gameId || t.id;
                    const full = window.pp.get(id) || t;
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

    /** Uniform P/B: default `math`; optional `crypto` via `getRandomValues` (falls back to `math` if missing). */
    const randomSideFair = () => {
        const engine = (Config.RANDOM_SIDE_ENGINE || 'math').toLowerCase();
        if (engine === 'crypto') {
            if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
                crypto.getRandomValues(u32);
                return (u32[0] & 1) === 0 ? 'P' : 'B';
            }
        }
        return Math.random() < 0.5 ? 'P' : 'B';
    };

    const chooseSide = () => {
        if (Config.SIDE === 'B') return 'B';
        if (Config.SIDE === 'P') return 'P';
        return randomSideFair();
    };

    // ═══════════════════════════════════════════════════════════════════════
    // BET EXECUTION
    // ═══════════════════════════════════════════════════════════════════════

    const placeBet = async (tile, betDollars, side) => {
        const selector = side === 'B' ? Config.BANKER_BTN : Config.PLAYER_BTN;
        // Calculate clicks: betDollars / chip value, rounded to nearest chip
        const clicks = Math.max(1, Math.round(betDollars / Config.CHIP_VALUE));

        // Wait for button to appear
        for (let i = 0; i < 60; i++) {
            const btn = tile.querySelector(selector);
            if (btn) {
                for (let j = 0; j < clicks; j++) {
                    simulateClick(btn);
                    if (j < clicks - 1) await sleep(50);
                }
                log(`Placed ${clicks} clicks = $${(clicks * Config.CHIP_VALUE).toFixed(2)}`, 'info');
                return true;
            }
            await sleep(50);
        }
        return false;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // RESULT DETECTION
    // ═══════════════════════════════════════════════════════════════════════

    const getTableLastResult = (tableId) => {
        if (!window.pp) return null;
        const t = window.pp.get(tableId);
        if (!t) return null;

        // Get the last result from PBT sequence
        const pbt = window.pp.lastN(tableId, 1);
        return pbt[0] || null; // 'P', 'B', or 'T'
    };

    const waitForResult = async (tableId, lastKnownCount) => {
        const startTime = Date.now();
        let lastLoggedTotal = null;

        while (Date.now() - startTime < Config.WAIT_FOR_RESULT) {
            const t = window.pp?.get(tableId);
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
        State.sessionBets = 0;
        State.sessionWins = 0;
        State.sessionLosses = 0;
        State.currentStep = 0;
        State.sequenceUnits = 0;
        State.focusedTable = null;
        State.usedTables.clear();
        State.tableBetCount = 0;
        
        // Recalculate unit size based on new balance
        State.sessionStartBalance = balance;
        State.sessionUnitSize = calcUnitSize(balance);
        
        console.log(`%c[NEW SESSION] Balance: $${balance.toFixed(2)} | Unit: $${State.sessionUnitSize.toFixed(2)} | Previous: ${oldUnits > 0 ? '+' : ''}${oldUnits}u`, 'background: #4CAF50; color: white; font-weight: bold; padding: 2px 6px; border-radius: 3px;');
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
     */
    const findFirstOpenTableForBet = (ordered) => {
        const betUnits = getCurrentBetUnits();
        const betDollars = betUnits * getUnitSize();
        const actualBet = Math.max(1, Math.round(betDollars / Config.CHIP_VALUE)) * Config.CHIP_VALUE;

        for (const row of ordered) {
            const id = row.gameId || row.id;
            if (!id) continue;

            const fresh = window.pp?.get(id);
            if (!fresh) continue;
            if ((fresh.total || 0) <= 1) continue;
            if (Config.LEAVE_ON_SHUFFLE && tableIsShuffling(id)) continue;
            if (!fresh.canBet) continue;

            const tableMinBetRaw = Number(fresh.minBet);
            const tableMinBet = Number.isFinite(tableMinBetRaw) && tableMinBetRaw > 0 ? tableMinBetRaw : null;
            const minRequiredBet = tableMinBet != null
                ? Math.ceil(tableMinBet / Config.CHIP_VALUE) * Config.CHIP_VALUE
                : null;
            if (minRequiredBet != null && actualBet + 1e-9 < minRequiredBet) {
                markTableDone(id, 'below-table-min', false);
                continue;
            }

            return { freshTable: fresh, pickRow: row };
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

    const processResult = (result) => {
        const betUnits = getCurrentBetUnits();
        const betSide = State.lastBet?.side || 'B';
        const won = (result === betSide);
        // Note: Tie returns stake, treating as push

        if (result === 'T') {
            // Tie - push (no change)
            log(`TIE - push (no units change)`, 'info');
            State.lastResult = 'T';
            return;
        }

        if (useParoli()) {
            if (won) {
                State.sessionUnits += betUnits;
                State.sessionWins++;
                State.lastResult = 'W';
                State.sequenceUnits = 0;
                State.currentStep += 1;
                const cap = Math.min(Config.PAROLI_MAX_WIN_STREAK, Config.STEPS.length);
                if (State.currentStep >= cap) {
                    log(
                        `WON +${betUnits} units (${betSide}) | Session: ${State.sessionUnits > 0 ? '+' : ''}${State.sessionUnits} units | Paroli: ${cap} wins — reset → 1 unit next`,
                        'win'
                    );
                    State.currentStep = 0;
                } else {
                    const nextU = Config.STEPS[State.currentStep] ?? Config.STEPS[0];
                    log(
                        `WON +${betUnits} units (${betSide}) | Session: ${State.sessionUnits > 0 ? '+' : ''}${State.sessionUnits} units | Next bet: ${nextU} unit (win ${State.currentStep}/${cap})`,
                        'win'
                    );
                }
            } else {
                State.sessionUnits -= betUnits;
                State.sequenceUnits -= betUnits;
                State.sessionLosses++;
                State.lastResult = 'L';
                State.currentStep = 0;
                log(
                    `LOST -${betUnits} units | Session: ${State.sessionUnits} units | Paroli reset → next 1 unit`,
                    'loss'
                );
            }
            return;
        }

        if (won) {
            State.sessionUnits += betUnits;
            State.sessionWins++;
            State.lastResult = 'W';
            State.currentStep = 0;
            State.sequenceUnits = 0;
            log(`WON +${betUnits} units (${betSide}) | Session: ${State.sessionUnits > 0 ? '+' : ''}${State.sessionUnits} units | Next bet: 1 unit`, 'win');
        } else {
            State.sessionUnits -= betUnits;
            State.sequenceUnits -= betUnits;
            State.sessionLosses++;
            State.currentStep++;
            State.lastResult = 'L';

            log(`LOST -${betUnits} units | Session: ${State.sessionUnits} units`, 'loss');

            if (State.currentStep >= Config.STEPS.length) {
                log(`Max step reached (lost 7 units) | Finding new table`, 'loss');
                const tableId =
                    State.focusedTable?.gameId || State.focusedTable?.id || State.lastBet?.tableId;
                if (tableId) {
                    markTableDone(tableId, 'max-loss', true);
                }
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
            log('No eligible tables (pick empty or all in usedTables)', 'exit');
            stop();
            return;
        }

        const picked = findFirstOpenTableForBet(ordered);
        if (!picked) {
            scheduleNext(500);
            return;
        }

        let freshTable = picked.freshTable;
        const tableId = freshTable.gameId || freshTable.id;
        State.focusedTable = freshTable;

        const chop = getChopDepth(window.pp.get(tableId) || freshTable);
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

        await sleep(Config.PRE_BET_DELAY_MS);

        freshTable = window.pp?.get(tableId) || freshTable;
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
        const betSide = chooseSide();
        tile.scrollIntoView({ block: 'center' });
        const betUnits = getCurrentBetUnits();
        const betDollars = betUnits * getUnitSize();
        const actualBet = Math.max(1, Math.round(betDollars / Config.CHIP_VALUE)) * Config.CHIP_VALUE;

        log(`${displayTableName(freshTable.name || tableId)} | Step ${State.currentStep + 1} | ${betSide} x${betUnits}u ($${actualBet.toFixed(2)})`, 'bet');

        const wireSince = Date.now();
        const placed = await placeBet(tile, betDollars, betSide);
        if (!placed) {
            log('Bet placement failed', 'error');
            scheduleNext();
            return;
        }

        if (typeof window.pp?.waitLpbet === 'function') {
            const wire = await window.pp.waitLpbet(tableId, {
                side: betSide,
                since: wireSince,
                minTotal: actualBet,
                timeoutMs: Config.LPBET_CONFIRM_MS,
            });
            if (!wire) {
                log('No matching lpbet on wire — stake may not have registered; skipping round', 'error');
                scheduleNext();
                return;
            }
        }

        State.sessionBets++;
        State.lastBet = {
            table: displayTableName(freshTable.name || tableId),
            tableId,
            side: betSide,
            units: betUnits,
            step: State.currentStep + 1,
            time: Date.now()
        };

        // Wait for result
        State.waitingForResult = true;
        log('Waiting for result...', 'info');

        const result = await waitForResult(tableId, countBefore);

        State.waitingForResult = false;

        if (result === 'SHOE_RESET') {
            // Shoe reset during wait - move to new table (bet voided)
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
            processResult(State.lastBet?.side === 'B' ? 'P' : 'B'); // Opposite side = loss
        } else {
            processResult(result);
        }

        // Wait 3s then check if shoe reset (total dropped to 0 = new shoe)
        await sleep(3000);
        const tableAfter = window.pp?.get(tableId);
        if (tableAfter && tableAfter.total === 0) {
            log(`New shoe detected (total=0) - moving to new table`, 'info');
            markTableDone(tableId, 'new-shoe', false);
            scheduleNext();
            return;
        }

        // Check exit conditions again after result
        const exitAfter = checkExitConditions();
        if (exitAfter.exit) {
            // Check if we can start a new session (have minimum unit)
            const balanceAfter = getBalance();
            const minUnitAfter = calcUnitSize(balanceAfter);
            if (balanceAfter >= minUnitAfter) {
                // Start new session
                startNewSession();
                scheduleNext();
                return;
            }
            // Not enough balance - stop completely
            stop();
            return;
        }

        scheduleNext();
    };

    const scheduleNext = (delay = Config.BET_DELAY) => {
        if (!State.running) return;
        State.intervalId = setTimeout(betCycle, delay);
    };

    // ═══════════════════════════════════════════════════════════════════════
    // POPUP HANDLING
    // ═══════════════════════════════════════════════════════════════════════

    const handlePopup = () => {
        const popup = document.querySelector('[data-testid="popup-content"]');
        if (!popup) return;

        const title = popup.querySelector('[data-testid="blocking-popup-title"]');
        if (title?.textContent === 'Insufficient funds') {
            log('Insufficient funds popup - stopping', 'exit');
            const btn = popup.querySelector('button[data-testid="button"]');
            if (btn) simulateClick(btn);
            stop();
        }
    };

    const watchForPopup = () => {
        const observer = new MutationObserver(handlePopup);
        observer.observe(document.body, { childList: true, subtree: true });
    };

    // ═══════════════════════════════════════════════════════════════════════
    // CONTROL API
    // ═══════════════════════════════════════════════════════════════════════

    const start = () => {
        if (State.running) {
            log('Already running');
            return;
        }

        // Pre-flight checks
        if (!window.pp) {
            log('pp API not available - load socks.js first', 'error');
            return;
        }
        if (!window.pick) {
            log('pick API not available - load pick.js first', 'error');
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
        const sideMode =
            Config.SIDE === null
                ? `RANDOM 50/50 (${(Config.RANDOM_SIDE_ENGINE || 'math').toLowerCase() === 'crypto' ? 'crypto.getRandomValues' : 'Math.random'})`
                : Config.SIDE;
        const paroliCap = Math.min(Config.PAROLI_MAX_WIN_STREAK, Config.STEPS.length);
        const modeLine = useParoli()
            ? `Paroli (${paroliCap} wins cap) WIN→raise rung · LOSE→reset`
            : `Martingale WIN→1u · LOSE→double (${Config.STEPS.join('→')}u)`;
        log(`STARTED | Balance: $${balance.toFixed(2)} | Unit: $${State.sessionUnitSize.toFixed(2)} (1/${Math.round(1/Config.UNIT_FRACTION)} of balance)`, 'info');
        log(`${modeLine} | Side: ${sideMode} | Stop-loss: ${Config.SESSION_STOP_LOSS}u | Stop-win: +${Config.SESSION_STOP_WIN}u`);

        betCycle();
    };

    const stop = () => {
        State.running = false;
        if (State.intervalId) {
            clearTimeout(State.intervalId);
            State.intervalId = null;
        }
        log(`STOPPED | Session: ${State.sessionUnits > 0 ? '+' : ''}${State.sessionUnits} units | W:${State.sessionWins} L:${State.sessionLosses}`, 'info');
    };

    const reset = () => {
        stop();
        State.sessionUnits = 0;
        State.sessionBets = 0;
        State.sessionWins = 0;
        State.sessionLosses = 0;
        State.sessionUnitSize = 0;
        State.sessionStartBalance = 0;
        State.currentStep = 0;
        State.sequenceUnits = 0;
        State.focusedTable = null;
        State.usedTables.clear();
        State.tableBetCount = 0;
        State.lastBet = null;
        State.lastResult = null;
        log('Session RESET', 'info');
    };

    const status = () => {
        const balance = getBalance();
        const unitSize = getUnitSize();
        const profitDollars = State.sessionUnits * unitSize;
        const nextBetDollars = getCurrentBetUnits() * unitSize;

        console.log(`
╔══════════════════════════════════════════════════════════════╗
║               PLAY STATUS: ${(useParoli() ? 'Paroli' : 'Martingale').padEnd(10)}                               ║
╠══════════════════════════════════════════════════════════════╣
║  Running: ${State.running ? 'YES' : 'NO '}                                              ║
║  Balance: $${balance.toFixed(2).padEnd(8)}  Start: $${(State.sessionStartBalance || balance).toFixed(2).padEnd(8)}         ║
║  Unit: $${unitSize.toFixed(2)} (1/${Math.round(1 / Config.UNIT_FRACTION)} of start balance, min $${Config.MIN_UNIT})          ║
╠══════════════════════════════════════════════════════════════╣
║  Session Units: ${String((State.sessionUnits > 0 ? '+' : '') + State.sessionUnits).padEnd(5)}  ($${(profitDollars > 0 ? '+' : '') + profitDollars.toFixed(2)})                    ║
║  Bets: ${String(State.sessionBets).padEnd(3)} Wins: ${String(State.sessionWins).padEnd(3)} Losses: ${String(State.sessionLosses).padEnd(3)}                      ║
╠══════════════════════════════════════════════════════════════╣
║  Next Bet: ${getCurrentBetUnits()}u ($${nextBetDollars.toFixed(2)})                                    ║
║  Sequence P/L: ${State.sequenceUnits} units                                   ║
║  Table: ${displayTableName(State.focusedTable?.name || State.focusedTable?.gameId || 'None').slice(0, 25).padEnd(25)}                   ║
╠══════════════════════════════════════════════════════════════╣
║  Stop-Loss: ${Config.SESSION_STOP_LOSS} units | Stop-Win: +${Config.SESSION_STOP_WIN} units               ║
╚══════════════════════════════════════════════════════════════╝
`);
        return {
            running: State.running,
            balance,
            sessionUnits: State.sessionUnits,
            profitDollars,
            bets: State.sessionBets,
            wins: State.sessionWins,
            losses: State.sessionLosses,
            currentStep: State.currentStep,
            focusedTable: State.focusedTable,
            usedTables: [...State.usedTables]
        };
    };

    // ═══════════════════════════════════════════════════════════════════════
    // API
    // ═══════════════════════════════════════════════════════════════════════

    window.play = {
        // Control
        start,
        stop,
        reset,
        status,
        s: status, // Shorthand

        // Config (can modify before starting)
        config: Config,

        // State (read-only inspection)
        state: () => ({ ...State, usedTables: [...State.usedTables] }),

        // Manual operations
        setTable: (uidOrId) => {
            const t = window.pp?.get(uidOrId);
            if (t) {
                State.focusedTable = t;
                State.tableBetCount = 0;
                log(`Manually set table: ${displayTableName(t.name || t.gameId)}`);
            }
        },

        clearUsed: () => {
            State.usedTables.clear();
            log('Cleared used tables list - can reuse all tables');
        },

        // Quick helpers
        balance: getBalance,
        units: () => State.sessionUnits,
        unitSize: getUnitSize,
        profit: () => State.sessionUnits * getUnitSize()
    };

    // ═══════════════════════════════════════════════════════════════════════
    // INITIALIZATION
    // ═══════════════════════════════════════════════════════════════════════

    watchForPopup();

    const init = () => {
        if (window.pp && window.pick) {
            console.log(`
╔══════════════════════════════════════════════════════════════╗
║              BACCARAT PLAY BOT v5.7.3                        ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  PROGRESSION (global multi-table ladder):                     ║
║  • Paroli (default): WIN→next STEPS · LOSE→reset to 1u       ║
║    cap = min(PAROLI_MAX_WIN_STREAK, STEPS.length) wins       ║
║  • Martingale: WIN→1u · LOSE→double (see STEPS)               ║
║  • Each cycle: first pick.eligible row with canBet           ║
║                                                              ║
║  UNIT: Balance / 8 at session start (min $0.20)              ║
║                                                              ║
║  EXIT RULES:                                                 ║
║  • Session stop-loss: -6 units                               ║
║  • Session stop-win: +3 units                                ║
║                                                              ║
║  COMMANDS:                                                   ║
║  play.start()     Start betting                              ║
║  play.stop()      Stop betting                               ║
║  play.status()    Show current state                         ║
║  play.reset()     Reset session                              ║
║                                                              ║
║  CONFIG:                                                     ║
║  play.config.PROGRESSION_MODE       'paroli' (default) | 'martingale' ║
║  play.config.PAROLI_MAX_WIN_STREAK = 3  (Paroli reset cap)   ║
║  play.config.STEPS = [1,2,4]          ladder chip multipliers ║
║  play.config.UNIT_FRACTION = 1/8    Unit = balance * this    ║
║  play.config.MIN_UNIT = 0.2         Minimum unit ($)         ║
║  play.config.SIDE = null            null = fair P/B (RANDOM_SIDE_ENGINE) ║
║  play.config.RANDOM_SIDE_ENGINE     'math' (default) | 'crypto' ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
`);
        } else {
            setTimeout(init, 500);
        }
    };

    init();

})();
