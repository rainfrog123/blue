// ==UserScript==
// @name         play
// @namespace    http://tampermonkey.net/
// @version      5.2
// @description  Martingale betting system for baccarat - 1-2-4 progression, dynamic unit sizing
// @author       You
// @match        *://client.pragmaticplaylive.net/desktop/multibaccarat/*
// @grant        none
// @run-at       document-end
// ==/UserScript==

(function() {
    'use strict';

    // ═══════════════════════════════════════════════════════════════════════
    // MARTINGALE CONFIGURATION
    // ═══════════════════════════════════════════════════════════════════════

    const Config = {
        // Martingale progression (1-2-4)
        STEPS: [1, 2, 4],           // Unit multipliers per step
        UNIT_FRACTION: 1/7,         // Unit = balance / 7
        MIN_UNIT: 0.2,              // Minimum unit size in dollars

        // Exit rules (in units)
        SESSION_STOP_LOSS: -6,      // Stop entire session
        SESSION_STOP_WIN: 4,        // Take profit and stop
        MAX_TABLE_LOSS: -7,         // Leave table (one failed sequence)

        // Betting
        SIDE: null,                 // null = 50/50 random, 'B' = Banker only, 'P' = Player only
        BET_DELAY: 2000,            // Delay between bet attempts (ms)
        WAIT_FOR_RESULT: 15000,     // Max wait for result (ms)

        // DOM selectors
        PLAYER_BTN: '[data-betcode="0"]',
        BANKER_BTN: '[data-betcode="1"]',
        TILE_SEL: '[id^="TileHeight-"]'
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
        currentStep: 0,             // 0 = fresh, 1 = after 1 loss, 2 = after 2 losses
        sequenceUnits: 0,           // Units in current sequence

        // Table focus
        focusedTable: null,         // The ONE table we're playing
        failedTables: new Set(),    // Tables that failed us (one failed sequence)

        // Execution
        running: false,
        waitingForResult: false,
        lastBet: null,
        lastResult: null,

        // Timers
        intervalId: null,
        resultTimeout: null
    };

    // Calculate unit size: balance/7, minimum 0.2
    const calcUnitSize = (balance) => {
        const calculated = balance * Config.UNIT_FRACTION;
        return Math.max(Config.MIN_UNIT, Math.round(calculated * 100) / 100); // Round to cents
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

    const log = (msg, type = 'info') => {
        const prefix = {
            'info': '[Play]',
            'bet': '[BET]',
            'win': '[WIN]',
            'loss': '[LOSS]',
            'exit': '[EXIT]',
            'error': '[ERR]'
        }[type] || '[Play]';
        console.log(`${prefix} ${msg}`);
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
    // TABLE SELECTION (from pick module)
    // ═══════════════════════════════════════════════════════════════════════

    const selectTable = () => {
        if (!window.pick) {
            log('pick API not available', 'error');
            return null;
        }

        // Get eligible tables, excluding failed ones
        const tables = window.pick.eligible().filter(t => {
            const id = t.gameId || t.id;
            return !State.failedTables.has(id);
        });

        if (tables.length === 0) {
            log('No eligible tables (all failed or none available)', 'exit');
            return null;
        }

        // Pick the best one (first in sorted list)
        const table = tables[0];
        log(`Selected table: ${table.name || table.gameId} | P:${table.P} B:${table.B} T:${table.T}`);
        return table;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // SIDE SELECTION
    // ═══════════════════════════════════════════════════════════════════════

    // Get side for current bet (respects Config.SIDE or random 50/50)
    const chooseSide = () => {
        if (Config.SIDE === 'B') return 'B';
        if (Config.SIDE === 'P') return 'P';
        // 50/50 random
        return Math.random() < 0.5 ? 'P' : 'B';
    };

    // Track chosen side for current sequence
    let sequenceSide = null;

    // ═══════════════════════════════════════════════════════════════════════
    // BET EXECUTION
    // ═══════════════════════════════════════════════════════════════════════

    const placeBet = async (tile, units, side) => {
        const selector = side === 'B' ? Config.BANKER_BTN : Config.PLAYER_BTN;
        const clicks = units; // 1 unit = 1 click

        // Wait for button to appear
        for (let i = 0; i < 60; i++) {
            const btn = tile.querySelector(selector);
            if (btn) {
                for (let j = 0; j < clicks; j++) {
                    simulateClick(btn);
                    if (j < clicks - 1) await sleep(50);
                }
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

        while (Date.now() - startTime < Config.WAIT_FOR_RESULT) {
            const t = window.pp?.get(tableId);
            if (t && t.total > lastKnownCount) {
                // New result arrived
                const result = getTableLastResult(tableId);
                return result;
            }
            await sleep(200);
        }
        return null; // Timeout
    };

    // ═══════════════════════════════════════════════════════════════════════
    // EXIT CONDITIONS
    // ═══════════════════════════════════════════════════════════════════════

    const checkExitConditions = () => {
        // Session stop-loss
        if (State.sessionUnits <= Config.SESSION_STOP_LOSS) {
            log(`SESSION STOP-LOSS reached: ${State.sessionUnits} units`, 'exit');
            return { exit: true, reason: 'stop-loss' };
        }

        // Session stop-win
        if (State.sessionUnits >= Config.SESSION_STOP_WIN) {
            log(`SESSION STOP-WIN reached: +${State.sessionUnits} units`, 'exit');
            return { exit: true, reason: 'stop-win' };
        }

        return { exit: false };
    };

    const markTableFailed = (tableId) => {
        State.failedTables.add(tableId);
        log(`Table ${tableId} marked as FAILED (sequence lost)`, 'exit');
        State.focusedTable = null;
        State.currentStep = 0;
        State.sequenceUnits = 0;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // MARTINGALE LOGIC
    // ═══════════════════════════════════════════════════════════════════════

    const getCurrentBetUnits = () => {
        return Config.STEPS[State.currentStep] || Config.STEPS[0];
    };

    const processResult = (result) => {
        const betUnits = getCurrentBetUnits();
        const betSide = sequenceSide || 'B';
        const won = (result === betSide);
        // Note: Tie returns stake, treating as push

        if (result === 'T') {
            // Tie - push (no change)
            log(`TIE - push (no units change)`, 'info');
            State.lastResult = 'T';
            return;
        }

        if (won) {
            // WIN - reset sequence, add 1 unit profit
            State.sessionUnits += 1; // Martingale profit is always 1 unit
            State.sessionWins++;
            State.currentStep = 0;
            State.sequenceUnits = 0;
            sequenceSide = null; // Reset side for next sequence
            State.lastResult = 'W';
            log(`WON +1 unit | Session: ${State.sessionUnits > 0 ? '+' : ''}${State.sessionUnits} units`, 'win');
        } else {
            // LOSS - advance step, track loss
            State.sessionUnits -= betUnits;
            State.sequenceUnits -= betUnits;
            State.sessionLosses++;
            State.currentStep++;
            State.lastResult = 'L';

            log(`LOST -${betUnits} units | Step ${State.currentStep}/${Config.STEPS.length} | Session: ${State.sessionUnits} units`, 'loss');

            // Check if sequence failed (max steps reached)
            if (State.currentStep >= Config.STEPS.length) {
                const tableId = State.focusedTable?.gameId || State.focusedTable?.id;
                log(`SEQUENCE FAILED on ${tableId} | Total loss: ${State.sequenceUnits} units`, 'exit');
                markTableFailed(tableId);
                sequenceSide = null; // Reset side for next table
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
            stop();
            return;
        }

        // Check balance
        const balance = getBalance();
        const neededUnits = getCurrentBetUnits();
        const unitSize = getUnitSize();
        const neededDollars = neededUnits * unitSize;

        if (balance < neededDollars) {
            log(`Balance too low: $${balance.toFixed(2)} < $${neededDollars.toFixed(2)} needed`, 'exit');
            stop();
            return;
        }

        // Select table if we don't have one
        if (!State.focusedTable) {
            State.focusedTable = selectTable();
            if (!State.focusedTable) {
                log('No table selected - stopping', 'exit');
                stop();
                return;
            }
            // Reset sequence for new table
            State.currentStep = 0;
            State.sequenceUnits = 0;
        }

        const table = State.focusedTable;
        const tableId = table.gameId || table.id;

        // Refresh table data
        const freshTable = window.pp?.get(tableId);
        if (!freshTable) {
            log(`Table ${tableId} no longer available`, 'error');
            State.focusedTable = null;
            scheduleNext();
            return;
        }

        // Check if betting is open
        if (!freshTable.canBet) {
            scheduleNext(500); // Check again soon
            return;
        }

        // Find tile
        const tile = findTile(freshTable.gameId) || findTile(freshTable.id);
        if (!tile) {
            log(`Tile not found for ${freshTable.name || tableId}`, 'error');
            scheduleNext();
            return;
        }

        // Record current count before bet
        const countBefore = freshTable.total || 0;

        // Choose side for this sequence (keep same side throughout sequence)
        if (sequenceSide === null) {
            sequenceSide = chooseSide();
        }
        const betSide = sequenceSide;

        // Place bet
        tile.scrollIntoView({ block: 'center' });
        const betUnits = getCurrentBetUnits();
        const betDollars = betUnits * getUnitSize();

        log(`${freshTable.name || tableId} | Step ${State.currentStep + 1} | ${betSide} x${betUnits} ($${betDollars.toFixed(2)})`, 'bet');

        const placed = await placeBet(tile, betUnits, betSide);
        if (!placed) {
            log('Bet placement failed', 'error');
            scheduleNext();
            return;
        }

        State.sessionBets++;
        State.lastBet = {
            table: freshTable.name || tableId,
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

        if (result === null) {
            log('Result timeout - treating as loss', 'error');
            processResult(sequenceSide === 'B' ? 'P' : 'B'); // Opposite side = loss
        } else {
            processResult(result);
        }

        // Check exit conditions again after result
        const exitAfter = checkExitConditions();
        if (exitAfter.exit) {
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

        // Calculate unit size for this session (1/7 of balance, min 0.2)
        State.sessionStartBalance = balance;
        State.sessionUnitSize = calcUnitSize(balance);

        State.running = true;
        const sideMode = Config.SIDE === null ? '50/50' : Config.SIDE;
        log(`STARTED | Balance: $${balance.toFixed(2)} | Unit: $${State.sessionUnitSize.toFixed(2)} (1/${Math.round(1/Config.UNIT_FRACTION)} of balance)`, 'info');
        log(`Rules: 1-2-4 | Side: ${sideMode} | Stop-loss: ${Config.SESSION_STOP_LOSS}u | Stop-win: +${Config.SESSION_STOP_WIN}u`);

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
        State.failedTables.clear();
        State.lastBet = null;
        State.lastResult = null;
        sequenceSide = null;
        log('Session RESET', 'info');
    };

    const status = () => {
        const balance = getBalance();
        const unitSize = getUnitSize();
        const profitDollars = State.sessionUnits * unitSize;
        const nextBetDollars = getCurrentBetUnits() * unitSize;

        console.log(`
╔══════════════════════════════════════════════════════════════╗
║                    MARTINGALE STATUS                         ║
╠══════════════════════════════════════════════════════════════╣
║  Running: ${State.running ? 'YES' : 'NO '}                                              ║
║  Balance: $${balance.toFixed(2).padEnd(8)}  Start: $${(State.sessionStartBalance || balance).toFixed(2).padEnd(8)}         ║
║  Unit: $${unitSize.toFixed(2)} (1/7 of start balance, min $${Config.MIN_UNIT})          ║
╠══════════════════════════════════════════════════════════════╣
║  Session Units: ${String((State.sessionUnits > 0 ? '+' : '') + State.sessionUnits).padEnd(5)}  ($${(profitDollars > 0 ? '+' : '') + profitDollars.toFixed(2)})                    ║
║  Bets: ${String(State.sessionBets).padEnd(3)} Wins: ${String(State.sessionWins).padEnd(3)} Losses: ${String(State.sessionLosses).padEnd(3)}                      ║
╠══════════════════════════════════════════════════════════════╣
║  Current Step: ${State.currentStep + 1}/${Config.STEPS.length} (next: ${getCurrentBetUnits()}u = $${nextBetDollars.toFixed(2)})                ║
║  Sequence P/L: ${State.sequenceUnits} units                                   ║
║  Focused Table: ${(State.focusedTable?.name || State.focusedTable?.gameId || 'None').slice(0, 20).padEnd(20)}            ║
║  Failed Tables: ${State.failedTables.size}                                           ║
╠══════════════════════════════════════════════════════════════╣
║  Stop-Loss: ${Config.SESSION_STOP_LOSS} units | Stop-Win: +${Config.SESSION_STOP_WIN} units              ║
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
            failedTables: [...State.failedTables]
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
        state: () => ({ ...State, failedTables: [...State.failedTables] }),

        // Manual operations
        setTable: (uidOrId) => {
            const t = window.pp?.get(uidOrId);
            if (t) {
                State.focusedTable = t;
                log(`Manually set table: ${t.name || t.gameId}`);
            }
        },

        clearFailed: () => {
            State.failedTables.clear();
            log('Cleared failed tables list');
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
║              MARTINGALE BETTING SYSTEM v5.2                  ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  STRATEGY: 1-2-4 Progression | 50/50 Random Side             ║
║  UNIT: Balance / 7 at session start (min $0.20)              ║
║                                                              ║
║  EXIT RULES:                                                 ║
║  • Max 3 steps per sequence                                  ║
║  • Failed sequence → leave table immediately                 ║
║  • Session stop-loss: -6 units                               ║
║  • Session stop-win: +4 units                                ║
║                                                              ║
║  COMMANDS:                                                   ║
║  play.start()     Start Martingale                           ║
║  play.stop()      Stop betting                               ║
║  play.status()    Show current state                         ║
║  play.reset()     Reset session                              ║
║                                                              ║
║  CONFIG:                                                     ║
║  play.config.UNIT_FRACTION = 1/7    Unit = balance * this    ║
║  play.config.MIN_UNIT = 0.2         Minimum unit ($)         ║
║  play.config.SIDE = null            null=50/50, 'B', 'P'     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
`);
        } else {
            setTimeout(init, 500);
        }
    };

    init();

})();
