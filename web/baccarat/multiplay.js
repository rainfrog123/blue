// ==UserScript==
// @name         multiplay
// @namespace    http://tampermonkey.net/
// @version      2.2
// @description  Multi-table Baccarat monitor and auto-betting system
// @author       You
// @match        *://client.pragmaticplaylive.net/desktop/multibaccarat/*
// @grant        none
// @run-at       document-end
// ==/UserScript==

(function() {
    'use strict';

    const Settings = {
        TILE_SELECTOR: '[id^="TileHeight-"]',
        TABLE_NAME_SELECTOR: '.rM_r1',
        MIN_BET_SELECTOR: '.wL_wM span[dir="ltr"]',
        TABLE_ID_SELECTOR: '.wq_wr',
        STATS_CONTAINER_SELECTOR: '.ot_ov',
        STATS_VALUE_SELECTOR: '.ot_oy',
        ROUND_NUMBER_SELECTOR: '.ot_oC .ot_oy',
        PLAYER_BUTTON_SELECTOR: '.lq_lv',
        BANKER_BUTTON_SELECTOR: '.lq_lw',
        TIE_BUTTON_SELECTOR: '.lq_lx',
        PLAYER_PAIR_SELECTOR: '.lq_lB',
        BANKER_PAIR_SELECTOR: '.lq_lF',
        POLL_INTERVAL_MS: 1000,
        BET_DELAY_MS: 1000,
        CLICK_DELAY_MS: 50,
        INIT_DELAY_MS: 2000,
        BETTING_START_DELAY_MS: 10000,
        BALANCE_STORAGE_KEY: 'currentBalance',
        CHIP_VALUE: 0.2,
        MIN_BET_FRACTION: 1/8,
        MAX_BET_FRACTION: 1/2,
        MIN_ROUNDS_THRESHOLD: 20,
        MAX_RANKED_TABLES: 20,
        DEBUG_MODE: false
    };

    const debug = (message, ...args) => Settings.DEBUG_MODE && console.log(`[Multi] ${message}`, ...args);

    const SecureRandom = {
        boolean: () => crypto.getRandomValues(new Uint8Array(1))[0] & 1,
        decimal: () => crypto.getRandomValues(new Uint32Array(1))[0] / 0x100000000,
        integer: (min, max) => min + Math.floor(SecureRandom.decimal() * (max - min + 1)),
        bettingSide: () => SecureRandom.boolean() ? 'Player' : 'Banker'
    };

    const query = (selector, context = document) => context.querySelector(selector);
    const queryAll = (selector, context = document) => context.querySelectorAll(selector);

    const extractNumber = (text) => {
        if (!text) return 0;
        const number = parseInt(text.replace(/\D/g, ''), 10);
        return isNaN(number) ? 0 : number;
    };

    class BaccaratTable {
        constructor(element, index) {
            this.element = element;
            this.index = index;
            this.tableKey = `table_${index}`;
            this.previousState = null;
            this.state = this.parseState();
        }

        parseState() {
            const element = this.element;

            const state = {
                // Basic table info
                tileId: element.id || '',
                tableName: query(Settings.TABLE_NAME_SELECTOR, element)?.textContent?.trim() || '',
                minimumBet: query(Settings.MIN_BET_SELECTOR, element)?.textContent?.trim() || '',
                tableIdentifier: query(Settings.TABLE_ID_SELECTOR, element)?.textContent?.trim() || '',
                roundNumber: 0,

                // Tile dimensions and position
                tile: {
                    width: parseInt(element.style.width) || 0,
                    height: parseInt(element.style.height) || 0,
                    transform: element.style.transform || '',
                    visible: element.style.display !== 'none'
                },

                // Win/loss statistics
                winCounts: { P: 0, B: 0, T: 0 },
                pairCounts: { PP: 0, BP: 0 },

                // Current hand info
                currentHand: {
                    playerScore: 0,
                    bankerScore: 0,
                    playerCards: [],
                    bankerCards: [],
                    lastWinner: ''
                },

                // Road/history
                bigRoad: [],

                // Status
                isBettingOpen: this.checkBettingOpen(element),
                hasFavorite: false,
                updatedAt: Date.now()
            };

            // Parse round number from .ot_oC .ot_oy (e.g., "#58")
            const roundElement = query(Settings.ROUND_NUMBER_SELECTOR, element);
            if (roundElement) {
                const match = roundElement.textContent.match(/#(\d+)/);
                if (match) state.roundNumber = parseInt(match[1], 10);
            }

            // Parse all stats from stats container
            const statsContainer = query(Settings.STATS_CONTAINER_SELECTOR, element);
            if (statsContainer) {
                const statMapping = {
                    '#stats-count-player': (val) => state.winCounts.P = val,
                    '#stats-count-banker': (val) => state.winCounts.B = val,
                    '#stats-count-tie': (val) => state.winCounts.T = val,
                    '#stats-count-player-pair': (val) => state.pairCounts.PP = val,
                    '#stats-count-banker-pair': (val) => state.pairCounts.BP = val
                };

                for (const [href, setter] of Object.entries(statMapping)) {
                    const svg = query(`use[href="${href}"]`, statsContainer);
                    if (svg) {
                        const valueEl = svg.closest('div[tabindex]')?.querySelector(Settings.STATS_VALUE_SELECTOR);
                        if (valueEl) setter(extractNumber(valueEl.textContent));
                    }
                }
            }

            // Parse current hand scores (Player: .so_sr blue, Banker: .so_sq red)
            const playerScoreEl = query('.so_sr', element);
            const bankerScoreEl = query('.so_sq', element);
            if (playerScoreEl) state.currentHand.playerScore = extractNumber(playerScoreEl.textContent);
            if (bankerScoreEl) state.currentHand.bankerScore = extractNumber(bankerScoreEl.textContent);

            // Parse current hand cards from SVG use elements
            // Player cards in .lq_lv, Banker cards in .lq_lw
            const playerArea = query(Settings.PLAYER_BUTTON_SELECTOR, element);
            const bankerArea = query(Settings.BANKER_BUTTON_SELECTOR, element);

            if (playerArea) {
                const cardUses = queryAll('use[href^="#card-"]', playerArea);
                state.currentHand.playerCards = [...cardUses].map(use => this.parseCardHref(use.getAttribute('href')));
            }

            if (bankerArea) {
                const cardUses = queryAll('use[href^="#card-"]', bankerArea);
                state.currentHand.bankerCards = [...cardUses].map(use => this.parseCardHref(use.getAttribute('href')));
            }

            // Parse last winner from win message (.zz_zG)
            const winnerEl = query('.zz_zG', element);
            if (winnerEl) {
                state.currentHand.lastWinner = winnerEl.textContent?.trim() || '';
            }

            // Parse big road history from SVG table
            const roadTable = query('.of_ok', element);
            if (roadTable) {
                const roadUses = queryAll('use[href^="#big-bigroad-"]', roadTable);
                state.bigRoad = [...roadUses].map(use => {
                    const href = use.getAttribute('href') || '';
                    // Format: #big-bigroad-XY# where X is P/B/T, Y is N/B/P/E (natural/banker pair/player pair/etc)
                    const match = href.match(/#big-bigroad-([PBT])([NBPE])(\d)/);
                    if (match) {
                        return {
                            winner: match[1], // P, B, or T
                            modifier: match[2], // N=normal, B=banker pair, P=player pair, E=?
                            index: parseInt(match[3])
                        };
                    }
                    return { raw: href };
                });
            }

            // Check if table is favorited (star icon filled)
            const starPath = query('.rE_rH', element);
            if (starPath) {
                const fill = window.getComputedStyle(starPath).fill;
                state.hasFavorite = fill && fill !== 'none' && fill !== 'transparent';
            }

            // Fallback to text parsing if needed
            if (!state.tableName || !state.winCounts.P) {
                this.parseStateFromText(state);
            }

            return state;
        }

        parseCardHref(href) {
            if (!href) return null;
            // Format: #card-RANK-SUIT (e.g., #card-4-clubs, #card-j-diamonds)
            const match = href.match(/#card-([^-]+)-(\w+)/);
            if (match) {
                return { rank: match[1].toUpperCase(), suit: match[2] };
            }
            return { raw: href };
        }

        checkBettingOpen(element) {
            // Check if betting buttons are clickable (not disabled)
            const playerBtn = query(Settings.PLAYER_BUTTON_SELECTOR, element);
            const bankerBtn = query(Settings.BANKER_BUTTON_SELECTOR, element);

            if (!playerBtn || !bankerBtn) return false;

            // Check for disabled class patterns
            const hasDisabled = (el) => {
                const classes = el.className || '';
                return classes.includes('disabled') || classes.includes('Disabled');
            };

            return !hasDisabled(playerBtn) && !hasDisabled(bankerBtn);
        }

        parseStateFromText(state) {
            const lines = this.element.innerText.split('\n').map(line => line.trim()).filter(Boolean);

            for (let i = 0; i < lines.length; i++) {
                const currentLine = lines[i];
                const previousLine = lines[i - 1];

                if (!state.tableName && currentLine.includes('Baccarat')) {
                    state.tableName = currentLine;
                }
                else if (currentLine.startsWith('#') && !state.roundNumber) {
                    state.roundNumber = parseInt(currentLine.slice(1), 10) || 0;
                }
                else if (currentLine.length === 1 && 'PBT'.includes(currentLine)) {
                    state.lastResult = currentLine;
                }
                else if (/^\d+$/.test(currentLine) && previousLine && 'PBT'.includes(previousLine)) {
                    state.winCounts[previousLine] = parseInt(currentLine, 10);
                }
                else if (/^[PBT]{2,}$/.test(currentLine)) {
                    state.resultHistory = currentLine.split('');
                }
            }
        }

        refresh() {
            this.previousState = this.state;
            this.state = this.parseState();
            return this.getChanges();
        }

        getChanges() {
            if (!this.previousState) return [];

            const changes = [];
            const previous = this.previousState;
            const current = this.state;

            if (previous.roundNumber && current.roundNumber !== previous.roundNumber) {
                changes.push(`Round #${previous.roundNumber} → #${current.roundNumber}`);
            }

            for (const side of ['P', 'B', 'T']) {
                if (current.winCounts[side] !== previous.winCounts[side]) {
                    changes.push(`${side}: ${previous.winCounts[side]} → ${current.winCounts[side]}`);
                }
            }

            if (previous.isBettingOpen !== current.isBettingOpen) {
                changes.push(`Betting: ${previous.isBettingOpen ? 'open' : 'closed'} → ${current.isBettingOpen ? 'open' : 'closed'}`);
            }

            if (changes.length && Settings.DEBUG_MODE) {
                debug(`${current.tableName}:`, changes.join(' | '));
            }

            return changes;
        }

        get totalRounds() {
            const { P, B, T } = this.state.winCounts;
            return P + B + T;
        }

        get winDifference() {
            const { P, B } = this.state.winCounts;
            return Math.abs(P - B);
        }

        get balanceRatio() {
            return this.totalRounds > 0 ? this.winDifference / this.totalRounds : 1;
        }

        async clickBetButton(selector, clickCount) {
            const selectors = selector.split(', ');
            let button = null;

            for (const sel of selectors) {
                button = query(sel, this.element);
                if (button) break;
            }

            if (!button) return false;

            for (let i = 0; i < clickCount; i++) {
                button.click();
                if (i < clickCount - 1) {
                    await new Promise(resolve => setTimeout(resolve, Settings.CLICK_DELAY_MS));
                }
            }

            return true;
        }

        placeBetOnPlayer(clickCount) {
            return this.clickBetButton(Settings.PLAYER_BUTTON_SELECTOR, clickCount);
        }

        placeBetOnBanker(clickCount) {
            return this.clickBetButton(Settings.BANKER_BUTTON_SELECTOR, clickCount);
        }
    }

    class TableMonitor {
        constructor() {
            this.tableRegistry = new Map();
            this.isMonitoring = false;
            this.pollInterval = null;
        }

        scanTables() {
            const tileElements = queryAll(Settings.TILE_SELECTOR);
            const activeTableKeys = new Set();

            tileElements.forEach((tileElement, index) => {
                const tableKey = `table_${index}`;
                activeTableKeys.add(tableKey);

                if (this.tableRegistry.has(tableKey)) {
                    const table = this.tableRegistry.get(tableKey);
                    table.element = tileElement;
                    table.refresh();
                } else {
                    const table = new BaccaratTable(tileElement, index);
                    this.tableRegistry.set(tableKey, table);
                    debug(`New table: ${table.state.tableName || tableKey}`);
                }
            });

            for (const [tableKey] of this.tableRegistry) {
                if (!activeTableKeys.has(tableKey)) {
                    this.tableRegistry.delete(tableKey);
                    debug(`Removed: ${tableKey}`);
                }
            }

            return tileElements.length;
        }

        startMonitoring() {
            if (this.isMonitoring) return;

            this.isMonitoring = true;
            this.scanTables();
            this.pollInterval = setInterval(() => this.scanTables(), Settings.POLL_INTERVAL_MS);

            debug(`Started monitoring ${this.tableRegistry.size} tables`);
        }

        stopMonitoring() {
            if (!this.isMonitoring) return;

            this.isMonitoring = false;
            clearInterval(this.pollInterval);
            this.pollInterval = null;

            debug('Stopped monitoring');
        }

        getTable(tableKey) {
            return this.tableRegistry.get(tableKey);
        }

        getAllTables() {
            return [...this.tableRegistry.values()];
        }

        getRankedTables() {
            return this.getAllTables()
                .filter(table => table.totalRounds >= Settings.MIN_ROUNDS_THRESHOLD)
                .sort((a, b) => a.balanceRatio - b.balanceRatio)
                .slice(0, Settings.MAX_RANKED_TABLES);
        }

        printStatus() {
            console.log('\n═══ TABLE STATUS ═══');
            for (const table of this.getAllTables()) {
                const s = table.state;
                const statusIcon = s.isBettingOpen ? '🟢' : '🔴';
                const favIcon = s.hasFavorite ? '⭐' : '';
                const hand = s.currentHand;
                const lastWin = hand.lastWinner ? ` [${hand.lastWinner}]` : '';
                console.log(`${statusIcon}${favIcon} ${s.tableName} | #${s.roundNumber} | P:${s.winCounts.P} B:${s.winCounts.B} T:${s.winCounts.T} | PP:${s.pairCounts.PP} BP:${s.pairCounts.BP}${lastWin} | ${s.tableIdentifier}`);
            }
        }
    }

    class AutoBetManager {
        constructor(tableMonitor) {
            this.tableMonitor = tableMonitor;
            this.bettingQueue = [];
            this.currentQueueIndex = 0;
            this.isAutoBetting = false;
            this.activeTable = null;
            this.lastBettingSide = '';
            this.lastBetAmount = 0;
        }

        getAccountBalance() {
            return parseFloat(localStorage.getItem(Settings.BALANCE_STORAGE_KEY)) || 0;
        }

        calculateBetSize() {
            const balance = this.getAccountBalance();
            if (balance < Settings.CHIP_VALUE) return { amount: 0, clicks: 0 };

            const minimumBet = balance * Settings.MIN_BET_FRACTION;
            const maximumBet = balance * Settings.MAX_BET_FRACTION;
            const randomBet = minimumBet + SecureRandom.decimal() * (maximumBet - minimumBet);
            const clickCount = Math.max(1, Math.floor(randomBet / Settings.CHIP_VALUE));

            return {
                amount: clickCount * Settings.CHIP_VALUE,
                clicks: clickCount
            };
        }

        refreshBettingQueue() {
            this.bettingQueue = this.tableMonitor.getRankedTables();
            this.currentQueueIndex = 0;
            debug(`Queue refreshed: ${this.bettingQueue.length} tables`);
        }

        startAutoBetting() {
            if (this.isAutoBetting) return;

            this.isAutoBetting = true;
            this.refreshBettingQueue();
            this.processNextTable();

            console.log('[Betting] Started');
        }

        stopAutoBetting() {
            this.isAutoBetting = false;
            this.activeTable = null;
            console.log('[Betting] Stopped');
        }

        processNextTable() {
            if (!this.isAutoBetting) return;

            if (this.currentQueueIndex >= this.bettingQueue.length) {
                this.refreshBettingQueue();
            }

            this.activeTable = this.bettingQueue[this.currentQueueIndex];
            this.currentQueueIndex++;

            if (!this.activeTable) {
                setTimeout(() => this.processNextTable(), 100);
                return;
            }

            this.activeTable.refresh();

            if (this.activeTable.state.isBettingOpen) {
                this.executeBet();
            } else {
                debug(`${this.activeTable.tableKey} closed, skipping`);
                setTimeout(() => this.processNextTable(), 100);
            }
        }

        async executeBet() {
            if (!this.isAutoBetting || !this.activeTable) return;

            const { amount, clicks } = this.calculateBetSize();
            if (clicks === 0) {
                debug('Insufficient balance');
                setTimeout(() => this.processNextTable(), 100);
                return;
            }

            this.lastBettingSide = SecureRandom.bettingSide();
            this.lastBetAmount = amount;

            const betPlaced = this.lastBettingSide === 'Player'
                ? await this.activeTable.placeBetOnPlayer(clicks)
                : await this.activeTable.placeBetOnBanker(clicks);

            if (betPlaced) {
                this.logBetDetails();
            }

            setTimeout(() => this.processNextTable(), Settings.BET_DELAY_MS);
        }

        logBetDetails() {
            const tableState = this.activeTable.state;
            const balance = this.getAccountBalance();

            console.log(`\n[Bet] ${tableState.tableName}`);
            console.log(`  #${tableState.roundNumber} | P:${tableState.winCounts.P} B:${tableState.winCounts.B} T:${tableState.winCounts.T}`);
            console.log(`  ${this.lastBettingSide} $${this.lastBetAmount.toFixed(2)} | Balance: $${balance.toFixed(2)}`);
            console.log(`  ${tableState.minimumBet} | ${tableState.tableIdentifier}`);
        }

        getStatus() {
            return {
                running: this.isAutoBetting,
                queueSize: this.bettingQueue.length,
                index: this.currentQueueIndex,
                current: this.activeTable?.tableKey || null,
                lastSide: this.lastBettingSide,
                lastAmount: this.lastBetAmount,
                balance: this.getAccountBalance()
            };
        }
    }

    const tableMonitor = new TableMonitor();
    const autoBetManager = new AutoBetManager(tableMonitor);

    setTimeout(() => {
        tableMonitor.startMonitoring();

        // Auto-betting disabled - focusing on data collection
        // setTimeout(() => {
        //     autoBetManager.startAutoBetting();
        // }, Settings.BETTING_START_DELAY_MS);

    }, Settings.INIT_DELAY_MS);

    window.tableMonitor = {
        start: () => tableMonitor.startMonitoring(),
        stop: () => tableMonitor.stopMonitoring(),
        status: () => tableMonitor.printStatus(),
        count: () => tableMonitor.tableRegistry.size,
        list: () => tableMonitor.getAllTables().map(t => ({ id: t.tableKey, name: t.state.tableName, round: t.state.roundNumber })),
        getTables: () => Object.fromEntries([...tableMonitor.tableRegistry].map(([k, v]) => [k, v.state])),
        getTable: (id) => tableMonitor.getTable(id)?.state || null,
        getEle: (id) => tableMonitor.getTable(id)?.element || null,
        rank: () => tableMonitor.getRankedTables().map(t => ({
            id: t.tableKey,
            name: t.state.tableName,
            P: t.state.winCounts.P,
            B: t.state.winCounts.B,
            total: t.totalRounds,
            ratio: t.balanceRatio.toFixed(3)
        })),
        betPlayer: (id, clicks = 1) => tableMonitor.getTable(id)?.placeBetOnPlayer(clicks),
        betBanker: (id, clicks = 1) => tableMonitor.getTable(id)?.placeBetOnBanker(clicks),
        startBetting: () => autoBetManager.startAutoBetting(),
        stopBetting: () => autoBetManager.stopAutoBetting(),
        bettingStatus: () => autoBetManager.getStatus(),
        getBalance: () => autoBetManager.getAccountBalance(),
        calcBet: () => autoBetManager.calculateBetSize(),
        getBettingStates: () => tableMonitor.getAllTables().map(t => ({
            id: t.tableKey,
            name: t.state.tableName,
            isOpen: t.state.isBettingOpen
        })),
        getTableBettingState: (id) => tableMonitor.getTable(id)?.state.isBettingOpen ?? null,
        toggleDebug: () => {
            Settings.DEBUG_MODE = !Settings.DEBUG_MODE;
            console.log(`Debug: ${Settings.DEBUG_MODE ? 'ON' : 'OFF'}`);
        },
        testSelectors: (id = 'table_0') => {
            const table = tableMonitor.getTable(id);
            if (!table) return console.log(`Table ${id} not found`);
            const el = table.element;
            const s = table.state;
            console.log('═══ FULL TABLE STATE ═══');
            console.log('Tile ID:', s.tileId);
            console.log('Table Name:', s.tableName);
            console.log('Table ID:', s.tableIdentifier);
            console.log('Min Bet:', s.minimumBet);
            console.log('Round #:', s.roundNumber);
            console.log('Tile:', s.tile);
            console.log('Win Counts:', s.winCounts);
            console.log('Pair Counts:', s.pairCounts);
            console.log('Current Hand:', s.currentHand);
            console.log('Big Road Length:', s.bigRoad.length);
            console.log('Big Road Sample:', s.bigRoad.slice(0, 5));
            console.log('Betting Open:', s.isBettingOpen);
            console.log('Has Favorite:', s.hasFavorite);
            console.log('─── Raw Selectors ───');
            console.log('Stats Container:', !!query(Settings.STATS_CONTAINER_SELECTOR, el));
            console.log('Player Btn:', !!query(Settings.PLAYER_BUTTON_SELECTOR, el));
            console.log('Banker Btn:', !!query(Settings.BANKER_BUTTON_SELECTOR, el));
            console.log('Road Table:', !!query('.of_ok', el));
            console.log('Win Message:', query('.zz_zG', el)?.textContent);
            return s;
        }
    };

    console.log('[Multi] v2.2 loaded | API: window.tableMonitor');

})();

/*
╔══════════════════════════════════════════════════════════════════════════════╗
║                        MULTIPLAY API REFERENCE                                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  MONITORING CONTROL                                                          ║
║  ─────────────────                                                           ║
║  tableMonitor.start()          Start polling tables (auto-starts on load)    ║
║  tableMonitor.stop()           Stop polling tables                           ║
║  tableMonitor.toggleDebug()    Toggle debug logging ON/OFF                   ║
║                                                                              ║
║  TABLE INFO                                                                  ║
║  ──────────                                                                  ║
║  tableMonitor.count()          Number of tables detected                     ║
║  tableMonitor.status()         Print all tables with stats to console        ║
║  tableMonitor.list()           Array of {id, name, round} for all tables     ║
║  tableMonitor.rank()           Tables ranked by balance ratio (most balanced)║
║                                                                              ║
║  SINGLE TABLE DATA                                                           ║
║  ─────────────────                                                           ║
║  tableMonitor.getTables()      Object with all table states keyed by id      ║
║  tableMonitor.getTable('table_0')     Full state object for one table        ║
║  tableMonitor.getEle('table_0')       Raw DOM element for one table          ║
║  tableMonitor.testSelectors('table_0') Debug: test all selectors on table    ║
║                                                                              ║
║  STATE OBJECT STRUCTURE                                                      ║
║  ──────────────────────                                                      ║
║  {                                                                           ║
║    tileId: "TileHeight-xxx",           // DOM element id                     ║
║    tableName: "Baccarat 3",            // Display name                       ║
║    minimumBet: "$0.2",                 // Min bet string                     ║
║    tableIdentifier: "ID: 10940298819", // Unique table ID                    ║
║    roundNumber: 58,                    // Current round #                    ║
║    tile: { width, height, transform, visible },                              ║
║    winCounts: { P: 22, B: 28, T: 8 },  // Player/Banker/Tie wins             ║
║    pairCounts: { PP: 6, BP: 5 },       // Player Pair/Banker Pair counts     ║
║    currentHand: {                                                            ║
║      playerScore: 9,                   // Current player score               ║
║      bankerScore: 2,                   // Current banker score               ║
║      playerCards: [{rank, suit}, ...], // Player cards dealt                 ║
║      bankerCards: [{rank, suit}, ...], // Banker cards dealt                 ║
║      lastWinner: "PLAYER"              // Last round winner                  ║
║    },                                                                        ║
║    bigRoad: [{winner, modifier, index}, ...], // Road history                ║
║    isBettingOpen: true,                // Can place bets now                 ║
║    hasFavorite: false,                 // Star favorited                     ║
║    updatedAt: 1733500000000            // Last update timestamp              ║
║  }                                                                           ║
║                                                                              ║
║  BETTING STATUS                                                              ║
║  ──────────────                                                              ║
║  tableMonitor.getBettingStates()              All tables betting status      ║
║  tableMonitor.getTableBettingState('table_0') Single table betting status    ║
║                                                                              ║
║  MANUAL BETTING (use with caution)                                           ║
║  ─────────────────────────────────                                           ║
║  tableMonitor.betPlayer('table_0', 5)  Click player bet 5 times              ║
║  tableMonitor.betBanker('table_0', 5)  Click banker bet 5 times              ║
║  tableMonitor.startBetting()           Start auto-betting system             ║
║  tableMonitor.stopBetting()            Stop auto-betting system              ║
║  tableMonitor.bettingStatus()          Current auto-bet status               ║
║  tableMonitor.getBalance()             Get stored balance from localStorage  ║
║  tableMonitor.calcBet()                Calculate bet size based on balance   ║
║                                                                              ║
║  QUICK EXAMPLES                                                              ║
║  ──────────────                                                              ║
║  // See all tables at a glance                                               ║
║  tableMonitor.status()                                                       ║
║                                                                              ║
║  // Get full data for first table                                            ║
║  tableMonitor.getTable('table_0')                                            ║
║                                                                              ║
║  // Find tables with most rounds played                                      ║
║  tableMonitor.rank()                                                         ║
║                                                                              ║
║  // Export all table data as JSON                                            ║
║  JSON.stringify(tableMonitor.getTables(), null, 2)                           ║
║                                                                              ║
║  // Watch specific table's road history                                      ║
║  tableMonitor.getTable('table_0').bigRoad                                    ║
║                                                                              ║
║  // Get current hand cards                                                   ║
║  tableMonitor.getTable('table_0').currentHand                                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
*/
