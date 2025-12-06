// ==UserScript==
// @name         multiplay
// @namespace    http://tampermonkey.net/
// @version      3.3
// @description  Baccarat betting logic using WebSocket data from pp API
// @author       You
// @match        *://client.pragmaticplaylive.net/desktop/multibaccarat/*
// @grant        none
// @run-at       document-end
// ==/UserScript==

(function() {
    'use strict';

    const Config = {
        CHIP_VALUE: 0.2,
        MIN_BET_FRAC: 1/8,
        MAX_BET_FRAC: 1/2,
        MIN_ROUNDS: 20,
        MAX_TABLES: 20,
        BET_DELAY: 1000,
        CLICK_DELAY: 50,
        // DOM selectors
        PLAYER_BTN: '[data-betcode="0"]',
        BANKER_BTN: '[data-betcode="1"]',
        TILE_SEL: '[id^="TileHeight-"]'
    };

    // Secure random
    const rand = {
        bool: () => crypto.getRandomValues(new Uint8Array(1))[0] & 1,
        float: () => crypto.getRandomValues(new Uint32Array(1))[0] / 0x100000000,
        side: () => rand.bool() ? 'P' : 'B'
    };

    // Wait for pp API
    const waitForPP = () => new Promise(resolve => {
        const check = () => window.pp ? resolve() : setTimeout(check, 100);
        check();
    });

    // Balance tracking
    const balanceHistory = [];
    let lastBalance = null;
    
    const getBalance = () => {
        const el = document.querySelector('[data-testid="wallet-mobile-balance"] [data-testid="wallet-mobile-value"] span');
        return el ? parseFloat(el.textContent.replace(/[^0-9.]/g, '')) || 0 : 0;
    };
    
    const trackBalance = () => {
        const bal = getBalance();
        if (bal !== lastBalance && lastBalance !== null) {
            const delta = bal - lastBalance;
            const entry = {
                time: Date.now(),
                balance: bal,
                prev: lastBalance,
                delta,
                type: delta > 0 ? 'WIN' : delta < 0 ? 'BET' : 'SAME'
            };
            balanceHistory.push(entry);
            console.log(`[Bal] ${delta >= 0 ? '+' : ''}${delta.toFixed(2)} → $${bal.toFixed(2)} (${entry.type})`);
        }
        lastBalance = bal;
    };
    
    // Watch balance with MutationObserver
    const watchBalance = () => {
        const target = document.querySelector('[data-testid="wallet-mobile-balance"]');
        if (!target) {
            setTimeout(watchBalance, 500);
            return;
        }
        lastBalance = getBalance();
        console.log(`[Bal] Watching balance: $${lastBalance.toFixed(2)}`);
        
        const observer = new MutationObserver(trackBalance);
        observer.observe(target, { childList: true, subtree: true, characterData: true });
    };

    // Calculate bet size
    const calcBet = () => {
        const bal = getBalance();
        if (bal < Config.CHIP_VALUE) return { amount: 0, clicks: 0 };
        const min = bal * Config.MIN_BET_FRAC;
        const max = bal * Config.MAX_BET_FRAC;
        const bet = min + rand.float() * (max - min);
        const clicks = Math.max(1, Math.floor(bet / Config.CHIP_VALUE));
        return { amount: clicks * Config.CHIP_VALUE, clicks };
    };

    // Find tile element by table ID (game format ID like "cbcf6qas8fscb222")
    const findTile = (tableId) => {
        if (!tableId) return null;
        // Try direct ID match first: id="TileHeight-cbcf6qas8fscb222"
        const direct = document.getElementById(`TileHeight-${tableId}`);
        if (direct) return direct;
        // Fallback: search all tiles
        const tiles = document.querySelectorAll(Config.TILE_SEL);
        for (const tile of tiles) {
            if (tile.id.includes(tableId)) return tile;
            const text = tile.innerText || '';
            if (text.includes(tableId)) return tile;
        }
        return null;
    };

    // Find tile by index
    const getTileByIndex = (idx) => {
        const tiles = document.querySelectorAll(Config.TILE_SEL);
        return tiles[idx] || null;
    };

    // Click bet button multiple times
    const clickBet = async (tile, selector, clicks) => {
        const btn = tile.querySelector(selector);
        if (!btn) return false;
        
        // Scroll tile into view first
        tile.scrollIntoView({ behavior: 'smooth', block: 'center' });
        await sleep(200);  // Wait for scroll to complete
        
        for (let i = 0; i < clicks; i++) {
            simulateClick(btn);
            if (i < clicks - 1) await sleep(Config.CLICK_DELAY);
        }
        return true;
    };

    const sleep = ms => new Promise(r => setTimeout(r, ms));
    
    // Simulate full mouse click sequence
    const simulateClick = (el) => {
        if (!el) return false;
        ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'click'].forEach(type => {
            el.dispatchEvent(new MouseEvent(type, {
                bubbles: true,
                cancelable: true,
                view: window
            }));
        });
        return true;
    };

    // Get ranked tables from pp API
    const getRankedTables = () => {
        if (!window.pp) return [];
        return [...Object.values(window.pp.tables())]
            .filter(t => (t.total || 0) >= Config.MIN_ROUNDS)
            .map(t => ({
                ...t,
                ratio: t.total > 0 ? Math.abs((t.P || 0) - (t.B || 0)) / t.total : 1
            }))
            .sort((a, b) => a.ratio - b.ratio)
            .slice(0, Config.MAX_TABLES);
    };

    // Betting Manager
    class BetManager {
        constructor() {
            this.running = false;
            this.queue = [];
            this.idx = 0;
            this.lastBet = null;
        }

        start() {
            if (this.running) return;
            this.running = true;
            this.refreshQueue();
            this.next();
            console.log('[Bet] Started');
        }

        stop() {
            this.running = false;
            console.log('[Bet] Stopped');
        }

        refreshQueue() {
            this.queue = getRankedTables();
            this.idx = 0;
        }

        async next() {
            if (!this.running) return;

            if (this.idx >= this.queue.length) {
                this.refreshQueue();
            }

            const table = this.queue[this.idx++];
            if (!table) {
                await sleep(100);
                return this.next();
            }

            // Find corresponding tile (by index for now)
            const tile = getTileByIndex(this.idx - 1);
            if (!tile) {
                await sleep(100);
                return this.next();
            }

            // Check if betting is open (button not disabled)
            const pBtn = tile.querySelector(Config.PLAYER_BTN);
            const bBtn = tile.querySelector(Config.BANKER_BTN);
            const isOpen = pBtn && bBtn && 
                !pBtn.className.includes('disabled') && 
                !bBtn.className.includes('disabled');

            if (!isOpen) {
                await sleep(100);
                return this.next();
            }

            // Place bet
            const { amount, clicks } = calcBet();
            if (clicks === 0) {
                console.log('[Bet] Insufficient balance');
                await sleep(100);
                return this.next();
            }

            const side = rand.side();
            const selector = side === 'P' ? Config.PLAYER_BTN : Config.BANKER_BTN;
            const placed = await clickBet(tile, selector, clicks);

            if (placed) {
                this.lastBet = { table: table.name || table.id, side, amount, time: Date.now() };
                console.log(`[Bet] ${table.name || table.id} | ${side} $${amount.toFixed(2)} | P:${table.P} B:${table.B} T:${table.T}`);
            }

            await sleep(Config.BET_DELAY);
            this.next();
        }

        status() {
            return {
                running: this.running,
                queue: this.queue.length,
                idx: this.idx,
                last: this.lastBet,
                balance: getBalance()
            };
        }
    }

    const betManager = new BetManager();

    // API
    window.bet = {
        start: () => betManager.start(),
        stop: () => betManager.stop(),
        status: () => betManager.status(),
        balance: getBalance,
        calc: calcBet,
        
        // Balance history
        history: (n = 20) => balanceHistory.slice(-n),
        profit: () => {
            if (balanceHistory.length === 0) return 0;
            return getBalance() - balanceHistory[0].prev;
        },
        wins: () => balanceHistory.filter(e => e.type === 'WIN').length,
        losses: () => balanceHistory.filter(e => e.type === 'BET').length,
        summary: () => {
            const wins = balanceHistory.filter(e => e.type === 'WIN');
            const bets = balanceHistory.filter(e => e.type === 'BET');
            const totalWin = wins.reduce((s, e) => s + e.delta, 0);
            const totalBet = bets.reduce((s, e) => s + Math.abs(e.delta), 0);
            const start = balanceHistory[0]?.prev || getBalance();
            return {
                start,
                current: getBalance(),
                profit: getBalance() - start,
                wins: wins.length,
                losses: bets.length,
                totalWin,
                totalBet,
                netWin: totalWin - totalBet
            };
        },
        
        // Manual betting
        player: async (tileIdx, clicks = 1) => {
            const tile = getTileByIndex(tileIdx);
            return tile ? clickBet(tile, Config.PLAYER_BTN, clicks) : false;
        },
        banker: async (tileIdx, clicks = 1) => {
            const tile = getTileByIndex(tileIdx);
            return tile ? clickBet(tile, Config.BANKER_BTN, clicks) : false;
        },
        
        // Get ranked tables from pp
        rank: getRankedTables,
        
        // Table info (from pp) with betting method
        tables: () => window.pp?.tables() || {},
        get: (uidOrId) => {
            const data = window.pp?.get(uidOrId);
            if (!data) return null;
            const ele = findTile(data.id) || findTile(data.name);
            return {
                ...data,
                ele,
                bet: async (clicks = 1, side = 'P') => {
                    if (!ele) { console.log('[Bet] Tile not found'); return false; }
                    const sel = side === 'B' ? Config.BANKER_BTN : Config.PLAYER_BTN;
                    return clickBet(ele, sel, clicks);
                }
            };
        },
        list: () => window.pp?.list() || [],
        
        // Print status
        print: () => {
            const tables = getRankedTables();
            console.log(`\n═══ BETTING TABLES (${tables.length}) ═══`);
            tables.forEach(t => {
                console.log(
                    `#${String(t.uid||'?').padStart(2)}: ${(t.name || t.id).slice(0, 22).padEnd(22)} ` +
                    `P:${String(t.P||0).padStart(2)} B:${String(t.B||0).padStart(2)} T:${t.T||0} ` +
                    `ratio:${t.ratio.toFixed(3)}`
                );
            });
        }
    };

    // Initialize
    watchBalance();
    waitForPP().then(() => {
        console.log('[Bet] v3.3 ready | Data from pp API');
        console.log('[Bet] Commands: bet.start() bet.stop() bet.status() bet.history()');
    });

})();

/*
╔══════════════════════════════════════════════════════════════════════════════╗
║                          BETTING API v3.3                                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  REQUIRES: socks.js WebSocket interceptor (provides pp API)                  ║
║                                                                              ║
║  AUTO BETTING                                                                ║
║  ───────────                                                                 ║
║  bet.start()              Start auto-betting                                 ║
║  bet.stop()               Stop auto-betting                                  ║
║  bet.status()             Current status {running, queue, last, balance}     ║
║                                                                              ║
║  MANUAL BETTING                                                              ║
║  ──────────────                                                              ║
║  bet.player(0, 5)         Bet on Player at tile 0, 5 clicks                  ║
║  bet.banker(0, 5)         Bet on Banker at tile 0, 5 clicks                  ║
║                                                                              ║
║  TABLE DATA (from pp API)                                                    ║
║  ────────────────────────                                                    ║
║  bet.tables()             All table data from WebSocket                      ║
║  bet.list()               Tables with UIDs [{uid, id, name, P, B, T}]        ║
║  bet.get(1)               Get table by UID (number)                          ║
║  bet.get("id")            Get table by original ID (string)                  ║
║  bet.get(1).bet(1,"P")    Bet on table (clicks, "P"|"B")                     ║
║  bet.get(1).ele           DOM element for testing                            ║
║  bet.rank()               Tables ranked by P/B balance                       ║
║  bet.print()              Print ranked tables with UIDs                      ║
║                                                                              ║
║  BALANCE TRACKING                                                            ║
║  ────────────────                                                            ║
║  bet.balance()            Get current balance from DOM                       ║
║  bet.calc()               Calculate bet size {amount, clicks}                ║
║  bet.history(20)          Last N balance changes                             ║
║  bet.profit()             Total profit since start                           ║
║  bet.wins()               Number of wins                                     ║
║  bet.losses()             Number of losses                                   ║
║  bet.summary()            Full stats {start,current,profit,wins,losses,...}  ║
║                                                                              ║
║  STRATEGY                                                                    ║
║  ────────                                                                    ║
║  - Ranks tables by P/B balance ratio (most balanced = lowest ratio)          ║
║  - Only considers tables with 20+ rounds                                     ║
║  - Random P/B selection (50/50)                                              ║
║  - Bet size: random between 1/8 and 1/2 of balance                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
*/
