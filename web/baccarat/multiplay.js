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
        BET_DELAY: 3000,
        CLICK_DELAY: 50,
        // DOM selectors
        PLAYER_BTN: '[data-betcode="0"]',
        BANKER_BTN: '[data-betcode="1"]',
        TILE_SEL: '[id^="TileHeight-"]'
    };

    // Simple random
    const rand = {
        bool: () => Math.random() < 0.5,
        float: () => Math.random(),
        side: () => rand.bool() ? 'P' : 'B'
    };

    const shuffle = (list) => {
        const a = [...list];
        for (let i = a.length - 1; i > 0; i--) {
            const j = Math.floor(rand.float() * (i + 1));
            [a[i], a[j]] = [a[j], a[i]];
        }
        return a;
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

            // Check if we should restart auto betting due to recovered balance
            if (betManager.stoppedDueToLowBalance && bal >= Config.CHIP_VALUE) {
                console.log(`[Bet] Balance recovered: $${bal.toFixed(2)} - restarting auto betting`);
                betManager.stoppedDueToLowBalance = false;
                betManager.start();
            }
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

    // Handle insufficient funds popup
    const handleInsufficientFundsPopup = () => {
        const popup = document.querySelector('[data-testid="popup-content"]');
        if (!popup) return false;

        const title = popup.querySelector('[data-testid="blocking-popup-title"]');
        if (!title || title.textContent !== 'Insufficient funds') return false;

        console.log('[Popup] Insufficient funds popup detected');

        // Click "No, thanks" button
        const buttons = popup.querySelectorAll('button[data-testid="button"]');
        for (const btn of buttons) {
            const span = btn.querySelector('span[data-testid="button-content"]');
            if (span && span.textContent === 'No, thanks') {
                simulateClick(btn);
                console.log('[Popup] Clicked "No, thanks"');
                return true;
            }
        }

        // If no "No, thanks" button found, click first button as fallback
        const allButtons = popup.querySelectorAll('button[data-testid="button"]');
        if (allButtons.length > 0) {
            simulateClick(allButtons[0]);
            console.log('[Popup] Clicked first button (fallback)');
            return true;
        }

        return false;
    };

    // Watch for insufficient funds popup
    const watchForPopup = () => {
        const observer = new MutationObserver(() => {
            handleInsufficientFundsPopup();
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
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

        for (let j = 0; j < clicks; j++) {
            simulateClick(btn);
            if (j < clicks - 1) await sleep(Config.CLICK_DELAY);
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

    // Betting availability from pp WebSocket
    const canBetNow = (t) => t?.canBet === true;

    // Get all tables eligible for random bet (>=20 rounds, P/B diff <=3, open)
    const getRankedTables = () => {
        if (!window.pp) return [];
        return shuffle(
            [...Object.values(window.pp.tables())]
                .filter(t => {
                    const total = t.total || 0;
                    const diff = Math.abs((t.P || 0) - (t.B || 0));
                    return total >= Config.MIN_ROUNDS && diff <= 3 && canBetNow(t);
                })
        );
    };

    // Betting Manager
    class BetManager {
        constructor() {
            this.running = false;
            this.lastBet = null;
            this.intervalId = null;
            this.stoppedDueToLowBalance = false;
            this.balanceCheckInterval = null;
        }

        start() {
            if (this.running) return;
            this.running = true;
            console.log('[Bet] Started');
            if (this.balanceCheckInterval) {
                clearInterval(this.balanceCheckInterval);
                this.balanceCheckInterval = null;
            }
            this.next();
        }

        stop(keepFlag = false) {
            this.running = false;
            if (!keepFlag) this.stoppedDueToLowBalance = false;
            if (this.intervalId) {
                clearInterval(this.intervalId);
                this.intervalId = null;
            }
            if (this.balanceCheckInterval) {
                clearInterval(this.balanceCheckInterval);
                this.balanceCheckInterval = null;
            }
            console.log('[Bet] Stopped');
        }

        stopDueToLowBalance() {
            this.stoppedDueToLowBalance = true;
            this.stop(true);
            // Start periodic balance check to restart when balance recovers
            this.balanceCheckInterval = setInterval(() => {
                if (!this.stoppedDueToLowBalance) {
                    clearInterval(this.balanceCheckInterval);
                    this.balanceCheckInterval = null;
                    return;
                }
                const bal = getBalance();
                if (bal >= Config.CHIP_VALUE) {
                    console.log(`[Bet] Balance recovered: $${bal.toFixed(2)} - restarting auto betting`);
                    this.stoppedDueToLowBalance = false;
                    clearInterval(this.balanceCheckInterval);
                    this.balanceCheckInterval = null;
                    this.start();
                }
            }, 2000); // Check every 2 seconds
        }

        async next() {
            if (!this.running) return;

            // Check balance first - stop if too low
            const balance = getBalance();
            if (balance <= Config.CHIP_VALUE) {
                console.log(`[Bet] Balance too low: $${balance.toFixed(2)} - stopping auto betting`);
                this.stopDueToLowBalance();
                return;
            }

            // Refresh candidates and pick random table
            const candidates = getRankedTables();
            if (candidates.length === 0) {
                console.log('[Bet] No eligible tables');
                this.intervalId = setTimeout(() => this.next(), Config.BET_DELAY);
                return;
            }

            const table = candidates[Math.floor(Math.random() * candidates.length)];

            // Find corresponding tile by table UID
            const tileIdx = table.uid - 1; // UIDs start from 1
            const tile = getTileByIndex(tileIdx);
            if (!tile) {
                console.log(`[Bet] Tile not found for table ${table.name || table.id}`);
                this.intervalId = setTimeout(() => this.next(), Config.BET_DELAY);
                return;
            }

            // Check betting status from pp WebSocket
            if (!canBetNow(table)) {
                console.log(`[Bet] Table not open: ${table.name || table.id}`);
                this.intervalId = setTimeout(() => this.next(), Config.BET_DELAY);
                return;
            }

            // Scroll tile into view and wait for buttons
            tile.scrollIntoView({block: 'center'});
            const side = rand.side();
            const selector = side === 'P' ? Config.PLAYER_BTN : Config.BANKER_BTN;

            // Place bet
            const { amount, clicks } = calcBet();
            if (clicks === 0) {
                console.log('[Bet] Insufficient balance for bet calculation');
                this.intervalId = setTimeout(() => this.next(), Config.BET_DELAY);
                return;
            }

            // Wait for button to appear (same logic as manual betting)
            for (let i = 0; i < 60; i++) { // ~3s max
                const btn = tile.querySelector(selector);
                if (btn) {
                    const placed = await clickBet(tile, selector, clicks);
                    if (placed) {
                        this.lastBet = { table: table.name || table.id, side, amount, time: Date.now() };
                        console.log(`[Bet] ${table.name || table.id} | ${side} $${amount.toFixed(2)} | P:${table.P} B:${table.B} T:${table.T}`);
                    }
                    this.intervalId = setTimeout(() => this.next(), Config.BET_DELAY);
                    return;
                }
                await sleep(50);
            }
            console.log('[Bet] Button not found');
            this.intervalId = setTimeout(() => this.next(), Config.BET_DELAY);
        }

        status() {
            return {
                running: this.running,
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
            if (!tile) return false;
            tile.scrollIntoView({block: 'center'});
            return clickBet(tile, Config.PLAYER_BTN, clicks);
        },
        banker: async (tileIdx, clicks = 1) => {
            const tile = getTileByIndex(tileIdx);
            if (!tile) return false;
            tile.scrollIntoView({block: 'center'});
            return clickBet(tile, Config.BANKER_BTN, clicks);
        },
        
        // Get ranked tables from pp
        rank: getRankedTables,
        
        // Table info (from pp) with betting method
        tables: () => window.pp?.tables() || {},
        get: (uidOrId) => {
            const data = window.pp?.get(uidOrId);
            if (!data) return null;
            const idx = Number.isInteger(data.uid) ? data.uid - 1 : null;
            const ele = findTile(data.id) || findTile(data.name) || (idx !== null ? getTileByIndex(idx) : null);
            return {
                ...data,
                ele,
                bet: async (clicks = 1, side = 'P') => {
                    if (!ele) { console.log('[Bet] Tile not found'); return false; }
                    const t = window.pp?.get(uidOrId) || data;
                    if (t?.canBet === false) { console.log('[Bet] Table not open'); return false; }
                    ele.scrollIntoView({block: 'center' });
                    const sel = side === 'B' ? Config.BANKER_BTN : Config.PLAYER_BTN;
                    for (let i = 0; i < 60; i++) { // ~3s max
                        const btn = ele.querySelector(sel);
                        if (btn) return clickBet(ele, sel, clicks);
                        await sleep(50);
                    }
                    console.log('[Bet] Button not found');
                    return false;
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
    watchForPopup();
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
║  bet.status()             Current status {running, last, balance}            ║
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
