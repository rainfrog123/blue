// ==UserScript==
// @name         play
// @namespace    http://tampermonkey.net/
// @version      4.0
// @description  Baccarat betting execution using pp (data) and pick (selection) APIs
// @author       You
// @match        *://client.pragmaticplaylive.net/desktop/multibaccarat/*
// @grant        none
// @run-at       document-end
// ==/UserScript==

(function() {
    'use strict';

    // ═══════════════════════════════════════════════════════════════════════
    // CONFIGURATION
    // ═══════════════════════════════════════════════════════════════════════

    const Config = {
        CHIP_VALUE: 0.2,
        MIN_BET_FRAC: 1/8,
        MAX_BET_FRAC: 1/2,
        BET_DELAY: 3000,
        CLICK_DELAY: 50,
        // DOM selectors
        PLAYER_BTN: '[data-betcode="0"]',
        BANKER_BTN: '[data-betcode="1"]',
        TILE_SEL: '[id^="TileHeight-"]'
    };

    // ═══════════════════════════════════════════════════════════════════════
    // UTILITIES
    // ═══════════════════════════════════════════════════════════════════════

    const sleep = ms => new Promise(r => setTimeout(r, ms));

    const rand = {
        bool: () => Math.random() < 0.5,
        float: () => Math.random(),
        side: () => rand.bool() ? 'P' : 'B'
    };

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

    // ═══════════════════════════════════════════════════════════════════════
    // BALANCE TRACKING
    // ═══════════════════════════════════════════════════════════════════════

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
                console.log(`[Play] Balance recovered: $${bal.toFixed(2)} - restarting`);
                betManager.stoppedDueToLowBalance = false;
                betManager.start();
            }
        }
        lastBalance = bal;
    };

    const watchBalance = () => {
        const target = document.querySelector('[data-testid="wallet-mobile-balance"]');
        if (!target) {
            setTimeout(watchBalance, 500);
            return;
        }
        lastBalance = getBalance();
        console.log(`[Bal] Watching: $${lastBalance.toFixed(2)}`);
        const observer = new MutationObserver(trackBalance);
        observer.observe(target, { childList: true, subtree: true, characterData: true });
    };

    // ═══════════════════════════════════════════════════════════════════════
    // POPUP HANDLING
    // ═══════════════════════════════════════════════════════════════════════

    const handleInsufficientFundsPopup = () => {
        const popup = document.querySelector('[data-testid="popup-content"]');
        if (!popup) return false;

        const title = popup.querySelector('[data-testid="blocking-popup-title"]');
        if (!title || title.textContent !== 'Insufficient funds') return false;

        console.log('[Popup] Insufficient funds detected');
        const buttons = popup.querySelectorAll('button[data-testid="button"]');
        for (const btn of buttons) {
            const span = btn.querySelector('span[data-testid="button-content"]');
            if (span && span.textContent === 'No, thanks') {
                simulateClick(btn);
                console.log('[Popup] Dismissed');
                return true;
            }
        }
        if (buttons.length > 0) {
            simulateClick(buttons[0]);
            return true;
        }
        return false;
    };

    const watchForPopup = () => {
        const observer = new MutationObserver(handleInsufficientFundsPopup);
        observer.observe(document.body, { childList: true, subtree: true });
    };

    // ═══════════════════════════════════════════════════════════════════════
    // BET SIZE CALCULATION
    // ═══════════════════════════════════════════════════════════════════════

    const calcBet = () => {
        const bal = getBalance();
        if (bal < Config.CHIP_VALUE) return { amount: 0, clicks: 0 };
        const min = bal * Config.MIN_BET_FRAC;
        const max = bal * Config.MAX_BET_FRAC;
        const bet = min + rand.float() * (max - min);
        const clicks = Math.max(1, Math.floor(bet / Config.CHIP_VALUE));
        return { amount: clicks * Config.CHIP_VALUE, clicks };
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

    const getTileByIndex = (idx) => {
        const tiles = document.querySelectorAll(Config.TILE_SEL);
        return tiles[idx] || null;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // BET EXECUTION
    // ═══════════════════════════════════════════════════════════════════════

    const clickBet = async (tile, selector, clicks) => {
        const btn = tile.querySelector(selector);
        if (!btn) return false;
        for (let j = 0; j < clicks; j++) {
            simulateClick(btn);
            if (j < clicks - 1) await sleep(Config.CLICK_DELAY);
        }
        return true;
    };

    const placeBet = async (tile, side, clicks) => {
        const selector = side === 'B' ? Config.BANKER_BTN : Config.PLAYER_BTN;
        // Wait for button to appear
        for (let i = 0; i < 60; i++) {
            const btn = tile.querySelector(selector);
            if (btn) return clickBet(tile, selector, clicks);
            await sleep(50);
        }
        return false;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // BETTING MANAGER
    // ═══════════════════════════════════════════════════════════════════════

    class BetManager {
        constructor() {
            this.running = false;
            this.lastBet = null;
            this.intervalId = null;
            this.stoppedDueToLowBalance = false;
            this.balanceCheckInterval = null;
            this.stats = { bets: 0, wins: 0, losses: 0 };
        }

        start() {
            if (this.running) return;
            this.running = true;
            console.log('[Play] Started');
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
            console.log('[Play] Stopped');
        }

        stopDueToLowBalance() {
            this.stoppedDueToLowBalance = true;
            this.stop(true);
            this.balanceCheckInterval = setInterval(() => {
                if (!this.stoppedDueToLowBalance) {
                    clearInterval(this.balanceCheckInterval);
                    this.balanceCheckInterval = null;
                    return;
                }
                const bal = getBalance();
                if (bal >= Config.CHIP_VALUE) {
                    console.log(`[Play] Balance recovered: $${bal.toFixed(2)}`);
                    this.stoppedDueToLowBalance = false;
                    clearInterval(this.balanceCheckInterval);
                    this.balanceCheckInterval = null;
                    this.start();
                }
            }, 2000);
        }

        async next() {
            if (!this.running) return;

            // Check balance
            const balance = getBalance();
            if (balance <= Config.CHIP_VALUE) {
                console.log(`[Play] Balance too low: $${balance.toFixed(2)}`);
                this.stopDueToLowBalance();
                return;
            }

            // Use pick API to get table and side
            if (!window.pick) {
                console.log('[Play] Waiting for pick API...');
                this.intervalId = setTimeout(() => this.next(), 1000);
                return;
            }

            const choice = window.pick.pick();
            if (!choice) {
                console.log('[Play] No eligible tables');
                this.intervalId = setTimeout(() => this.next(), Config.BET_DELAY);
                return;
            }

            const { table, side } = choice;

            // Find tile
            const tile = findTile(table.gameId) || findTile(table.id) || getTileByIndex(table.uid - 1);
            if (!tile) {
                console.log(`[Play] Tile not found: ${table.name || table.gameId}`);
                this.intervalId = setTimeout(() => this.next(), Config.BET_DELAY);
                return;
            }

            // Check betting still open
            if (table.canBet !== true) {
                console.log(`[Play] Table closed: ${table.name}`);
                this.intervalId = setTimeout(() => this.next(), Config.BET_DELAY);
                return;
            }

            // Scroll and bet
            tile.scrollIntoView({ block: 'center' });
            const { amount, clicks } = calcBet();
            if (clicks === 0) {
                this.intervalId = setTimeout(() => this.next(), Config.BET_DELAY);
                return;
            }

            const placed = await placeBet(tile, side, clicks);
            if (placed) {
                this.lastBet = {
                    table: table.name || table.gameId,
                    side,
                    amount,
                    time: Date.now(),
                    P: table.P,
                    B: table.B,
                    T: table.T,
                    streak: table.streak
                };
                this.stats.bets++;
                console.log(
                    `[Play] ${table.name || table.id} | ${side} $${amount.toFixed(2)} | ` +
                    `P:${table.P} B:${table.B} streak:${table.streak?.length || 0}${table.streak?.side || ''}`
                );
            } else {
                console.log('[Play] Bet failed - button not found');
            }

            this.intervalId = setTimeout(() => this.next(), Config.BET_DELAY);
        }

        status() {
            return {
                running: this.running,
                last: this.lastBet,
                balance: getBalance(),
                stats: this.stats
            };
        }
    }

    const betManager = new BetManager();

    // ═══════════════════════════════════════════════════════════════════════
    // API
    // ═══════════════════════════════════════════════════════════════════════

    window.play = {
        // Auto betting
        start: () => betManager.start(),
        stop: () => betManager.stop(),
        status: () => betManager.status(),

        // Balance
        balance: getBalance,
        calc: calcBet,
        history: (n = 20) => balanceHistory.slice(-n),
        profit: () => balanceHistory.length ? getBalance() - balanceHistory[0].prev : 0,
        summary: () => {
            const wins = balanceHistory.filter(e => e.type === 'WIN');
            const bets = balanceHistory.filter(e => e.type === 'BET');
            const start = balanceHistory[0]?.prev || getBalance();
            return {
                start,
                current: getBalance(),
                profit: getBalance() - start,
                wins: wins.length,
                bets: bets.length,
                totalWin: wins.reduce((s, e) => s + e.delta, 0),
                totalBet: bets.reduce((s, e) => s + Math.abs(e.delta), 0)
            };
        },

        // Manual betting
        player: async (tileIdx, clicks = 1) => {
            const tile = getTileByIndex(tileIdx);
            if (!tile) return false;
            tile.scrollIntoView({ block: 'center' });
            return placeBet(tile, 'P', clicks);
        },
        banker: async (tileIdx, clicks = 1) => {
            const tile = getTileByIndex(tileIdx);
            if (!tile) return false;
            tile.scrollIntoView({ block: 'center' });
            return placeBet(tile, 'B', clicks);
        },

        // Bet on specific table
        bet: async (uidOrId, side = 'P', clicks = 1) => {
            const t = window.pp?.get(uidOrId);
            if (!t) { console.log('[Play] Table not found'); return false; }
            const tile = findTile(t.gameId) || findTile(t.id);
            if (!tile) { console.log('[Play] Tile not found'); return false; }
            if (t.canBet !== true) { console.log('[Play] Table not open'); return false; }
            tile.scrollIntoView({ block: 'center' });
            return placeBet(tile, side, clicks);
        },

        // Config
        config: Config,

        // Quick print
        print: () => {
            const s = betManager.status();
            console.log(`\n═══ PLAY STATUS ═══`);
            console.log(`Running: ${s.running} | Balance: $${s.balance.toFixed(2)}`);
            console.log(`Bets: ${s.stats.bets} | Profit: $${window.play.profit().toFixed(2)}`);
            if (s.last) {
                console.log(`Last: ${s.last.table} ${s.last.side} $${s.last.amount.toFixed(2)}`);
            }
        }
    };

    // ═══════════════════════════════════════════════════════════════════════
    // INITIALIZATION
    // ═══════════════════════════════════════════════════════════════════════

    const waitForAPIs = () => new Promise(resolve => {
        const check = () => (window.pp && window.pick) ? resolve() : setTimeout(check, 100);
        check();
    });

    watchBalance();
    watchForPopup();
    waitForAPIs().then(() => {
        console.log('[Play] v4.0 | Uses pp (data) + pick (selection)');
        console.log('[Play] Commands: play.start() play.stop() play.status() play.print()');
    });

})();

/*
╔══════════════════════════════════════════════════════════════════════════════╗
║                           PLAY API v4.0                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  REQUIRES: socks.js (pp API) + pick.js (pick API)                            ║
║                                                                              ║
║  AUTO BETTING                                                                ║
║  ───────────                                                                 ║
║  play.start()            Start auto-betting using pick.pick()                ║
║  play.stop()             Stop auto-betting                                   ║
║  play.status()           {running, last, balance, stats}                     ║
║  play.print()            Print current status                                ║
║                                                                              ║
║  MANUAL BETTING                                                              ║
║  ──────────────                                                              ║
║  play.player(0, 5)       Bet Player on tile 0, 5 clicks                      ║
║  play.banker(0, 5)       Bet Banker on tile 0, 5 clicks                      ║
║  play.bet(1, 'P', 3)     Bet on table UID 1, Player, 3 clicks                ║
║                                                                              ║
║  BALANCE                                                                     ║
║  ───────                                                                     ║
║  play.balance()          Current balance                                     ║
║  play.calc()             Calculate bet {amount, clicks}                      ║
║  play.history(20)        Last N balance changes                              ║
║  play.profit()           Total profit since start                            ║
║  play.summary()          Full stats                                          ║
║                                                                              ║
║  CONFIG (play.config)                                                        ║
║  ────────────────────                                                        ║
║  CHIP_VALUE: 0.2         Chip value per click                                ║
║  MIN_BET_FRAC: 1/8       Min bet as fraction of balance                      ║
║  MAX_BET_FRAC: 1/2       Max bet as fraction of balance                      ║
║  BET_DELAY: 3000         Delay between bets (ms)                             ║
║                                                                              ║
║  SYSTEM ARCHITECTURE                                                         ║
║  ───────────────────                                                         ║
║  socks.js (pp API)   → WebSocket data collection                             ║
║  pick.js (pick API)  → Table selection rules                                 ║
║  play.js (play API)  → Bet execution                                         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
*/

