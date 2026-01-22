// ==UserScript==
// @name         fixed bet 0.2
// @namespace    http://tampermonkey.net/
// @version      7.0
// @description  Event-driven crypto-secure random betting - Fixed 0.2 chip every 4-6 rounds (receives comprehensive game state from result.js)
// @author       you
// @match        *://client.pragmaticplaylive.net/desktop/baccarat/*
// @grant        unsafeWindow
// @run-at       document-idle
// ==/UserScript==

(function () {
    'use strict';

    /**
     * Configuration
     */
    const CONFIG = {
        ROUND_DELAY: 10000,          // ms after result before betting (10 seconds)
        FIXED_BET_AMOUNT: 0.2,       // Always bet exactly 0.2 (1 chip)
        DEBUG: true,                // Enable debug logging
        SELECTORS: {
            // Only betting areas needed - result detection handled by result.js
            playerArea: '#leftBetTextRoot',
            bankerArea: '#rightBetTextRoot'
        }
    };

    /**
     * Crypto-based random utilities
     */
    class CryptoRandom {
        // Generate secure random boolean
        static randomBool() {
            return crypto.getRandomValues(new Uint8Array(1))[0] & 1;
        }

        // Generate secure random float between 0 and 1
        static randomFloat() {
            const array = new Uint32Array(1);
            crypto.getRandomValues(array);
            return array[0] / (0xFFFFFFFF + 1);
        }

        // Generate secure random integer between min and max (inclusive)
        static randomInt(min, max) {
            return Math.floor(this.randomFloat() * (max - min + 1)) + min;
        }

        // Choose Player or Banker randomly
        static randomSide() {
            return this.randomBool() ? 'Player' : 'Banker';
        }
    }

    /**
     * Simple logger
     */
    class Logger {
        static log(msg) {
            console.log(`[FixedBet] ${new Date().toLocaleTimeString()} - ${msg}`);
        }
        static debug(msg) {
            if (CONFIG.DEBUG) console.log(`[DEBUG] ${msg}`);
        }
    }

    /**
     * Simplified DOM utilities - Event-driven, no counter detection
     */
    class DOMUtils {
        static getPlayerArea() {
            return document.querySelector(CONFIG.SELECTORS.playerArea);
        }

        static getBankerArea() {
            return document.querySelector(CONFIG.SELECTORS.bankerArea);
        }

        static areElementsReady() {
            return !!(this.getPlayerArea() && this.getBankerArea());
        }
    }

    /**
     * Fixed betting logic - Always 0.2
     */
    class BettingLogic {
        static simulateClick(element) {
            try {
                // Simple and effective PointerEvent sequence
                const downEvent = new PointerEvent('pointerdown', {
                    bubbles: true,
                    cancelable: true,
                    pointerType: 'mouse',
                });

                const upEvent = new PointerEvent('pointerup', {
                    bubbles: true,
                    cancelable: true,
                    pointerType: 'mouse',
                });

                element.dispatchEvent(downEvent);
                element.dispatchEvent(upEvent);

                return true;
            } catch (error) {
                Logger.log(`❌ Click simulation error: ${error.message}`);
                return false;
            }
        }

        static getCurrentBalance() {
            try {
                // Use robust method to find balance
                const balanceLabel = [...document.querySelectorAll('div')]
                    .find(el => el.textContent.trim() === 'Balance');
                if (!balanceLabel) return 0;

                const balanceContainer = balanceLabel.parentElement;
                if (!balanceContainer) return 0;

                const balanceValueDiv = balanceContainer.querySelector('div:not(:first-child) span');
                if (!balanceValueDiv) return 0;

                const balanceText = balanceValueDiv.textContent.trim();
                const balance = parseFloat(balanceText.replace(/[^0-9.]/g, ''));

                return !isNaN(balance) ? balance : 0;
            } catch {
                return 0;
            }
        }

        static calculateBetAmount() {
            // Always bet exactly 0.2 (1 chip)
            return {
                betAmount: CONFIG.FIXED_BET_AMOUNT,
                chips: 1
            };
        }

        static async placeBet(side) {
            try {
                const balance = this.getCurrentBalance();
                if (balance < CONFIG.FIXED_BET_AMOUNT) {
                    Logger.log(`❌ Insufficient balance: $${balance.toFixed(2)} (need $${CONFIG.FIXED_BET_AMOUNT})`);
                    return false;
                }

                const { betAmount, chips } = this.calculateBetAmount();

                Logger.log(`💰 Betting $${betAmount.toFixed(2)} (${chips} chip) on ${side} | Balance: $${balance.toFixed(2)}`);

                const area = side === 'Player' ? DOMUtils.getPlayerArea() : DOMUtils.getBankerArea();
                if (!area) {
                    Logger.log(`❌ ${side} area not found`);
                    return false;
                }

                // Single click for 0.2 bet
                const success = this.simulateClick(area);
                if (!success) {
                    Logger.log(`❌ Failed to click on ${side}`);
                    return false;
                }

                Logger.log(`✅ ${side} bet placed: $${betAmount.toFixed(2)} (1 click)`);
                return true;

            } catch (error) {
                Logger.log(`❌ Bet error: ${error.message}`);
                return false;
            }
        }
    }

    /**
     * Game state manager - Event-driven
     */
    class GameState {
        constructor() {
            this.round = 0;
            this.roundsSinceLastBet = 0;
            this.nextBetRound = this.getRandomInterval();
            this.waitingForResult = false;
            this.isRunning = false;
            this.lastResult = null;
            this.gameCounters = { P: 0, B: 0, T: 0 };
            this.gameStats = { totalRounds: 0, playerWinRate: 0 };
        }

        getRandomInterval() {
            return CryptoRandom.randomInt(4, 6); // 4-6 rounds using crypto random
        }

        onGameStateUpdate(gameState) {
            this.waitingForResult = false;
            this.round = gameState.roundNumber || this.round + 1;
            this.roundsSinceLastBet++;
            this.lastResult = gameState.triggeredBy;
            this.gameCounters = gameState.counters;
            this.gameStats = gameState.totals;

            const roundsLeft = this.nextBetRound - this.roundsSinceLastBet;
            Logger.log(`🎯 Result: ${gameState.triggeredBy} | Round #${this.round} | P:${gameState.counters.P} B:${gameState.counters.B} T:${gameState.counters.T} | Next bet in: ${roundsLeft} round(s)`);

            if (this.roundsSinceLastBet >= this.nextBetRound) {
                this.scheduleBet();
            }
        }

        scheduleBet() {
            if (this.waitingForResult) return;

            Logger.log(`⏰ Scheduling bet in ${CONFIG.ROUND_DELAY}ms`);

            setTimeout(async () => {
                if (!this.waitingForResult && DOMUtils.areElementsReady()) {
                    const side = CryptoRandom.randomSide();
                    const success = await BettingLogic.placeBet(side);

                    if (success) {
                        this.waitingForResult = true;
                        this.roundsSinceLastBet = 0;
                        this.nextBetRound = this.getRandomInterval();
                    }
                }
            }, CONFIG.ROUND_DELAY);
        }

        start() {
            if (this.isRunning) return;

            Logger.log('🟢 Started - Fixed 0.2 betting every 4-6 rounds (Event-driven)');
            this.isRunning = true;

            // Listen for comprehensive game state events from result.js
            window.addEventListener('ResultDetected', (event) => {
                if (this.isRunning) {
                    this.onGameStateUpdate(event.detail);
                }
            });

            Logger.log('📡 Listening for ResultDetected events...');
        }

        stop() {
            this.isRunning = false;
            Logger.log('🔴 Stopped');
        }

        getStatus() {
            return {
                round: this.round,
                roundsLeft: Math.max(0, this.nextBetRound - this.roundsSinceLastBet),
                waiting: this.waitingForResult,
                running: this.isRunning,
                lastResult: this.lastResult,
                counters: this.gameCounters,
                stats: this.gameStats
            };
        }
    }

    /**
     * Minimal HUD
     */
    class MiniHUD {
        constructor(gameState) {
            this.gameState = gameState;
            this.createHUD();
        }

        createHUD() {
            this.hud = document.createElement('div');
            Object.assign(this.hud.style, {
                position: 'fixed',
                bottom: '10px',
                left: '10px',
                background: 'rgba(0, 0, 0, 0.8)',
                color: '#0f0',
                font: '11px monospace',
                padding: '4px 8px',
                borderRadius: '4px',
                zIndex: '99999',
                minWidth: '120px'
            });

            document.body.appendChild(this.hud);

            setInterval(() => this.update(), 500);
        }

        getBalance() {
            try {
                // Use robust method to find balance
                const balanceLabel = [...document.querySelectorAll('div')]
                    .find(el => el.textContent.trim() === 'Balance');
                if (!balanceLabel) return 'N/A';

                const balanceContainer = balanceLabel.parentElement;
                if (!balanceContainer) return 'N/A';

                const balanceValueDiv = balanceContainer.querySelector('div:not(:first-child) span');
                if (!balanceValueDiv) return 'N/A';

                return balanceValueDiv.textContent.trim();
            } catch {
                return 'N/A';
            }
        }

        update() {
            const s = this.gameState.getStatus();
            const balance = this.getBalance();

            const status = s.waiting ? '⏳' : s.running ? '🟢' : '🔴';
            const nextBet = s.roundsLeft === 0 ? 'NOW' : s.roundsLeft;
            const lastResult = s.lastResult ? ` | Last: ${s.lastResult}` : '';
            const counters = s.counters ? ` | P:${s.counters.P} B:${s.counters.B} T:${s.counters.T}` : '';
            const winRate = s.stats?.playerWinRate ? ` | P Rate: ${s.stats.playerWinRate}%` : '';

            this.hud.innerHTML = `${status} #${s.round} | Next: ${nextBet} | ${balance}${lastResult}${counters}${winRate} | BET: $0.20`;
        }
    }

    // Initialize
    const gameState = new GameState();
    const hud = new MiniHUD(gameState);

    // Wait for DOM then start (event-driven mode)
    setTimeout(() => {
        if (DOMUtils.areElementsReady()) {
            gameState.start();
            Logger.log('✅ FixedBet v7.0 ready - Event-driven $0.20 betting every 4-6 rounds enabled');
            Logger.log('📊 Enhanced: Receives comprehensive game state (counters, round, win rates)');
        } else {
            Logger.log('⚠️ Betting areas not ready, retrying...');
            setTimeout(() => {
                if (DOMUtils.areElementsReady()) {
                    gameState.start();
                    Logger.log('✅ FixedBet v7.0 ready - Event-driven $0.20 betting every 4-6 rounds enabled');
                    Logger.log('📊 Enhanced: Receives comprehensive game state (counters, round, win rates)');
                }
            }, 3000);
        }
    }, 2000);

    // Global API
    window.fixedBet = {
        start: () => gameState.start(),
        stop: () => gameState.stop(),
        status: () => gameState.getStatus(),
        testBet: (side = 'Player') => BettingLogic.placeBet(side),
        getBalance: () => BettingLogic.getCurrentBalance(),
        calcBet: () => {
            const balance = BettingLogic.getCurrentBalance();
            const result = BettingLogic.calculateBetAmount();
            console.log(`Balance: $${balance.toFixed(2)}, Fixed Bet: $${result.betAmount.toFixed(2)} (${result.chips} chip)`);
            return result;
        },
        // Crypto random test functions
        testRandom: () => {
            console.log('Testing crypto random functions:');
            console.log(`Random bool: ${CryptoRandom.randomBool()}`);
            console.log(`Random float: ${CryptoRandom.randomFloat()}`);
            console.log(`Random int (4-6): ${CryptoRandom.randomInt(4, 6)}`);
            console.log(`Random side: ${CryptoRandom.randomSide()}`);
        },
        randomSide: () => CryptoRandom.randomSide()
    };

})();