// ==UserScript==
// @name         balance+result
// @namespace    http://tampermonkey.net/
// @version      7.0
// @description  Unified balance and result detector for Baccarat
// @author       You
// @match        *://client.pragmaticplaylive.net/desktop/baccarat/*
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_log
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    // ═══════════════════════════════════════════════════════════════
    // CONFIGURATION
    // ═══════════════════════════════════════════════════════════════
    const CONFIG = {
        STORAGE_KEY: 'currentBalance',
        VALID_RESULTS: ['B', 'P', 'T'],
        CHECK_INTERVAL: 500,
        INIT_DELAY: 1000,
        DEBUG: true,

        SELECTORS: {
            resultLabel: ['.km_kp'],
            resultValue: ['.km_ky'],
            roundNumber: ['.jV_jW', '.ju_jv', '[class*="round"]']
        }
    };

    // ═══════════════════════════════════════════════════════════════
    // UTILITIES
    // ═══════════════════════════════════════════════════════════════
    const Utils = {
        log: (msg, type = 'log') => CONFIG.DEBUG && console[type](`[Monitor] ${msg}`),
        
        parseNumber: (text) => {
            if (!text) return null;
            const num = parseFloat(text.replace(/[^0-9.]/g, ''));
            return isNaN(num) ? null : num;
        },

        querySelector: (selectors, parent = document) => {
            for (const sel of selectors) {
                const el = parent.querySelector(sel);
                if (el) return el;
            }
            return null;
        },

        querySelectorAll: (selectors, parent = document) => {
            for (const sel of selectors) {
                const els = parent.querySelectorAll(sel);
                if (els.length) return els;
            }
            return [];
        }
    };

    // ═══════════════════════════════════════════════════════════════
    // BALANCE DETECTOR
    // ═══════════════════════════════════════════════════════════════
    const BalanceDetector = {
        lastBalance: null,

        findBalanceElement() {
            const labels = document.querySelectorAll('[data-testid="wallet-mobile-label"]');
            for (const label of labels) {
                if (label.textContent.trim() === 'Balance') {
                    return label.parentElement?.querySelector('[data-testid="wallet-mobile-balance-value"] span');
                }
            }
            return null;
        },

        detect() {
            try {
                const el = this.findBalanceElement();
                if (!el) return null;

                const balance = Utils.parseNumber(el.textContent);
                if (!balance || balance < 0.01) return null;

                if (this.lastBalance !== balance) {
                    this.lastBalance = balance;
                    this.save(balance);
                    Utils.log(`Balance: $${balance.toFixed(2)}`);
                    this.emit(balance);
                }

                return balance;
            } catch (e) {
                Utils.log(`Balance error: ${e.message}`, 'error');
                return null;
            }
        },

        save(balance) {
            localStorage.setItem(CONFIG.STORAGE_KEY, balance.toString());
            localStorage.setItem(`${CONFIG.STORAGE_KEY}_timestamp`, Date.now().toString());
        },

        emit(balance) {
            window.dispatchEvent(new CustomEvent('BalanceUpdated', { 
                detail: { balance, timestamp: Date.now() }
            }));
        },

        get() {
            return Utils.parseNumber(localStorage.getItem(CONFIG.STORAGE_KEY));
        }
    };

    // ═══════════════════════════════════════════════════════════════
    // RESULT DETECTOR
    // ═══════════════════════════════════════════════════════════════
    const ResultDetector = {
        prevCounts: { B: null, P: null, T: null },

        getCounts() {
            const counts = {};
            const labels = Utils.querySelectorAll(CONFIG.SELECTORS.resultLabel);
            const values = Utils.querySelectorAll(CONFIG.SELECTORS.resultValue);

            const len = Math.min(labels.length, values.length);
            for (let i = 0; i < len; i++) {
                const label = labels[i]?.textContent?.trim();
                const value = parseInt(values[i]?.textContent?.trim(), 10);
                
                if (CONFIG.VALID_RESULTS.includes(label) && !isNaN(value)) {
                    counts[label] = value;
                }
            }

            return Object.keys(counts).length >= 3 ? counts : null;
        },

        getRoundNumber() {
            for (const sel of CONFIG.SELECTORS.roundNumber) {
                const el = document.querySelector(sel);
                if (el) {
                    const match = el.textContent.match(/#(\d+)/);
                    if (match) return parseInt(match[1], 10);
                }
            }
            return 0;
        },

        detect() {
            const counts = this.getCounts();
            if (!counts) return null;

            const changed = [];

            for (const r of CONFIG.VALID_RESULTS) {
                const prev = this.prevCounts[r];
                const curr = counts[r];

                if (prev !== null && curr > prev) {
                    changed.push(r);
                }
                this.prevCounts[r] = curr;
            }

            if (changed.length === 0) return null;

            const total = counts.P + counts.B + counts.T;
            const result = {
                winner: changed[0],
                round: this.getRoundNumber(),
                counts: { ...counts },
                total,
                rates: {
                    P: Math.round((counts.P / total) * 100),
                    B: Math.round((counts.B / total) * 100),
                    T: Math.round((counts.T / total) * 100)
                },
                timestamp: Date.now()
            };

            Utils.log(`${result.winner} → #${result.round} | P:${counts.P} B:${counts.B} T:${counts.T}`);
            this.emit(result);

            return result;
        },

        emit(result) {
            window.dispatchEvent(new CustomEvent('ResultDetected', { detail: result }));
        }
    };

    // ═══════════════════════════════════════════════════════════════
    // MAIN MONITOR
    // ═══════════════════════════════════════════════════════════════
    const Monitor = {
        observer: null,
        pollInterval: null,

        start() {
            Utils.log('Baccarat Monitor v7.0');

            // Initial detection
            BalanceDetector.detect();
            ResultDetector.detect();

            // Setup mutation observer for reactive updates
            this.setupObserver();

            // Backup polling for reliability
            this.pollInterval = setInterval(() => {
                BalanceDetector.detect();
                ResultDetector.detect();
            }, CONFIG.CHECK_INTERVAL);
        },

        setupObserver() {
            this.observer = new MutationObserver((mutations) => {
                let shouldCheck = false;

                for (const m of mutations) {
                    if (m.type === 'characterData') {
                        shouldCheck = true;
                        break;
                    }
                    if (m.addedNodes.length) {
                        for (const node of m.addedNodes) {
                            if (node.nodeType === 1 && (node.tagName === 'SPAN' || node.querySelector?.('span'))) {
                                shouldCheck = true;
                                break;
                            }
                        }
                    }
                    if (shouldCheck) break;
                }

                if (shouldCheck) {
                    setTimeout(() => {
                        BalanceDetector.detect();
                        ResultDetector.detect();
                    }, 50);
                }
            });

            this.observer.observe(document.body, {
                childList: true,
                subtree: true,
                characterData: true
            });
        },

        stop() {
            this.observer?.disconnect();
            clearInterval(this.pollInterval);
            Utils.log('Monitor stopped');
        }
    };

    // ═══════════════════════════════════════════════════════════════
    // INITIALIZATION
    // ═══════════════════════════════════════════════════════════════
    const init = () => {
        if (document.body) {
            setTimeout(() => Monitor.start(), CONFIG.INIT_DELAY);
        } else {
            document.addEventListener('DOMContentLoaded', () => {
                setTimeout(() => Monitor.start(), CONFIG.INIT_DELAY);
            });
        }
    };

    // Expose for debugging
    window.BaccaratMonitor = { Monitor, BalanceDetector, ResultDetector, CONFIG };

    init();
})();
