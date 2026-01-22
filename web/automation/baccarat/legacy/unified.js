// ==UserScript==
// @name         balance+result
// @namespace    http://tampermonkey.net/
// @version      6.0
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

    const CONFIG = {
        // Balance detection
        STORAGE_KEY: 'currentBalance',
        MIN_VALID_BALANCE: 0.1,
        MAX_VALID_BALANCE: 100000,
        
        // Result detection
        VALID_RESULTS: ['B', 'P', 'T'],
        LABEL_CLASS: 'km_kp',
        VALUE_CLASS: 'km_ky',
        CHECK_INTERVAL: 500,
        
        // Debug
        DEBUG: true,
        VERBOSE: false
    };

    const STATE = {
        lastConfirmedBalance: null,
        lastUpdateTime: 0,
        previousCounts: { B: null, P: null, T: null }
    };

    const log = (msg, type = 'info') => {
        if (CONFIG.DEBUG) console[type](`[Monitor] ${msg}`);
    };

    function extractNumericValue(text) {
        if (!text) return null;
        const value = parseFloat(text.replace(/[^0-9.]/g, ''));
        return !isNaN(value) ? value : null;
    }

    function detectBalance() {
        try {
            const balanceLabel = [...document.querySelectorAll('div')]
                .find(el => el.textContent.trim() === 'Balance');
            
            if (!balanceLabel) return;

            const balanceValueDiv = balanceLabel.parentElement?.querySelector('div:not(:first-child) span');
            if (!balanceValueDiv) return;

            const balance = extractNumericValue(balanceValueDiv.textContent);
            
            if (balance >= CONFIG.MIN_VALID_BALANCE) {
                const previousBalance = parseFloat(localStorage.getItem(CONFIG.STORAGE_KEY)) || null;
                
                if (previousBalance !== balance) {
                    log(`Balance updated: ${balance.toFixed(2)}`);
                    localStorage.setItem(CONFIG.STORAGE_KEY, balance.toString());
                    localStorage.setItem(`${CONFIG.STORAGE_KEY}_timestamp`, Date.now().toString());
                    STATE.lastConfirmedBalance = balance;
                    STATE.lastUpdateTime = Date.now();
                }
            }
        } catch (error) {
            log(`Balance detection error: ${error.message}`, 'error');
        }
    }

    function getCurrentCounts() {
        const counts = {};
        const labelElements = document.querySelectorAll(`.${CONFIG.LABEL_CLASS}`);
        const valueElements = document.querySelectorAll(`.${CONFIG.VALUE_CLASS}`);

        for (let i = 0; i < Math.min(labelElements.length, valueElements.length); i++) {
            const label = labelElements[i]?.textContent?.trim();
            const value = valueElements[i]?.textContent?.trim();

            if (CONFIG.VALID_RESULTS.includes(label) && value !== undefined) {
                counts[label] = parseInt(value, 10);
            }
        }

        return Object.keys(counts).length > 0 ? counts : null;
    }

    function getRoundNumber() {
        const selectors = ['.jV_jW', '.ju_jv', '[class*="round"]'];
        for (const selector of selectors) {
            const element = document.querySelector(selector);
            if (element) {
                const match = element.textContent.match(/#(\d+)/);
                if (match) return parseInt(match[1]);
            }
        }
        return 0;
    }

    function detectResults() {
        const currentCounts = getCurrentCounts();
        if (!currentCounts) return;

        let changedResults = [];

        CONFIG.VALID_RESULTS.forEach(result => {
            const prev = STATE.previousCounts[result];
            const curr = currentCounts[result];

            if (prev !== null && curr !== undefined && curr > prev) {
                changedResults.push(result);
            }

            STATE.previousCounts[result] = curr;
        });

        if (changedResults.length > 0) {
            const roundNumber = getRoundNumber();
            const totalRounds = (currentCounts.P || 0) + (currentCounts.B || 0) + (currentCounts.T || 0);
            
            const gameState = {
                changedResults,
                triggeredBy: changedResults[0],
                roundNumber,
                counters: {
                    P: currentCounts.P || 0,
                    B: currentCounts.B || 0,
                    T: currentCounts.T || 0
                },
                totals: {
                    totalRounds,
                    playerWinRate: currentCounts.P ? Math.round((currentCounts.P / totalRounds) * 100) : 0
                },
                timestamp: new Date().toISOString()
            };

            log(`${gameState.triggeredBy} → Round #${roundNumber} | P:${gameState.counters.P} B:${gameState.counters.B} T:${gameState.counters.T}`);

            window.dispatchEvent(new CustomEvent('ResultDetected', { detail: gameState }));
        }
    }

    function setupObserver() {
        const observer = new MutationObserver((mutations) => {
            const shouldCheck = mutations.some(mutation => {
                if (mutation.type === 'characterData') return true;
                
                if (mutation.addedNodes.length) {
                    for (const node of mutation.addedNodes) {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            const text = node.textContent;
                            if (text && (text.includes('Balance') || node.tagName === 'SPAN' || node.querySelector?.('span'))) {
                                return true;
                            }
                        }
                    }
                }
                return false;
            });

            if (shouldCheck) {
                setTimeout(() => {
                    detectBalance();
                    detectResults();
                }, 100);
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true,
            characterData: true,
            characterDataOldValue: true
        });

        log('Observer setup complete');
    }

    function waitForElementsAndStart() {
        const interval = setInterval(() => {
            const labelElements = document.querySelectorAll(`.${CONFIG.LABEL_CLASS}`);
            const valueElements = document.querySelectorAll(`.${CONFIG.VALUE_CLASS}`);

            if (labelElements.length >= 3 && valueElements.length >= 3) {
                log('Game elements detected, starting monitors');
                clearInterval(interval);
                setInterval(() => {
                    detectBalance();
                    detectResults();
                }, CONFIG.CHECK_INTERVAL);
            }
        }, 1000);
    }

    function initialize() {
        log('Baccarat Monitor v6.0 initialized');
        
        setTimeout(() => {
            detectBalance();
            setupObserver();
        }, 1000);
        
        setTimeout(waitForElementsAndStart, 2000);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
})();
