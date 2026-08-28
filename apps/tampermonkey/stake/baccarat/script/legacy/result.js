// ==UserScript==
// @name         Baccarat Result Detector
// @namespace    http://tampermonkey.net/
// @version      5.0
// @description  Detects Baccarat results and dispatches comprehensive game state (counters, round number, win rates) via ResultDetected event
// @author       You
// @match        *://client.pragmaticplaylive.net/desktop/baccarat/*
// @grant        none
// @run-at       document-end
// ==/UserScript==

(function () {
    'use strict';

    const CONFIG = {
        VALID_RESULTS: ['B', 'P', 'T'],
        TARGET_SELECTOR: '.km_ko', // Updated container selector
        LABEL_CLASS: 'km_kp',      // Updated label class (contains P/B/T text)
        VALUE_CLASS: 'km_ky',      // Updated value class (contains numbers)
        CHECK_INTERVAL: 500, // milliseconds
    };

    let previousCounts = {
        B: null,
        P: null,
        T: null,
    };

    function getCurrentCounts() {
        const counts = {};

        // Find all label elements (P, B, T text)
        const labelElements = document.querySelectorAll(`.${CONFIG.LABEL_CLASS}`);
        const valueElements = document.querySelectorAll(`.${CONFIG.VALUE_CLASS}`);

        // Debug logging (only first time)
        if (!getCurrentCounts.debugLogged) {
            console.log(`[Detector] Found ${labelElements.length} label elements, ${valueElements.length} value elements`);
            getCurrentCounts.debugLogged = true;
        }

        // Match labels with values (they should be in same order)
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
        // Try to find round number in various selectors
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

    function detectChangesAndDispatch() {
        const currentCounts = getCurrentCounts();
        if (!currentCounts) return;

        let changedResults = [];

        // Check which results changed
        CONFIG.VALID_RESULTS.forEach(result => {
            const prev = previousCounts[result];
            const curr = currentCounts[result];

            if (prev !== null && curr !== undefined && curr > prev) {
                changedResults.push(result);
            }

            previousCounts[result] = curr;
        });

        // If any results changed, dispatch comprehensive game state
        if (changedResults.length > 0) {
            const roundNumber = getRoundNumber();
            const gameState = {
                changedResults: changedResults,
                triggeredBy: changedResults[0], // First changed result (usually only one)
                roundNumber: roundNumber,
                counters: {
                    P: currentCounts.P || 0,
                    B: currentCounts.B || 0,
                    T: currentCounts.T || 0
                },
                totals: {
                    totalRounds: (currentCounts.P || 0) + (currentCounts.B || 0) + (currentCounts.T || 0),
                    playerWinRate: currentCounts.P ? Math.round((currentCounts.P / ((currentCounts.P || 0) + (currentCounts.B || 0) + (currentCounts.T || 0))) * 100) : 0
                },
                timestamp: new Date().toISOString()
            };

            console.log(`[Detector] ${gameState.triggeredBy} → Round #${roundNumber} | P:${gameState.counters.P} B:${gameState.counters.B} T:${gameState.counters.T}`);

            const event = new CustomEvent('ResultDetected', {
                detail: gameState
            });
            window.dispatchEvent(event);
        }
    }

    function waitForStatsPanelAndStart() {
        const interval = setInterval(() => {
            // Check if we can find the stats elements
            const labelElements = document.querySelectorAll(`.${CONFIG.LABEL_CLASS}`);
            const valueElements = document.querySelectorAll(`.${CONFIG.VALUE_CLASS}`);

            if (labelElements.length >= 3 && valueElements.length >= 3) {
                console.log("[Detector] Stats panel detected, starting monitor...");
                clearInterval(interval);
                setInterval(detectChangesAndDispatch, CONFIG.CHECK_INTERVAL);
            }
        }, 1000);
    }

    console.log("[Detector] Initializing Baccarat stats monitor...");
    waitForStatsPanelAndStart();
})();
