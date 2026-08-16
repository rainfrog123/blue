// ==UserScript==
// @name         Baccarat Balance Detector
// @namespace    http://tampermonkey.net/
// @version      1.5
// @description  Detects balance using robust DOM traversal and stores it in localStorage (no UI indicator)
// @author       You
// @match        *://client.pragmaticplaylive.net/desktop/baccarat/*
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_log
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    // ==========================================
    // CONFIGURATION SETTINGS
    // ==========================================
    const CONFIG = {
        // Balance detection settings
        STORAGE_KEY: 'currentBalance',    // Key used in localStorage

        // No longer using specific CSS selectors - using robust DOM traversal instead

        // Balance validation settings
        VALIDATION: {
            MIN_VALID_BALANCE: 0.1,       // Minimum valid balance
            MAX_VALID_BALANCE: 100000,    // Maximum valid balance
        },

        // Debug settings
        DEBUG: true,
        VERBOSE: false,  // Set to true for more detailed logging
    };

    // ==========================================
    // STATE TRACKING
    // ==========================================
    const STATE = {
        lastConfirmedBalance: null,   // Last confirmed valid balance
        lastUpdateTime: 0,            // Last time balance was updated
    };

    // ==========================================
    // UTILITY FUNCTIONS
    // ==========================================

    /**
     * Logger utility with different log levels
     */
    const Logger = {
        info: (message) => {
            if (CONFIG.DEBUG) console.log(`[Balance] ${message}`);
        },
        verbose: (message) => {
            if (CONFIG.DEBUG && CONFIG.VERBOSE) console.log(`[Balance] ${message}`);
        },
        warn: (message) => console.warn(`[Balance] ${message}`),
        error: (message) => console.error(`[Balance] ${message}`)
    };

    /**
     * Extract numeric value from text
     * @param {string} text - Text to extract from
     * @returns {number|null} - Extracted number or null
     */
    function extractNumericValue(text) {
        if (!text) return null;

        // Remove all non-numeric characters except decimal point
        const numericString = text.replace(/[^0-9.]/g, '');
        const value = parseFloat(numericString);

        return !isNaN(value) ? value : null;
    }

    // ==========================================
    // BALANCE DETECTION FUNCTIONS
    // ==========================================

    /**
     * Try to detect balance using robust DOM traversal
     */
    function detectBalance() {
        try {
            // Find the div with "Balance" text using robust method
            const balanceLabel = [...document.querySelectorAll('div')]
                .find(el => el.textContent.trim() === 'Balance');

            if (!balanceLabel) {
                Logger.verbose('Balance label not found');
                return;
            }

            // Get the parent container
            const balanceContainer = balanceLabel.parentElement;
            if (!balanceContainer) {
                Logger.verbose('Balance container not found');
                return;
            }

            // Find the balance value element (sibling div with span)
            const balanceValueDiv = balanceContainer.querySelector('div:not(:first-child) span');
            if (!balanceValueDiv) {
                Logger.verbose('Balance value element not found');
                return;
            }

            const balanceText = balanceValueDiv.textContent;
            const balance = extractNumericValue(balanceText);

            if (balance !== null && balance >= CONFIG.VALIDATION.MIN_VALID_BALANCE) {
                Logger.verbose(`Balance detected: ${balance.toFixed(2)} from text: "${balanceText}"`);

                // Get previous balance for comparison
                const previousBalance = localStorage.getItem(CONFIG.STORAGE_KEY);
                const previousBalanceNum = previousBalance ? parseFloat(previousBalance) : null;

                // Update storage if balance changed
                if (previousBalanceNum !== balance) {
                    Logger.info(`Balance updated: ${balance.toFixed(2)}`);

                    // Store in localStorage
                    localStorage.setItem(CONFIG.STORAGE_KEY, balance.toString());

                    // Also store timestamp of last update
                    localStorage.setItem(`${CONFIG.STORAGE_KEY}_timestamp`, Date.now().toString());

                    // Update last confirmed balance
                    STATE.lastConfirmedBalance = balance;
                    STATE.lastUpdateTime = Date.now();
                }
            } else {
                Logger.verbose(`Invalid balance detected: ${balance} from text: "${balanceText}"`);
            }
        } catch (error) {
            Logger.error(`Error detecting balance: ${error.message}`);
        }
    }

    // ==========================================
    // BALANCE CHANGE OBSERVER
    // ==========================================

    /**
     * Set up a MutationObserver to detect DOM changes
     */
    function setupBalanceObserver() {
        // Create a MutationObserver to watch for changes
        const observer = new MutationObserver((mutations) => {
            // Check if any mutations might affect balance display
            const shouldCheckBalance = mutations.some(mutation => {
                // Check for text changes in any element
                if (mutation.type === 'characterData') {
                    return true;
                }

                // Check for new elements that might contain balance
                if (mutation.addedNodes.length) {
                    for (const node of mutation.addedNodes) {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            // Check if added node or its children contain "Balance" text
                            if (node.textContent && node.textContent.includes('Balance')) {
                                return true;
                            }
                            // Check if added node contains span elements (balance values)
                            if (node.tagName === 'SPAN' || node.querySelector && node.querySelector('span')) {
                                return true;
                            }
                        }
                    }
                }

                return false;
            });

            // If relevant changes detected, check balance after a short delay
            if (shouldCheckBalance) {
                setTimeout(detectBalance, 100);
            }
        });

        // Start observing the document with the configured parameters
        observer.observe(document.body, {
            childList: true,
            subtree: true,
            characterData: true,
            characterDataOldValue: true
        });

        Logger.info('Balance observer set up with robust detection');

        // Also run periodic checks as a fallback
        setInterval(detectBalance, 2000);
    }

    // ==========================================
    // INITIALIZATION
    // ==========================================

    /**
     * Initialize the balance detector
     */
    function initialize() {
        Logger.info('Balance Detector v1.5 initialized');
        Logger.info('Using robust DOM traversal to find "Balance" label');

        // Run initial detection
        setTimeout(detectBalance, 1000);

        // Set up observer for real-time detection
        setTimeout(setupBalanceObserver, 2000);

        // Status indicator disabled - no UI elements shown
    }

    /**
     * Create a small status indicator - DISABLED
     */
    function createStatusIndicator() {
        // Status indicator disabled - function kept for compatibility
    }

    // Start the script when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
})();
