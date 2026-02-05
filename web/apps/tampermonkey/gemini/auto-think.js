// ==UserScript==
// @name         Auto Thinking
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Automatically switch Gemini from Fast to Thinking mode
// @author       You
// @match        https://gemini.google.com/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(function() {
    'use strict';

    const TARGET_MODE = 'Thinking';
    const CHECK_INTERVAL = 1000;
    let isProcessing = false;

    function findModeButton() {
        // Find the input-area-switch button
        return document.querySelector('button.input-area-switch');
    }

    function getCurrentMode(button) {
        if (!button) return null;
        const labelSpan = button.querySelector('.logo-pill-label-container span');
        return labelSpan ? labelSpan.textContent.trim() : null;
    }

    async function selectThinkingMode() {
        if (isProcessing) return;

        const button = findModeButton();
        if (!button) return;

        const currentMode = getCurrentMode(button);
        if (!currentMode || currentMode === TARGET_MODE) return;

        console.log(`[Gemini Auto Thinking] Current mode: ${currentMode}, switching to ${TARGET_MODE}`);
        isProcessing = true;

        try {
            // Click the button to open dropdown
            button.click();

            // Wait for dropdown to appear
            await new Promise(resolve => setTimeout(resolve, 300));

            // Find and click the Thinking option
            const options = document.querySelectorAll('mat-option, [role="option"], .mat-mdc-option');
            for (const option of options) {
                const text = option.textContent.trim();
                if (text.includes(TARGET_MODE)) {
                    console.log(`[Gemini Auto Thinking] Found ${TARGET_MODE} option, clicking...`);
                    option.click();
                    break;
                }
            }

            // Alternative: look for menu items if mat-option doesn't work
            if (getCurrentMode(button) !== TARGET_MODE) {
                const menuItems = document.querySelectorAll('[mat-menu-item], .mat-menu-item, [role="menuitem"], .mdc-list-item');
                for (const item of menuItems) {
                    const text = item.textContent.trim();
                    if (text.includes(TARGET_MODE)) {
                        console.log(`[Gemini Auto Thinking] Found ${TARGET_MODE} menu item, clicking...`);
                        item.click();
                        break;
                    }
                }
            }
        } catch (e) {
            console.error('[Gemini Auto Thinking] Error:', e);
        } finally {
            setTimeout(() => { isProcessing = false; }, 500);
        }
    }

    // Observer for dynamic content changes
    function setupObserver() {
        const observer = new MutationObserver((mutations) => {
            const button = findModeButton();
            if (button && getCurrentMode(button) !== TARGET_MODE) {
                selectThinkingMode();
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true,
            characterData: true
        });
    }

    // Initial check and periodic re-check
    function init() {
        console.log('[Gemini Auto Thinking] Script loaded');

        // Setup mutation observer
        setupObserver();

        // Periodic check as fallback
        setInterval(() => {
            const button = findModeButton();
            if (button && getCurrentMode(button) !== TARGET_MODE) {
                selectThinkingMode();
            }
        }, CHECK_INTERVAL);

        // Initial check after page settles
        setTimeout(selectThinkingMode, 2000);
    }

    // Wait for page to be ready
    if (document.readyState === 'complete') {
        init();
    } else {
        window.addEventListener('load', init);
    }
})();
