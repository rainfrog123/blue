// ==UserScript==
// @name         Auto Pro
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Automatically switch Gemini to Pro mode
// @author       You
// @match        https://gemini.google.com/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(function() {
    'use strict';

    const TARGET_MODE = 'Pro';
    const CHECK_INTERVAL = 1000;
    let isProcessing = false;

    function findModeButton() {
        return document.querySelector('button.input-area-switch');
    }

    function getCurrentMode(button) {
        if (!button) return null;
        const labelSpan = button.querySelector('.logo-pill-label-container span');
        return labelSpan ? labelSpan.textContent.trim() : null;
    }

    function focusInputArea() {
        const inputArea = document.querySelector('[aria-label="Enter a prompt for Gemini"]') ||
            document.querySelector('input-area-v2 .ql-editor');
        if (inputArea && typeof inputArea.focus === 'function') {
            inputArea.focus();
        }
    }

    async function selectProMode() {
        if (isProcessing) return;

        const button = findModeButton();
        if (!button) return;

        const currentMode = getCurrentMode(button);
        if (!currentMode || currentMode === TARGET_MODE) return;

        console.log(`[Gemini Auto Pro] Current mode: ${currentMode}, switching to ${TARGET_MODE}`);
        isProcessing = true;

        try {
            button.click();

            const options = document.querySelectorAll('mat-option, [role="option"], .mat-mdc-option');
            for (const option of options) {
                const text = option.textContent.trim();
                if (text.includes(TARGET_MODE) && !text.includes('Thinking')) {
                    console.log(`[Gemini Auto Pro] Found ${TARGET_MODE} option, clicking...`);
                    option.click();
                    setTimeout(focusInputArea, 350);
                    break;
                }
            }

            if (getCurrentMode(button) !== TARGET_MODE) {
                const menuItems = document.querySelectorAll('[mat-menu-item], .mat-menu-item, [role="menuitem"], .mdc-list-item');
                for (const item of menuItems) {
                    const text = item.textContent.trim();
                    if (text.includes(TARGET_MODE) && !text.includes('Thinking')) {
                        console.log(`[Gemini Auto Pro] Found ${TARGET_MODE} menu item, clicking...`);
                        item.click();
                        setTimeout(focusInputArea, 350);
                        break;
                    }
                }
            }
        } catch (e) {
            console.error('[Gemini Auto Pro] Error:', e);
        } finally {
            setTimeout(() => {
                isProcessing = false;
                focusInputArea();
            }, 500);
        }
    }

    function setupObserver() {
        const observer = new MutationObserver((mutations) => {
            const button = findModeButton();
            if (button && getCurrentMode(button) !== TARGET_MODE) {
                selectProMode();
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true,
            characterData: true
        });
    }

    function init() {
        console.log('[Gemini Auto Pro] Script loaded');

        setupObserver();

        setInterval(() => {
            const button = findModeButton();
            if (button && getCurrentMode(button) !== TARGET_MODE) {
                selectProMode();
            }
        }, CHECK_INTERVAL);

        setTimeout(selectProMode, 2000);
    }

    if (document.readyState === 'complete') {
        init();
    } else {
        window.addEventListener('load', init);
    }
})();
