// ==UserScript==
// @name         Model Toggle
// @namespace    http://tampermonkey.net/
// @version      1.0.0
// @description  Toggle between GPT-5.2 Auto/Instant/Thinking models - Ctrl+X to switch
// @author       Assistant
// @match        https://chatgpt.com/*
// @match        https://chat.openai.com/*
// @grant        GM_setValue
// @grant        GM_getValue
// @run-at       document-idle
// @icon         https://www.google.com/s2/favicons?sz=64&domain=chatgpt.com
// ==/UserScript==

(function() {
    'use strict';

    const CONFIG = {
        models: [
            { id: 'gpt-5-2', testId: 'model-switcher-gpt-5-2', name: 'Auto' },
            // { id: 'gpt-5-2-instant', testId: 'model-switcher-gpt-5-2-instant', name: 'Instant' },
            { id: 'gpt-5-2-thinking', testId: 'model-switcher-gpt-5-2-thinking', name: 'Thinking' }
        ],
        toggleKey: 'x',
        storageKey: 'chatgpt_gpt52_model_index'
    };

    let currentIndex = GM_getValue(CONFIG.storageKey, 0);
    let isToggling = false;

    // Debug helper (set to true to enable)
    const DEBUG_ENABLED = false;
    function debug(...args) {
        if (DEBUG_ENABLED) console.log('%c[GPT52-DEBUG]', 'color: #10a37f; font-weight: bold;', ...args);
    }

    function saveState() {
        GM_setValue(CONFIG.storageKey, currentIndex);
        debug('State saved, currentIndex:', currentIndex);
    }

    // Simulate real click - full sequence like stop_read.js
    function simulateRealClick(element) {
        if (!element) {
            debug('simulateRealClick: element is null/undefined');
            return false;
        }

        debug('simulateRealClick on:', element.tagName, element.getAttribute('data-testid') || element.className);

        const rect = element.getBoundingClientRect();
        const cx = rect.left + rect.width / 2;
        const cy = rect.top + rect.height / 2;

        debug('Click coords:', cx, cy);

        // Scroll into view first
        element.scrollIntoView({ block: 'nearest', inline: 'center' });
        try { element.focus({ preventScroll: true }); } catch {}

        const baseMouse = { bubbles: true, cancelable: true, clientX: cx, clientY: cy, button: 0, buttons: 1 };
        const basePtr = { ...baseMouse, pointerId: 1, pointerType: 'mouse', isPrimary: true };

        // Full hover + click sequence
        element.dispatchEvent(new PointerEvent('pointerover', basePtr));
        element.dispatchEvent(new MouseEvent('mouseover', baseMouse));
        element.dispatchEvent(new PointerEvent('pointerenter', basePtr));
        element.dispatchEvent(new MouseEvent('mouseenter', baseMouse));
        element.dispatchEvent(new PointerEvent('pointerdown', basePtr));
        element.dispatchEvent(new MouseEvent('mousedown', baseMouse));
        element.dispatchEvent(new PointerEvent('pointerup', basePtr));
        element.dispatchEvent(new MouseEvent('mouseup', baseMouse));
        element.dispatchEvent(new MouseEvent('click', baseMouse));

        debug('simulateRealClick completed');
        return true;
    }

    // Try calling React's internal handlers directly
    function tryReactHandler(el) {
        const key = Object.keys(el).find(k => k.startsWith('__reactProps$'));
        if (!key) {
            debug('No React props found on element');
            return false;
        }
        const props = el[key] || {};
        const ev = { isTrusted: true, target: el, currentTarget: el, preventDefault() {}, stopPropagation() {}, nativeEvent: { isTrusted: true } };
        for (const n of ['onPointerDown', 'onClick', 'onMouseDown', 'onMouseUp']) {
            if (typeof props[n] === 'function') {
                try {
                    debug('Calling React handler:', n);
                    props[n](ev);
                    return true;
                } catch (e) {
                    debug('React handler error:', e);
                }
            }
        }
        return false;
    }

    async function toggleModel() {
        debug('toggleModel called, isToggling:', isToggling);
        if (isToggling) {
            debug('Already toggling, skipping');
            return;
        }
        isToggling = true;

        try {
            // Step 1: Click the model switcher dropdown button
            debug('Step 1: Looking for dropdown button...');
            const dropdownBtn = document.querySelector('[data-testid="model-switcher-dropdown-button"]');
            debug('Dropdown button found:', !!dropdownBtn, dropdownBtn);

            if (!dropdownBtn) {
                debug('ERROR: Model switcher button not found!');
                // Try to find similar elements
                const allTestIds = document.querySelectorAll('[data-testid]');
                debug('All data-testid elements:', Array.from(allTestIds).map(el => el.getAttribute('data-testid')));
                isToggling = false;
                return;
            }

            debug('Clicking dropdown button...');
            simulateRealClick(dropdownBtn);

            // Also try React handler
            debug('Trying React handler on dropdown...');
            tryReactHandler(dropdownBtn);

            // Step 2: Wait for dropdown to open with retry
            debug('Step 2: Waiting for dropdown to open...');
            let dropdownMenu = null;
            for (let i = 0; i < 10; i++) {
                await new Promise(resolve => setTimeout(resolve, 100));
                dropdownMenu = document.querySelector('[role="menu"]');
                debug(`Attempt ${i + 1}: Dropdown menu found:`, !!dropdownMenu);
                if (dropdownMenu) break;

                // Retry click if menu didn't open
                if (i === 2 || i === 5) {
                    debug('Retrying click + React handler...');
                    simulateRealClick(dropdownBtn);
                    tryReactHandler(dropdownBtn);
                }
            }

            if (!dropdownMenu) {
                debug('ERROR: Dropdown never opened after all attempts');
                isToggling = false;
                return;
            }

            // Step 3: Cycle to next model
            currentIndex = (currentIndex + 1) % CONFIG.models.length;
            const targetModel = CONFIG.models[currentIndex];
            debug('Step 3: Cycling to model index:', currentIndex, 'target:', targetModel);

            // Step 4: Find and click the target model option
            debug('Step 4: Looking for model option with testId:', targetModel.testId);
            const modelOption = document.querySelector(`[data-testid="${targetModel.testId}"]`);
            debug('Model option found:', !!modelOption, modelOption);

            if (modelOption) {
                debug('Clicking model option...');
                simulateRealClick(modelOption);
                tryReactHandler(modelOption);
                saveState();
                debug('SUCCESS: Switched to', targetModel.name);

                // Focus back on text input after a short delay
                setTimeout(() => {
                    const textInput = document.querySelector('#prompt-textarea') ||
                                     document.querySelector('[contenteditable="true"]') ||
                                     document.querySelector('textarea');
                    if (textInput) {
                        textInput.focus();
                        debug('Focused back on text input');
                    }
                }, 100);
            } else {
                // List all menu items for debugging
                const allMenuItems = document.querySelectorAll('[role="menuitem"]');
                debug('All menu items:', Array.from(allMenuItems).map(el => ({
                    testId: el.getAttribute('data-testid'),
                    text: el.textContent.substring(0, 50)
                })));

                // If model not found, close dropdown by clicking elsewhere
                simulateRealClick(dropdownBtn);
                debug('ERROR: Model option not found');
            }

        } catch (error) {
            console.error('Toggle error:', error);
            debug('EXCEPTION:', error);
        }

        setTimeout(() => {
            isToggling = false;
            debug('isToggling reset to false');
        }, 300);
    }

    // Set up keyboard shortcut
    document.addEventListener('keydown', (event) => {
        // Log all Ctrl+key presses for debugging
        if (event.ctrlKey) {
            debug('Ctrl+key pressed:', event.key, 'code:', event.code);
        }

        if (event.key === CONFIG.toggleKey && event.ctrlKey && !event.altKey && !event.shiftKey) {
            debug('Ctrl+X detected! Triggering toggle...');
            event.preventDefault();
            event.stopPropagation();
            toggleModel();
        }
    }, true);

    debug('Script initialized');
    debug('Current saved index:', currentIndex);
    debug('Models config:', CONFIG.models);
    console.log('[GPT-5.2 Toggle] Loaded - Press Ctrl+X to cycle models');

})();
