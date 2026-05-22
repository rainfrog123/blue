// ==UserScript==
// @name         Toggle Pro / Flash Extended
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Ctrl+Shift+Y toggles between 3.5 Flash + Extended and Pro on Gemini
// @author       You
// @match        https://gemini.google.com/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(function() {
    'use strict';

    const LOG_PREFIX = '[Pro/Flash Toggle]';

    const FLASH = {
        label: '3.5 Flash',
        pillPrimary: 'Flash',
        testId: 'bard-mode-option-56fdd199312815e2',
        modeId: '56fdd199312815e2',
    };

    const PRO = {
        labels: ['3.1 Pro', 'Pro'],
        pillSecondary: 'Pro',
        testId: 'bard-mode-option-e6fa609c3fa255c0',
        modeId: 'e6fa609c3fa255c0',
    };

    const THINKING = 'Extended';

    let isProcessing = false;

    function sleep(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }

    async function waitUntil(test, timeoutMs = 2000, stepMs = 16) {
        const start = Date.now();
        while (Date.now() - start < timeoutMs) {
            if (test()) return true;
            await sleep(stepMs);
        }
        return test();
    }

    function isVisible(el) {
        if (!el) return false;
        const rect = el.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
    }

    function findModeButton() {
        const desktop = document.querySelector('button.input-area-switch:not([disabled])');
        if (desktop && isVisible(desktop)) return desktop;

        const mobileHost = document.querySelector('[data-test-id="bard-mode-menu-button"]');
        if (mobileHost) {
            const mobileBtn = mobileHost.matches('button')
                ? mobileHost
                : mobileHost.querySelector('button:not([disabled])');
            if (mobileBtn && isVisible(mobileBtn)) return mobileBtn;
        }

        return null;
    }

    function getVisiblePillLabel() {
        const containers = [...document.querySelectorAll('[data-test-id="logo-pill-label-container"]')]
            .filter(isVisible);

        const inModeButton = (container) => container.closest(
            'button.input-area-switch, [data-test-id="bard-mode-menu-button"], [data-test-id="bard-mode-switcher"]'
        );

        const preferred = containers.find((c) =>
            c.classList.contains('thinking-level-enabled') && inModeButton(c)
        ) || containers.find((c) => inModeButton(c))
          || containers.find((c) => c.classList.contains('thinking-level-enabled'))
          || containers[0];

        if (!preferred) return null;

        return {
            primary: preferred.querySelector('.picker-primary-text')?.textContent.trim() || '',
            secondary: preferred.querySelector('.picker-secondary-text')?.textContent.trim() || '',
        };
    }

    function isFlashExtended() {
        const pill = getVisiblePillLabel();
        if (!pill) return false;
        return pill.primary === FLASH.pillPrimary && pill.secondary === THINKING;
    }

    function isProMode() {
        const pill = getVisiblePillLabel();
        if (!pill) return false;
        if (pill.secondary === PRO.pillSecondary) return true;
        return PRO.labels.some((label) => pill.primary === label || pill.secondary === label);
    }

    function getCurrentState() {
        if (isProMode()) return 'pro';
        if (isFlashExtended()) return 'flash-extended';
        return 'other';
    }

    function isMenuOpen() {
        const menu = document.querySelector('[data-test-id="gem-mode-menu"]');
        if (menu?.getAttribute('data-visible') === 'true') return true;

        const popover = document.querySelector(
            '[data-test-id="bard-mode-desktop-gem-menu"], [data-test-id="bard-mode-mobile-gem-menu"], [data-test-id="bard-mode-gem-menu"]'
        );
        if (popover && isVisible(popover)) return true;

        return !!document.querySelector('mat-option, .mat-mdc-option, gem-menu-item[role="menuitem"]');
    }

    function closeMenu() {
        document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    }

    async function closeMenuAndWait() {
        if (!isMenuOpen()) return;
        closeMenu();
        await waitUntil(() => !isMenuOpen(), 500, 16);
    }

    async function ensureMenuOpen(button) {
        if (isMenuOpen()) return true;
        button.click();
        return waitUntil(isMenuOpen, 2000, 16);
    }

    function getMenuItemLabel(item) {
        const label = item?.querySelector('.label-container .label, .label, .title-text');
        return label?.textContent.replace(/\s+/g, ' ').trim()
            || item?.textContent.replace(/\s+/g, ' ').trim()
            || '';
    }

    function isMenuItemSelected(item) {
        return item?.getAttribute('data-active') === 'true' || item?.classList.contains('selected');
    }

    function findMenuItem(labels, testId) {
        if (testId) {
            const byId = document.querySelector(`[data-test-id="${testId}"]`);
            if (byId && isVisible(byId)) return byId;
        }

        const wanted = Array.isArray(labels) ? labels : [labels];
        for (const item of document.querySelectorAll('gem-menu-item[role="menuitem"], mat-option, .mat-mdc-option, [role="option"]')) {
            if (!isVisible(item)) continue;
            if (item.getAttribute('value') === 'thinking_level') continue;

            const text = getMenuItemLabel(item) || item.textContent.replace(/\s+/g, ' ').trim();
            if (wanted.some((label) => text === label || text.includes(label))) {
                return item;
            }
        }

        return null;
    }

    function getThinkingLevelItem() {
        return document.querySelector('gem-menu-item[value="thinking_level"]');
    }

    function getCurrentThinkingLevel() {
        const pill = getVisiblePillLabel();
        if (pill?.secondary && pill.secondary !== PRO.pillSecondary && pill.primary === FLASH.pillPrimary) {
            return pill.secondary;
        }
        return getThinkingLevelItem()?.querySelector('.sublabel')?.textContent.trim() || '';
    }

    async function selectModel(button, model) {
        if (!await ensureMenuOpen(button)) return false;

        const item = findMenuItem(model.labels || model.label, model.testId);
        if (!item) return false;
        if (isMenuItemSelected(item)) return true;

        item.click();
        return waitUntil(() => isMenuItemSelected(item), 1500, 16);
    }

    async function selectThinking(button, level) {
        let thinkingItem = getThinkingLevelItem();
        if (!thinkingItem) {
            if (!await ensureMenuOpen(button)) return false;
            thinkingItem = getThinkingLevelItem();
        }
        if (!thinkingItem) return true;

        if (getCurrentThinkingLevel() === level) return true;

        if (thinkingItem.getAttribute('aria-expanded') !== 'true') {
            thinkingItem.click();
            await waitUntil(
                () => thinkingItem.getAttribute('aria-expanded') === 'true' || !!findMenuItem(level),
                1500,
                16
            );
        }

        const levelItem = findMenuItem(level);
        if (!levelItem) return false;
        if (isMenuItemSelected(levelItem)) return true;

        levelItem.click();
        return waitUntil(() => getCurrentThinkingLevel() === level, 1500, 16);
    }

    async function applyFlashExtended(button) {
        await selectModel(button, { label: FLASH.label, testId: FLASH.testId });
        if (!isMenuOpen()) await ensureMenuOpen(button);
        await selectThinking(button, THINKING);
        await closeMenuAndWait();
    }

    async function applyPro(button) {
        await selectModel(button, { labels: PRO.labels, testId: PRO.testId });
        await closeMenuAndWait();
    }

    function focusInputArea() {
        const inputArea = document.querySelector('[aria-label="Enter a prompt for Gemini"]') ||
            document.querySelector('input-area-v2 .ql-editor');
        inputArea?.focus?.();
    }

    async function toggleMode() {
        if (isProcessing) return;

        const button = findModeButton();
        if (!button) {
            console.warn(`${LOG_PREFIX} Mode button not found`);
            return;
        }

        isProcessing = true;

        try {
            const state = getCurrentState();
            const target = state === 'pro' ? 'flash-extended' : 'pro';

            console.log(`${LOG_PREFIX} ${state} -> ${target}`);

            if (target === 'flash-extended') {
                await applyFlashExtended(button);
            } else {
                await applyPro(button);
            }

            focusInputArea();
        } catch (e) {
            console.error(`${LOG_PREFIX} Error:`, e);
        } finally {
            await closeMenuAndWait();
            isProcessing = false;
        }
    }

    function setupKeyboardShortcut() {
        document.addEventListener('keydown', (event) => {
            if (!event.ctrlKey || !event.shiftKey || event.key.toLowerCase() !== 'y') return;

            event.preventDefault();
            event.stopPropagation();
            toggleMode();
        }, true);
    }

    function init() {
        console.log(`${LOG_PREFIX} Loaded — Ctrl+Shift+Y toggles Pro ↔ Flash + Extended`);
        setupKeyboardShortcut();
    }

    if (document.readyState === 'complete') {
        init();
    } else {
        window.addEventListener('load', init, { once: true });
    }
})();
