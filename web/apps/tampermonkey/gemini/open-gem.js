// ==UserScript==
// @name         Open Gem Shortcut
// @namespace    http://tampermonkey.net/
// @version      2.8
// @description  Add "Open a gem" sidenav link, Ctrl+Shift+U shortcut, configurable model + thinking level on gem page
// @author       You
// @match        https://gemini.google.com/*
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_registerMenuCommand
// @run-at       document-idle
// ==/UserScript==

(function() {
    'use strict';

    const GEM_PATH = '/u/1/gem/aacb7f1889af';
    const GEM_ID = 'aacb7f1889af';
    const BUTTON_TEST_ID = 'open-gem-button';
    const CHECK_INTERVAL = 1000;
    const LOG_PREFIX = '[Open Gem Shortcut]';

    const TARGET_MODEL_KEY = 'targetModel';
    const TARGET_THINKING_KEY = 'targetThinking';
    const THINKING_CACHE_KEY = 'availableThinkingCache';
    const DEFAULT_THINKING = 'Extended';

    const DEFAULT_THINKING_LEVELS = ['Extended', 'Standard'];

    const DEFAULT_MODEL = {
        label: '3.5 Flash',
        pillPrimary: 'Flash',
        testId: 'bard-mode-option-56fdd199312815e2',
        jslogId: '56fdd199312815e2',
    };

    const MODELS_CACHE_KEY = 'availableModelsCache';

    const GEM_PAGE_MODELS = [
        {
            label: '3.1 Flash-Lite',
            pillPrimary: 'Flash-Lite',
            testId: 'bard-mode-option-8c46e95b1a07cecc',
            jslogId: '8c46e95b1a07cecc',
        },
        { ...DEFAULT_MODEL },
        {
            label: '3.1 Pro',
            pillPrimary: 'Pro',
            testId: 'bard-mode-option-e6fa609c3fa255c0',
            jslogId: 'e6fa609c3fa255c0',
        },
    ];

    function guessPillPrimary(label) {
        if (/flash-lite/i.test(label)) return 'Flash-Lite';
        if (/flash/i.test(label)) return 'Flash';
        if (/pro/i.test(label)) return 'Pro';
        const parts = label.trim().split(/\s+/);
        return parts[parts.length - 1] || label;
    }

    function normalizeModelConfig(config) {
        return {
            label: config.label,
            pillPrimary: config.pillPrimary || guessPillPrimary(config.label),
            testId: config.testId || null,
            jslogId: config.jslogId || null,
        };
    }

    function loadModelSettings() {
        const stored = GM_getValue(TARGET_MODEL_KEY, null);
        if (stored?.label) return normalizeModelConfig(stored);

        const legacyId = GM_getValue('targetModelId', null);
        if (legacyId === 'custom') {
            return normalizeModelConfig({ label: GM_getValue('customModelLabel', DEFAULT_MODEL.label) });
        }
        if (legacyId === 'flash-35' || legacyId === 'pro') {
            return legacyId === 'pro'
                ? normalizeModelConfig(GEM_PAGE_MODELS[2])
                : { ...DEFAULT_MODEL };
        }

        return { ...DEFAULT_MODEL };
    }

    let modelSettings = loadModelSettings();

    function getTargetThinking() {
        return GM_getValue(TARGET_THINKING_KEY, DEFAULT_THINKING);
    }

    function setTargetThinking(level) {
        GM_setValue(TARGET_THINKING_KEY, level.trim());
        resetGemSettingsState();
        console.log(`${LOG_PREFIX} Thinking level set to ${getTargetThinking()}`);
        if (isTargetGemPage()) scheduleGemRetries();
    }

    function getTargetModel() {
        return modelSettings.label;
    }

    function getPillPrimary() {
        return modelSettings.pillPrimary || guessPillPrimary(getTargetModel());
    }

    function getTargetModelTestId() {
        return modelSettings.testId || null;
    }

    function setTargetModelConfig(config) {
        modelSettings = normalizeModelConfig(config);
        GM_setValue(TARGET_MODEL_KEY, modelSettings);
        resetGemSettingsState();
        console.log(`${LOG_PREFIX} Default model set to ${getTargetModel()}`);
        if (isTargetGemPage()) scheduleGemRetries();
    }

    async function showModelPicker() {
        const models = await discoverAvailableModels();
        if (!models.length) {
            alert('Could not read the model list. Open your gem page, then try again.');
            return;
        }

        const lines = models.map((model, index) => {
            const current = model.label === getTargetModel() ? ' *' : '';
            return `${index + 1}. ${model.label}${current}`;
        });

        const choice = prompt(
            `Pick a model from Gemini:\n\n${lines.join('\n')}\n\nEnter number:`,
            ''
        );
        if (choice == null || choice.trim() === '') return;

        const num = parseInt(choice.trim(), 10);
        if (num >= 1 && num <= models.length) {
            setTargetModelConfig(models[num - 1]);
        }
    }

    async function showThinkingPicker() {
        const levels = await discoverAvailableThinkingLevels();
        if (!levels.length) {
            alert('Could not read thinking levels. Open your gem page, then try again.');
            return;
        }

        const lines = levels.map((level, index) => {
            const current = level === getTargetThinking() ? ' *' : '';
            return `${index + 1}. ${level}${current}`;
        });

        const choice = prompt(
            `Pick a thinking level:\n\n${lines.join('\n')}\n\nEnter number:`,
            ''
        );
        if (choice == null || choice.trim() === '') return;

        const num = parseInt(choice.trim(), 10);
        if (num >= 1 && num <= levels.length) {
            setTargetThinking(levels[num - 1]);
        }
    }

    function setupSettingsMenu() {
        GM_registerMenuCommand(`Model: ${getTargetModel()} (${getPillPrimary()})`, () => {
            showModelPicker();
        });
        GM_registerMenuCommand(`Thinking: ${getTargetThinking()}`, () => {
            showThinkingPicker();
        });
    }

    let isConfiguringGem = false;
    let gemSettingsApplied = false;
    let lastGemPath = '';
    let injectTimer = null;

    let gemConfigureTimer = null;

    function resetGemSettingsState() {
        gemSettingsApplied = false;
    }

    function markGemSettingsApplied() {
        gemSettingsApplied = true;
        console.log(`${LOG_PREFIX} Gem settings configured (${getTargetModel()} + ${getTargetThinking()})`);
    }

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

    function setConfigureVisualsHidden(hidden) {
        if (hidden) {
            if (!document.getElementById('tm-open-gem-hide-menu')) {
                const style = document.createElement('style');
                style.id = 'tm-open-gem-hide-menu';
                style.textContent = `
                    body.tm-open-gem-configuring .cdk-overlay-pane:has([data-test-id="gem-mode-menu"]),
                    body.tm-open-gem-configuring .cdk-overlay-pane:has([data-test-id="bard-mode-desktop-gem-menu"]),
                    body.tm-open-gem-configuring .cdk-overlay-pane:has([data-test-id="bard-mode-mobile-gem-menu"]),
                    body.tm-open-gem-configuring .cdk-overlay-pane:has([data-test-id="bard-mode-gem-menu"]) {
                        opacity: 0 !important;
                        visibility: hidden !important;
                    }
                `;
                document.head.appendChild(style);
            }
            document.body.classList.add('tm-open-gem-configuring');
        } else {
            document.body.classList.remove('tm-open-gem-configuring');
        }
    }

    function isFullyConfigured() {
        if (isSettingsShownInPill()) return true;
        return isTargetModelSelected() && getCurrentThinkingLevel() === getTargetThinking();
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

        const model = preferred.querySelector('.picker-primary-text')?.textContent.trim() || '';
        const thinking = preferred.querySelector('.picker-secondary-text')?.textContent.trim() || '';
        if (!model && !thinking) return null;

        return { model, thinking };
    }

    function confirmModelViaJslog() {
        if (!modelSettings.jslogId) return true;
        const jslog = findModeButton()?.getAttribute('jslog') || '';
        if (jslog.includes(modelSettings.jslogId)) return true;

        const activeItem = document.querySelector(
            `[data-test-id="bard-mode-option-${modelSettings.jslogId}"][data-active="true"],` +
            `[data-mode-id="${modelSettings.jslogId}"][data-active="true"]`
        );
        return !!activeItem;
    }

    function isModelLabelMatch(modelText) {
        if (!modelText) return false;
        if (modelText === getTargetModel()) return true;
        if (modelText === getPillPrimary()) return true;
        return false;
    }

    function isSettingsShownInPill() {
        const pill = getVisiblePillLabel();
        if (!pill || pill.thinking !== getTargetThinking()) return false;
        if (!isModelLabelMatch(pill.model)) return false;
        return confirmModelViaJslog();
    }

    function syncGemSettingsFromPill() {
        if (!isSettingsShownInPill()) return false;
        markGemSettingsApplied();
        return true;
    }

    async function closeMenuAndWait() {
        if (!isGemMenuOpen()) return;
        closeMenu();
        await waitUntil(() => !isGemMenuOpen(), 500, 16);
    }

    function isVisible(el) {
        if (!el || el.closest('.removed')) return false;
        const rect = el.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
    }

    function hasOpenGemAfter(gemsNavItem) {
        const next = gemsNavItem?.nextElementSibling;
        return next?.getAttribute('data-test-id') === BUTTON_TEST_ID;
    }

    function getTemplateItem(gemsNavItem) {
        const scope = gemsNavItem.closest('[data-test-id="overflow-container"]')
            || gemsNavItem.closest('mat-sidenav')
            || document;
        const template = scope.querySelector('[data-test-id="new-chat-button"]');
        return template?.matches('gem-nav-list-item')
            ? template
            : template?.closest('gem-nav-list-item');
    }

    function isInjectTarget(gemsNavItem) {
        if (!gemsNavItem || gemsNavItem.closest('.removed')) return false;
        const navList = gemsNavItem.parentElement;
        if (!navList || navList.classList.contains('removed') || navList.closest('.removed')) {
            return false;
        }
        return isVisible(gemsNavItem);
    }

    function findActiveGemsNavItems() {
        const items = [];
        const seen = new Set();

        document.querySelectorAll('[data-test-id="overflow-container"]').forEach((container) => {
            if (!isVisible(container)) return;

            container.querySelectorAll('[data-test-id="gems-side-nav-entry-button"]').forEach((gemsEl) => {
                const gemsNavItem = gemsEl.matches('gem-nav-list-item')
                    ? gemsEl
                    : gemsEl.closest('gem-nav-list-item');
                if (!gemsNavItem || seen.has(gemsNavItem) || !isInjectTarget(gemsNavItem)) return;

                seen.add(gemsNavItem);
                items.push(gemsNavItem);
            });
        });

        return items;
    }

    function createOpenGemNavItem(templateItem) {
        const item = templateItem.cloneNode(true);
        item.setAttribute('data-test-id', BUTTON_TEST_ID);
        item.classList.add('tm-open-gem-item');
        item.querySelector('.hovered-trailing-content')?.remove();

        const link = item.querySelector('a[href]');
        if (!link) return null;

        link.href = GEM_PATH;
        link.setAttribute('aria-label', 'Open a gem');
        setLinkText(item, 'Open a gem');
        setLinkIcon(item, 'open_in_new');
        return item;
    }

    function isTargetGemPage() {
        return location.pathname.includes(`/gem/${GEM_ID}`);
    }

    function openGem() {
        const url = `${location.origin}${GEM_PATH}`;
        if (location.href === url) return;
        location.assign(url);
    }

    function setupKeyboardShortcut() {
        document.addEventListener('keydown', (event) => {
            if (!event.ctrlKey || !event.shiftKey || event.key.toLowerCase() !== 'u') return;

            event.preventDefault();
            event.stopPropagation();
            openGem();
        }, true);
    }

    function alreadyInjected(parent) {
        if (!parent) return false;
        const existing = parent.querySelector(`[data-test-id="${BUTTON_TEST_ID}"]`);
        return existing && isVisible(existing);
    }

    function injectExpandedNavList(gemsNavItem) {
        if (!isInjectTarget(gemsNavItem)) return false;

        const navList = gemsNavItem.parentElement;
        if (hasOpenGemAfter(gemsNavItem)) return false;

        const templateItem = getTemplateItem(gemsNavItem);
        if (!templateItem) return false;

        const item = createOpenGemNavItem(templateItem);
        if (!item) return false;

        navList.insertBefore(item, gemsNavItem.nextSibling);
        const layout = gemsNavItem.closest('.overflow-container.mobile') ? 'mobile' : 'desktop';
        console.log(`${LOG_PREFIX} Added "Open a gem" below Gems (${layout})`);
        return true;
    }

    function setLinkText(root, label) {
        const title = root.querySelector('.title-text, .title-container');
        if (title) title.textContent = label;
    }

    function setLinkIcon(root, iconName) {
        const icon = root.querySelector('mat-icon[fonticon], mat-icon[data-mat-icon-name]');
        if (!icon) return;
        icon.setAttribute('fonticon', iconName);
        icon.setAttribute('data-mat-icon-name', iconName);
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

    function isGemMenuOpen() {
        const menu = document.querySelector('[data-test-id="gem-mode-menu"]');
        if (menu?.getAttribute('data-visible') === 'true') return true;

        const popover = document.querySelector(
            '[data-test-id="bard-mode-desktop-gem-menu"], [data-test-id="bard-mode-mobile-gem-menu"], [data-test-id="bard-mode-gem-menu"]'
        );
        if (popover && isVisible(popover)) return true;

        const testId = getTargetModelTestId();
        if (testId) {
            const modelItem = document.querySelector(`[data-test-id="${testId}"]`);
            if (modelItem && isVisible(modelItem)) return true;
        }

        return !!findGemMenuItem(getTargetModel(), true);
    }

    function isTargetModelSelectedInMenu() {
        const testId = getTargetModelTestId();
        if (testId) {
            const modelItem = document.querySelector(`[data-test-id="${testId}"]`);
            if (modelItem && isVisible(modelItem) && isMenuItemSelected(modelItem)) return true;
        }

        const modeBtn = findModeButton();
        const jslog = modeBtn?.getAttribute('jslog') || '';
        if (modelSettings.jslogId && jslog.includes(modelSettings.jslogId)) return true;

        const menuItem = findGemMenuItem(getTargetModel(), true);
        return isMenuItemSelected(menuItem);
    }

    function isTargetModelSelected() {
        if (isSettingsShownInPill()) return true;

        const pill = getVisiblePillLabel();
        if (pill && isModelLabelMatch(pill.model) && confirmModelViaJslog()) return true;

        return isTargetModelSelectedInMenu();
    }

    function getCurrentThinkingFromPill() {
        return getVisiblePillLabel()?.thinking || '';
    }

    function focusInputArea() {
        const inputArea = document.querySelector('[aria-label="Enter a prompt for Gemini"]') ||
            document.querySelector('input-area-v2 .ql-editor');
        if (inputArea && typeof inputArea.focus === 'function') {
            inputArea.focus();
        }
    }

    function closeMenu() {
        document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    }

    function getMenuItemLabel(item) {
        const label = item?.querySelector('.label-container .label, .label, .title-text');
        return label?.textContent.replace(/\s+/g, ' ').trim()
            || item?.textContent.replace(/\s+/g, ' ').trim()
            || '';
    }

    function extractJslogId(item) {
        const testId = item.getAttribute('data-test-id') || '';
        const fromTestId = testId.match(/bard-mode-option-([a-f0-9]+)/);
        if (fromTestId) return fromTestId[1];

        const jslog = item.getAttribute('jslog') || '';
        const fromJslog = jslog.match(/([a-f0-9]{16,})/);
        return fromJslog?.[1] || null;
    }

    function isModelMenuItem(item) {
        if (!item || item.getAttribute('value') === 'thinking_level') return false;
        const modeId = item.getAttribute('data-mode-id');
        const testId = item.getAttribute('data-test-id') || '';
        if (!modeId && !testId.startsWith('bard-mode-option-')) return false;
        const label = getMenuItemLabel(item);
        return !!label && !/^thinking level$/i.test(label);
    }

    function extractModeId(item) {
        return item.getAttribute('data-mode-id') || extractJslogId(item);
    }

    function scrapeModelMenuItems() {
        const models = [];
        const seen = new Set();
        const selectors = [
            '[data-test-id="gem-mode-menu"] gem-menu-item[role="menuitem"]',
            '[data-test-id="bard-mode-desktop-gem-menu"] gem-menu-item[role="menuitem"]',
            '[data-test-id="bard-mode-mobile-gem-menu"] gem-menu-item[role="menuitem"]',
            '[data-test-id="bard-mode-gem-menu"] gem-menu-item[role="menuitem"]',
            'gem-menu-item[role="menuitem"][data-mode-id]',
            'gem-menu-item[role="menuitem"][data-test-id^="bard-mode-option-"]',
        ];

        for (const selector of selectors) {
            document.querySelectorAll(selector).forEach((item) => {
                if (!isModelMenuItem(item)) return;

                const rect = item.getBoundingClientRect();
                if (rect.width === 0 && rect.height === 0) return;

                const modeId = extractModeId(item);
                if (modeId && seen.has(modeId)) return;

                const label = getMenuItemLabel(item);
                if (!label || seen.has(label)) return;

                if (modeId) seen.add(modeId);
                seen.add(label);

                models.push(normalizeModelConfig({
                    label,
                    testId: item.getAttribute('data-test-id'),
                    jslogId: modeId,
                }));
            });

            if (models.length) break;
        }

        return models;
    }

    function cacheAvailableModels(models) {
        if (models.length) GM_setValue(MODELS_CACHE_KEY, models);
    }

    function getCachedModels() {
        const cached = GM_getValue(MODELS_CACHE_KEY, null);
        return Array.isArray(cached) ? cached.map(normalizeModelConfig) : [];
    }

    async function discoverAvailableModels() {
        let models = scrapeModelMenuItems();

        if (!models.length) {
            const button = findModeButton();
            if (button) {
                setConfigureVisualsHidden(true);
                try {
                    const opened = await ensureGemMenuOpen(button);
                    if (opened) models = scrapeModelMenuItems();
                    await closeMenuAndWait();
                } finally {
                    setConfigureVisualsHidden(false);
                }
            }
        }

        if (!models.length) models = getCachedModels();
        if (!models.length && isTargetGemPage()) models = GEM_PAGE_MODELS.map(normalizeModelConfig);

        cacheAvailableModels(models);
        return models;
    }

    function isMenuItemSelected(item) {
        return item?.getAttribute('data-active') === 'true' || item?.classList.contains('selected');
    }

    function findGemMenuItem(label, exact) {
        const items = document.querySelectorAll('gem-menu-item[role="menuitem"]');
        for (const item of items) {
            const rect = item.getBoundingClientRect();
            if (rect.width === 0 && rect.height === 0) continue;

            const text = getMenuItemLabel(item);
            if (exact ? text === label : text.includes(label)) {
                return item;
            }
        }
        return null;
    }

    function getThinkingLevelItem() {
        return document.querySelector('gem-menu-item[value="thinking_level"]');
    }

    function getCurrentThinkingLevel() {
        const fromPill = getCurrentThinkingFromPill();
        if (fromPill) return fromPill;
        return getThinkingLevelItem()?.querySelector('.sublabel')?.textContent.trim() || '';
    }

    async function ensureGemMenuOpen(button) {
        if (isGemMenuOpen()) return true;
        button.click();
        return waitUntil(isGemMenuOpen, 2000, 16);
    }

    async function selectTargetModel() {
        const testId = getTargetModelTestId();
        const modelItem = (testId && document.querySelector(`[data-test-id="${testId}"]`)) ||
            findGemMenuItem(getTargetModel(), true);
        if (!modelItem || isMenuItemSelected(modelItem)) return true;

        modelItem.click();
        await waitUntil(() => isMenuItemSelected(modelItem) || isTargetModelSelected(), 1500, 16);
        return true;
    }

    function isThinkingLevelOption(item) {
        if (!item || item.getAttribute('value') === 'thinking_level') return false;
        if (item.getAttribute('data-mode-id')) return false;
        if (item.getAttribute('data-test-id')?.startsWith('bard-mode-option-')) return false;
        const label = getMenuItemLabel(item);
        return !!label && !/^thinking level$/i.test(label);
    }

    function scrapeThinkingLevelItems() {
        const levels = [];
        const seen = new Set();
        const thinkingItem = getThinkingLevelItem();
        const menuId = thinkingItem?.getAttribute('aria-controls');
        const roots = [];

        if (menuId) {
            const nested = document.getElementById(menuId);
            if (nested) roots.push(nested);
        }

        document.querySelectorAll('.cdk-overlay-pane gem-menu').forEach((menu) => {
            if (thinkingItem && menu.contains(thinkingItem)) return;
            if (menu.querySelector('[data-test-id="gem-mode-menu"]')) return;
            roots.push(menu);
        });

        const collect = (root) => {
            root.querySelectorAll('gem-menu-item[role="menuitem"]').forEach((item) => {
                if (!isThinkingLevelOption(item)) return;

                const rect = item.getBoundingClientRect();
                if (rect.width === 0 && rect.height === 0) return;

                const label = getMenuItemLabel(item);
                if (seen.has(label)) return;

                seen.add(label);
                levels.push(label);
            });
        };

        roots.forEach(collect);

        if (!levels.length) {
            document.querySelectorAll('.cdk-overlay-pane gem-menu-item[role="menuitem"]').forEach((item) => {
                if (!isThinkingLevelOption(item)) return;
                const rect = item.getBoundingClientRect();
                if (rect.width === 0 && rect.height === 0) return;
                const label = getMenuItemLabel(item);
                if (!label || seen.has(label)) return;
                seen.add(label);
                levels.push(label);
            });
        }

        return levels;
    }

    function cacheAvailableThinkingLevels(levels) {
        if (levels.length) GM_setValue(THINKING_CACHE_KEY, levels);
    }

    function getCachedThinkingLevels() {
        const cached = GM_getValue(THINKING_CACHE_KEY, null);
        return Array.isArray(cached) ? cached : [];
    }

    async function discoverAvailableThinkingLevels() {
        let levels = scrapeThinkingLevelItems();

        if (!levels.length) {
            const button = findModeButton();
            if (button) {
                setConfigureVisualsHidden(true);
                try {
                    await ensureGemMenuOpen(button);
                    let thinkingItem = getThinkingLevelItem();
                    if (thinkingItem?.getAttribute('aria-expanded') !== 'true') {
                        thinkingItem.click();
                        await waitUntil(
                            () => thinkingItem.getAttribute('aria-expanded') === 'true' || scrapeThinkingLevelItems().length > 0,
                            1500,
                            16
                        );
                    }
                    levels = scrapeThinkingLevelItems();
                    await closeMenuAndWait();
                } finally {
                    setConfigureVisualsHidden(false);
                }
            }
        }

        if (!levels.length) levels = getCachedThinkingLevels();
        if (!levels.length) levels = [...DEFAULT_THINKING_LEVELS];

        cacheAvailableThinkingLevels(levels);
        return levels;
    }

    async function selectTargetThinking(button) {
        const targetThinking = getTargetThinking();
        let thinkingItem = getThinkingLevelItem();
        if (!thinkingItem && button) {
            await ensureGemMenuOpen(button);
            thinkingItem = getThinkingLevelItem();
        }
        if (!thinkingItem) return false;

        if (getCurrentThinkingLevel() === targetThinking) return true;

        if (thinkingItem.getAttribute('aria-expanded') !== 'true') {
            thinkingItem.click();
            await waitUntil(
                () => thinkingItem.getAttribute('aria-expanded') === 'true' || !!findGemMenuItem(targetThinking, true),
                1500,
                16
            );
        }

        const levelItem = findGemMenuItem(targetThinking, true);
        if (!levelItem) return false;
        if (isMenuItemSelected(levelItem)) return true;

        levelItem.click();
        await waitUntil(() => getCurrentThinkingLevel() === targetThinking, 1500, 16);
        return getCurrentThinkingLevel() === targetThinking;
    }

    async function configureGemSettings() {
        if (!isTargetGemPage()) {
            resetGemSettingsState();
            return;
        }

        if (gemSettingsApplied || isConfiguringGem) return;
        if (syncGemSettingsFromPill()) return;

        const button = findModeButton();
        if (!button) return;

        isConfiguringGem = true;
        setConfigureVisualsHidden(true);

        try {
            const menuReady = await ensureGemMenuOpen(button);
            if (!menuReady) return;

            if (isFullyConfigured() || syncGemSettingsFromPill()) {
                await closeMenuAndWait();
                return;
            }

            if (!isTargetModelSelected()) {
                await selectTargetModel();
                if (!isGemMenuOpen()) {
                    await ensureGemMenuOpen(button);
                }
            }

            await selectTargetThinking(button);
            await closeMenuAndWait();
            focusInputArea();

            if (isSettingsShownInPill() || isFullyConfigured()) {
                markGemSettingsApplied();
            }
        } catch (e) {
            console.error(`${LOG_PREFIX} Gem configure error:`, e);
        } finally {
            await closeMenuAndWait();
            setConfigureVisualsHidden(false);
            isConfiguringGem = false;
        }
    }

    function scheduleGemConfigure() {
        if (!isTargetGemPage() || isConfiguringGem) return;
        if (syncGemSettingsFromPill()) return;
        if (gemSettingsApplied) return;
        if (gemConfigureTimer) return;
        gemConfigureTimer = setTimeout(() => {
            gemConfigureTimer = null;
            configureGemSettings();
        }, 0);
    }

    function setupGemConfigureWatcher() {
        const observer = new MutationObserver(() => {
            if (!isTargetGemPage() || isConfiguringGem) return;
            if (syncGemSettingsFromPill()) return;
            if (gemSettingsApplied) return;
            if (findModeButton()) scheduleGemConfigure();
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    function hookSpaNavigation() {
        const notify = () => setTimeout(onGemNavigation, 0);
        const { pushState, replaceState } = history;
        history.pushState = function(...args) {
            const result = pushState.apply(this, args);
            notify();
            return result;
        };
        history.replaceState = function(...args) {
            const result = replaceState.apply(this, args);
            notify();
            return result;
        };
        window.addEventListener('hashchange', notify);
    }

    function injectSideNavEntry(gemsEntry) {
        const container = gemsEntry.closest('.gems-list-container')
            || gemsEntry.closest('.side-nav-entry-container')
            || gemsEntry.parentElement;
        if (!container || !container.parentElement || alreadyInjected(container.parentElement)) return false;

        const templateEntry = gemsEntry.matches('side-nav-entry-button')
            ? gemsEntry
            : gemsEntry.querySelector('side-nav-entry-button') || gemsEntry;
        const item = templateEntry.cloneNode(true);
        item.setAttribute('data-test-id', BUTTON_TEST_ID);
        item.classList.add('tm-open-gem-item');

        const link = item.querySelector('a[href]');
        if (!link) return false;

        link.href = GEM_PATH;
        link.setAttribute('aria-label', 'Open a gem');
        link.classList.remove('is-arrow-icon');
        setLinkText(item, 'Open a gem');
        item.querySelector('[data-test-id="arrow-icon"]')?.remove();
        setLinkIcon(item, 'open_in_new');

        const wrapper = document.createElement('div');
        wrapper.className = 'side-nav-entry-container tm-open-gem-container ng-star-inserted';
        wrapper.setAttribute('data-test-id', BUTTON_TEST_ID);
        wrapper.appendChild(item);
        container.parentElement.insertBefore(wrapper, container.nextSibling);

        console.log(`${LOG_PREFIX} Added "Open a gem" below Gems (side nav entry)`);
        return true;
    }

    function injectOpenGemButton() {
        let injected = false;

        findActiveGemsNavItems().forEach((gemsNavItem) => {
            if (injectExpandedNavList(gemsNavItem)) {
                injected = true;
            }
        });

        document.querySelectorAll('a[aria-label="Gems"][href*="/gems"]').forEach((gemsAnchor) => {
            if (!isVisible(gemsAnchor)) return;

            const gemsNavItem = gemsAnchor.closest('gem-nav-list-item');
            if (gemsNavItem && injectExpandedNavList(gemsNavItem)) {
                injected = true;
                return;
            }

            const sideEntry = gemsAnchor.closest('side-nav-entry-button');
            if (sideEntry && injectSideNavEntry(sideEntry)) {
                injected = true;
            }
        });

        return injected;
    }

    function scheduleInjectOpenGemButton() {
        if (injectTimer) return;
        injectTimer = setTimeout(() => {
            injectTimer = null;
            injectOpenGemButton();
        }, 100);
    }

    function setupObserver() {
        const observer = new MutationObserver(() => {
            scheduleInjectOpenGemButton();
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    function scheduleLayoutInjectBurst() {
        [0, 150, 400, 800, 1500, 2500].forEach((delay) => {
            setTimeout(scheduleInjectOpenGemButton, delay);
        });
    }

    function scheduleLayoutGemConfigureBurst() {
        if (!isTargetGemPage() || isConfiguringGem) return;
        if (syncGemSettingsFromPill()) return;
        if (gemSettingsApplied) return;
        scheduleGemConfigure();
    }

    function setupLayoutWatchers() {
        let resizeTimer = null;
        const onLayoutChange = () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => {
                scheduleLayoutInjectBurst();
                scheduleLayoutGemConfigureBurst();
            }, 50);
        };

        window.addEventListener('resize', onLayoutChange);
        window.visualViewport?.addEventListener('resize', onLayoutChange);
        window.visualViewport?.addEventListener('scroll', onLayoutChange);

        document.addEventListener('click', (event) => {
            if (event.target.closest('[data-test-id="side-nav-menu-button"]')) {
                scheduleLayoutInjectBurst();
            }
        }, true);
    }

    function setupGemPageWatchers() {
        window.addEventListener('popstate', onGemNavigation);

        setInterval(() => {
            if (location.pathname !== lastGemPath) {
                onGemNavigation();
            }
        }, CHECK_INTERVAL);
    }

    function onGemNavigation() {
        const onGem = isTargetGemPage();
        if (onGem && location.pathname !== lastGemPath) {
            resetGemSettingsState();
            scheduleGemRetries();
        } else if (!onGem) {
            resetGemSettingsState();
        }
        lastGemPath = location.pathname;
        scheduleInjectOpenGemButton();
    }

    function scheduleGemRetries() {
        if (!isTargetGemPage()) return;
        if (syncGemSettingsFromPill()) return;
        [0, 50, 150, 400, 800, 1500].forEach((delay) => {
            setTimeout(scheduleGemConfigure, delay);
        });
    }

    function start() {
        console.log(`${LOG_PREFIX} Script loaded (model: ${getTargetModel()})`);
        lastGemPath = location.pathname;
        injectOpenGemButton();
        setupObserver();
        setupLayoutWatchers();
        setupGemPageWatchers();
        setupGemConfigureWatcher();
        setupSettingsMenu();
        setupKeyboardShortcut();
        syncGemSettingsFromPill();
        scheduleGemRetries();
        setInterval(scheduleInjectOpenGemButton, CHECK_INTERVAL);
    }

    function init() {
        hookSpaNavigation();
        if (document.readyState === 'complete') {
            start();
        } else {
            window.addEventListener('load', start, { once: true });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init, { once: true });
    } else {
        init();
    }
})();
