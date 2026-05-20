// ==UserScript==
// @name         Open Gem Shortcut
// @namespace    http://tampermonkey.net/
// @version      2.2
// @description  Add "Open a gem" sidenav link, Ctrl+Shift+U shortcut, and auto-select 3.5 Flash + Extended on gem page
// @author       You
// @match        https://gemini.google.com/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(function() {
    'use strict';

    const GEM_PATH = '/u/1/gem/aacb7f1889af';
    const GEM_ID = 'aacb7f1889af';
    const BUTTON_TEST_ID = 'open-gem-button';
    const CHECK_INTERVAL = 1000;
    const LOG_PREFIX = '[Open Gem Shortcut]';

    const TARGET_MODEL = '3.5 Flash';
    const TARGET_MODEL_TEST_ID = 'bard-mode-option-56fdd199312815e2';
    const TARGET_THINKING = 'Extended';

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
        console.log(`${LOG_PREFIX} Gem settings configured (${TARGET_MODEL} + ${TARGET_THINKING})`);
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
        return isTargetModelSelected() && getCurrentThinkingLevel() === TARGET_THINKING;
    }

    function getVisiblePillLabel() {
        for (const container of document.querySelectorAll('[data-test-id="logo-pill-label-container"]')) {
            if (!isVisible(container)) continue;

            const model = container.querySelector('.picker-primary-text')?.textContent.trim() || '';
            const thinking = container.querySelector('.picker-secondary-text')?.textContent.trim() || '';
            if (model || thinking) {
                return { model, thinking };
            }
        }
        return null;
    }

    function isModelLabelMatch(modelText) {
        return modelText === TARGET_MODEL ||
            modelText === 'Flash' ||
            (TARGET_MODEL.includes('Flash') && modelText.includes('Flash'));
    }

    function isSettingsShownInPill() {
        const pill = getVisiblePillLabel();
        if (!pill) return false;
        return isModelLabelMatch(pill.model) && pill.thinking === TARGET_THINKING;
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

        const modelItem = document.querySelector(`[data-test-id="${TARGET_MODEL_TEST_ID}"]`);
        return !!modelItem && isVisible(modelItem);
    }

    function isTargetModelSelected() {
        const pill = getVisiblePillLabel();
        if (pill && isModelLabelMatch(pill.model)) return true;

        const modelItem = document.querySelector(`[data-test-id="${TARGET_MODEL_TEST_ID}"]`);
        if (modelItem && isVisible(modelItem) && isMenuItemSelected(modelItem)) return true;

        const modeBtn = findModeButton();
        const jslog = modeBtn?.getAttribute('jslog') || '';
        if (jslog.includes('56fdd199312815e2')) return true;

        return false;
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
        const modelItem = document.querySelector(`[data-test-id="${TARGET_MODEL_TEST_ID}"]`) ||
            findGemMenuItem(TARGET_MODEL, true);
        if (!modelItem || isMenuItemSelected(modelItem)) return true;

        modelItem.click();
        await waitUntil(() => isMenuItemSelected(modelItem) || isTargetModelSelected(), 1500, 16);
        return true;
    }

    async function selectExtendedThinking(button) {
        let thinkingItem = getThinkingLevelItem();
        if (!thinkingItem && button) {
            await ensureGemMenuOpen(button);
            thinkingItem = getThinkingLevelItem();
        }
        if (!thinkingItem) return false;

        if (getCurrentThinkingLevel() === TARGET_THINKING) return true;

        if (thinkingItem.getAttribute('aria-expanded') !== 'true') {
            thinkingItem.click();
            await waitUntil(
                () => thinkingItem.getAttribute('aria-expanded') === 'true' || !!findGemMenuItem(TARGET_THINKING, true),
                1500,
                16
            );
        }

        const extendedItem = findGemMenuItem(TARGET_THINKING, true);
        if (!extendedItem) return false;
        if (isMenuItemSelected(extendedItem)) return true;

        extendedItem.click();
        await waitUntil(() => getCurrentThinkingLevel() === TARGET_THINKING, 1500, 16);
        return getCurrentThinkingLevel() === TARGET_THINKING;
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

            await selectExtendedThinking(button);
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
        console.log(`${LOG_PREFIX} Script loaded`);
        lastGemPath = location.pathname;
        injectOpenGemButton();
        setupObserver();
        setupLayoutWatchers();
        setupGemPageWatchers();
        setupGemConfigureWatcher();
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
