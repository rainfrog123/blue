// ==UserScript==
// @name         popup blocker
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Auto-dismisses blocking popups (inactivity pauses) on Baccarat
// @author       You
// @match        *://client.pragmaticplaylive.net/desktop/baccarat/*
// @grant        none
// @run-at       document-end
// ==/UserScript==

(function() {
    'use strict';
    document.querySelector('#root > div.bJ_bK.bJ_cb').style.visibility = 'hidden';

    // Override window dimensions
    Object.defineProperty(window, 'innerWidth', { get: () => 600 });
    Object.defineProperty(window, 'innerHeight', { get: () => 1200 });

    const CONFIG = {
        POPUP_SEL: '[data-testid="blocking-popup-content"]',
        BUTTON_SEL: '[data-testid="blocking-popup-buttons"] [data-testid="button"]',
        TITLE_SEL: '[data-testid="blocking-popup-title"]',
        INACTIVITY_REGEX: /game paused due to inactivity/i,
        SESSION_EXPIRED_REGEX: /session expired/i,
        CHECK_INTERVAL: 2000,
        STAKE_URL: 'https://stake.com/casino/games/pragmatic-play-japanese-speed-baccarat'
    };

    function isVisible(el) {
        if (!el) return false;
        const st = getComputedStyle(el);
        if (st.display === 'none' || st.visibility === 'hidden' || +st.opacity === 0) return false;
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0;
    }

    function checkPopup() {
        const node = document.querySelector(CONFIG.POPUP_SEL);
        if (!node || !isVisible(node)) return;

        const title = document.querySelector(CONFIG.TITLE_SEL);
        const content = node.textContent || '';
        
        // Check for inactivity popup
        if (CONFIG.INACTIVITY_REGEX.test(content)) {
            console.log('[Popup] Inactivity popup detected - auto-dismissing');
            const btn = document.querySelector(CONFIG.BUTTON_SEL);
            if (btn) btn.click();
            return;
        }

        // Check for session expired popup
        if (title && CONFIG.SESSION_EXPIRED_REGEX.test(title.textContent || '')) {
            console.log('[Popup] Session expired detected - redirecting to Stake.com');
            const btn = document.querySelector(CONFIG.BUTTON_SEL);
            if (btn) {
                btn.click();
                setTimeout(() => {
                    redirectToStake();
                }, 1000);
            }
            return;
        }
    }

    function redirectToStake() {
        console.log('[Popup] Redirecting to Stake.com Japanese Speed Baccarat...');
        window.location.href = CONFIG.STAKE_URL;
    }

    // Set up observer for DOM changes
    const observer = new MutationObserver(() => { 
        queueMicrotask(checkPopup); 
    });

    observer.observe(document.documentElement, {
        subtree: true,
        childList: true,
        attributes: true,
        attributeFilter: ['class', 'style', 'aria-hidden']
    });

    console.log('[Popup] popup blocker v1.0 initialized');
    console.log('[Popup] Session expired -> redirects to Stake.com');
    
    // Initial check and periodic fallback
    checkPopup();
    setInterval(checkPopup, CONFIG.CHECK_INTERVAL);
})();
