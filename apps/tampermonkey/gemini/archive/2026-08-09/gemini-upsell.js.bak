// ==UserScript==
// @name         Remove Gemini Ultra Upsell
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Remove the "Upgrade to Google AI Ultra" button from Gemini
// @author       You
// @match        https://gemini.google.com/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(function() {
    'use strict';

    function removeUpsellElements() {
        // Target the upsell button container
        const upsellContainers = document.querySelectorAll('.buttons-container.adv-upsell');
        upsellContainers.forEach(el => el.remove());

        // Target the dynamic upsell button component directly
        const upsellButtons = document.querySelectorAll('g1-dynamic-upsell-button');
        upsellButtons.forEach(el => el.remove());

        // Fallback: find by text content
        const allButtons = document.querySelectorAll('button');
        allButtons.forEach(btn => {
            if (btn.textContent.includes('Upgrade to Google AI Ultra') ||
                btn.textContent.includes('Upgrade to Ultra')) {
                const container = btn.closest('.buttons-container.adv-upsell') || btn.closest('g1-dynamic-upsell-button');
                if (container) {
                    container.remove();
                } else {
                    btn.remove();
                }
            }
        });
    }

    function setupObserver() {
        const observer = new MutationObserver(() => {
            removeUpsellElements();
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    function init() {
        console.log('[Gemini Remove Upsell] Script loaded');
        setupObserver();
        removeUpsellElements();
        setTimeout(removeUpsellElements, 1000);
        setTimeout(removeUpsellElements, 3000);
    }

    if (document.readyState === 'complete') {
        init();
    } else {
        window.addEventListener('load', init);
    }
})();
