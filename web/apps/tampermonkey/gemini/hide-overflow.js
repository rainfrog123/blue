// ==UserScript==
// @name         Hide Gemini Sidenav
// @namespace    http://tampermonkey.net/
// @version      1.2
// @description  Hide the sidebar with a toggle icon
// @author       You
// @match        https://gemini.google.com/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(function() {
    'use strict';

    const TOGGLE_ID = 'tm-sidenav-toggle';
    let isHidden = localStorage.getItem('gemini-sidenav-hidden') === 'true';

    function addStyles() {
        if (document.getElementById('tm-sidenav-styles')) return;
        const style = document.createElement('style');
        style.id = 'tm-sidenav-styles';
        style.textContent = `
            bard-sidenav.tm-hidden {
                display: none !important;
            }
            body.tm-sidenav-hidden side-nav-menu-button,
            body.tm-sidenav-hidden bard-mode-switcher {
                display: none !important;
            }
            #${TOGGLE_ID} {
                width: 48px;
                height: 48px;
                border-radius: 50%;
                background: transparent;
                border: none;
                color: var(--gds-sys-color-on-surface, #c4c7c5);
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                font-family: 'Google Symbols', 'Material Symbols Outlined', sans-serif;
                font-size: 24px;
                font-weight: normal;
                font-style: normal;
                line-height: 1;
                -webkit-font-smoothing: antialiased;
            }
            #${TOGGLE_ID}:hover {
                background: rgba(255,255,255,0.08);
            }
        `;
        document.head.appendChild(style);
    }

    function getSidenav() {
        return document.querySelector('bard-sidenav');
    }

    function updateVisibility() {
        const sidenav = getSidenav();
        if (!sidenav) return;

        if (isHidden) {
            sidenav.classList.add('tm-hidden');
            document.body.classList.add('tm-sidenav-hidden');
        } else {
            sidenav.classList.remove('tm-hidden');
            document.body.classList.remove('tm-sidenav-hidden');
        }

        const btn = document.getElementById(TOGGLE_ID);
        if (btn) {
            btn.textContent = isHidden ? 'menu' : 'close';
            btn.title = isHidden ? 'Show sidebar' : 'Hide sidebar';
        }
    }

    function toggle() {
        isHidden = !isHidden;
        localStorage.setItem('gemini-sidenav-hidden', isHidden);
        updateVisibility();
    }

    function createToggleButton() {
        if (document.getElementById(TOGGLE_ID)) return;

        const container = document.querySelector('.top-bar-actions .buttons-container');
        if (!container) return;

        const btn = document.createElement('button');
        btn.id = TOGGLE_ID;
        btn.className = 'mdc-icon-button mat-mdc-icon-button mat-mdc-button-base mat-unthemed';
        btn.title = isHidden ? 'Show sidebar' : 'Hide sidebar';
        btn.onclick = toggle;
        container.insertBefore(btn, container.firstChild);
        updateVisibility();
    }

    function setupObserver() {
        const observer = new MutationObserver(() => {
            const sidenav = getSidenav();
            if (sidenav && !sidenav.dataset.tmProcessed) {
                sidenav.dataset.tmProcessed = 'true';
                updateVisibility();
            }
            createToggleButton();
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    function init() {
        console.log('[Gemini Hide Sidenav] Script loaded');
        addStyles();
        createToggleButton();
        setupObserver();
        setTimeout(updateVisibility, 500);
        setTimeout(updateVisibility, 1500);
    }

    if (document.readyState === 'complete') {
        init();
    } else {
        window.addEventListener('load', init);
    }
})();
