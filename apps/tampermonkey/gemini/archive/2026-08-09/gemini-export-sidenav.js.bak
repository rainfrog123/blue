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
            mat-sidenav.tm-hidden {
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
            }
            #${TOGGLE_ID}:hover {
                background: rgba(255,255,255,0.08);
            }
        `;
        document.head.appendChild(style);
    }

    const inspirationalQuotes = [
        "The only limit is your imagination.",
        "Dream big, start small, act now.",
        "Every moment is a fresh beginning.",
        "Be the energy you want to attract.",
        "Stars can't shine without darkness.",
        "Your potential is endless.",
        "Create the life you can't wait to wake up to.",
        "The best time to start is now.",
        "Believe you can and you're halfway there.",
        "Make today ridiculously amazing.",
        "You are capable of extraordinary things.",
        "Let your light shine so bright it inspires others.",
        "The universe is conspiring in your favor.",
        "You were born to do remarkable things.",
        "Your story is still being written.",
        "What feels impossible today will be your warm-up tomorrow.",
        "You are exactly where you need to be.",
        "Trust the magic of new beginnings.",
        "You carry galaxies within you.",
        "Today is full of endless possibilities.",
        "Your presence makes the world more beautiful.",
        "The best is yet to come.",
        "You are a work of art in progress.",
        "Let curiosity lead the way.",
        "You have survived 100% of your worst days.",
        "Embrace the glorious mess that you are.",
        "You are the author of your own story.",
        "Breathe. You've got this.",
        "Small steps still move you forward.",
        "You are braver than you believe.",
        "The sun will rise and we will try again.",
        "You are someone's reason to smile.",
        "Dare to be different. Dare to be you.",
        "Your dreams are valid.",
        "You are made of stardust and infinite potential.",
        "Every day is a chance to begin again.",
        "You light up the world just by being in it.",
        "Wherever you go, go with all your heart.",
        "You are worthy of all the good things coming your way.",
        "The world needs your unique magic."
    ];

    function replaceDisclaimer() {
        const disclaimer = document.querySelector('hallucination-disclaimer p');
        if (disclaimer && !disclaimer.dataset.tmInspired) {
            disclaimer.dataset.tmInspired = 'true';
            const quote = inspirationalQuotes[Math.floor(Math.random() * inspirationalQuotes.length)];
            disclaimer.textContent = quote;
        }
    }

    function getSidenav() {
        return document.querySelector('mat-sidenav');
    }

    function updateVisibility() {
        // Always update body class (controls hamburger menu and logo visibility)
        if (isHidden) {
            document.body.classList.add('tm-sidenav-hidden');
        } else {
            document.body.classList.remove('tm-sidenav-hidden');
        }

        // Update sidenav if it exists
        const sidenav = getSidenav();
        if (sidenav) {
            if (isHidden) {
                sidenav.classList.add('tm-hidden');
            } else {
                sidenav.classList.remove('tm-hidden');
            }
        }

        // Update button icon
        const btn = document.getElementById(TOGGLE_ID);
        if (btn) {
            btn.title = isHidden ? 'Show sidebar' : 'Hide sidebar';
            const icon = btn.querySelector('mat-icon');
            if (icon) {
                icon.textContent = isHidden ? 'menu' : 'close';
                icon.setAttribute('fonticon', isHidden ? 'menu' : 'close');
            }
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

        const icon = document.createElement('mat-icon');
        icon.className = 'mat-icon notranslate gds-icon-l google-symbols mat-ligature-font mat-icon-no-color';
        icon.setAttribute('aria-hidden', 'true');
        icon.setAttribute('fonticon', isHidden ? 'menu' : 'close');
        icon.textContent = isHidden ? 'menu' : 'close';
        btn.appendChild(icon);

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
            replaceDisclaimer();
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    function init() {
        console.log('[Gemini Hide Sidenav] Script loaded');
        addStyles();
        updateVisibility(); // Apply immediately to hide menu/logo
        createToggleButton();
        replaceDisclaimer();
        setupObserver();
        setTimeout(updateVisibility, 500);
        setTimeout(updateVisibility, 1500);
        setTimeout(replaceDisclaimer, 500);
    }

    if (document.readyState === 'complete') {
        init();
    } else {
        window.addEventListener('load', init);
    }
})();
