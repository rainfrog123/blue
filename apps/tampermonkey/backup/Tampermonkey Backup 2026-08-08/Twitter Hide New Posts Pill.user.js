// ==UserScript==
// @name         Twitter Hide New Posts Pill
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Permanently hide the "New posts are available" pill on Twitter/X
// @author       You
// @match        https://twitter.com/*
// @match        https://x.com/*
// @grant        GM_addStyle
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    const css = `
        /* Hide the "New posts are available" notification pill */
        [role="status"][data-keep-composer-open="true"] {
            display: none !important;
        }

        button[aria-label*="New posts are available"] {
            display: none !important;
        }
    `;

    if (typeof GM_addStyle !== 'undefined') {
        GM_addStyle(css);
    } else {
        const style = document.createElement('style');
        style.textContent = css;
        (document.head || document.documentElement).appendChild(style);
    }
})();
