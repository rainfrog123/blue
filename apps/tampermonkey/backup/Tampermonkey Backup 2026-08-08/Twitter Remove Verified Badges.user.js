// ==UserScript==
// @name         Twitter Remove Verified Badges
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Remove all verified account badges (blue checkmarks) from Twitter/X
// @author       You
// @match        https://twitter.com/*
// @match        https://x.com/*
// @grant        GM_addStyle
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    const css = `
        /* Hide verified badges by data-testid */
        [data-testid="icon-verified"] {
            display: none !important;
        }

        /* Hide verified badges by aria-label */
        svg[aria-label="Verified account"] {
            display: none !important;
        }

        /* Hide the parent span that contains the badge (removes extra spacing) */
        span:has(> [data-testid="icon-verified"]),
        span:has(> svg[aria-label="Verified account"]) {
            display: none !important;
        }

        /* Hide parody/authenticity labels (PCF labels) */
        a[href*="rules-and-policies/authenticity"] {
            display: none !important;
        }

        /* Hide any label containing parody-mask image */
        [style*="parody-mask"],
        img[src*="parody-mask"] {
            display: none !important;
        }

        /* Hide parent container of authenticity labels */
        div:has(> a[href*="rules-and-policies/authenticity"]) {
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
