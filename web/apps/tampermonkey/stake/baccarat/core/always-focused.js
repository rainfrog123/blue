// ==UserScript==
// @name         always-focused
// @namespace    http://tampermonkey.net/
// @version      1.1.0
// @description  Report tab as visible/focused; block blur visibility signals (Stake + PP multibaccarat).
// @author       You
// @match        *://*.stake.com/*
// @match        *://stake.com/*
// @match        *://client.pragmaticplaylive.net/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    const visibleDesc = {
        configurable: true,
        get() { return 'visible'; },
    };

    const notHiddenDesc = {
        configurable: true,
        get() { return false; },
    };

    try {
        Object.defineProperty(document, 'visibilityState', visibleDesc);
        Object.defineProperty(document, 'webkitVisibilityState', visibleDesc);
        Object.defineProperty(document, 'hidden', notHiddenDesc);
        Object.defineProperty(document, 'webkitHidden', notHiddenDesc);
    } catch (_) {}

    try {
        Document.prototype.hasFocus = function() { return true; };
    } catch (_) {}

    const block = (e) => {
        e.stopImmediatePropagation();
    };

    window.addEventListener('blur', block, true);
    window.addEventListener('mouseleave', block, true);
    window.addEventListener('visibilitychange', block, true);
    window.addEventListener('webkitvisibilitychange', block, true);

    console.log('[always-focused] visibility/blur masking active');
})();
