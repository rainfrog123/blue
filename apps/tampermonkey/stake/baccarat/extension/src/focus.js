'use strict';

/**
 * Keep PP/Stake from pausing when the tab is in the background.
 * CDP clicks do not need the tab focused; the game still checks visibility.
 * Scope patches to this document only — do not touch Document.prototype or mouseleave.
 */
(function (SB) {
    SB.maskPageFocus = function () {
        const doc = document;
        const define = (obj, key, get) => {
            try {
                Object.defineProperty(obj, key, { configurable: true, get });
            } catch (_) {}
        };
        define(doc, 'visibilityState', () => 'visible');
        define(doc, 'webkitVisibilityState', () => 'visible');
        define(doc, 'hidden', () => false);
        define(doc, 'webkitHidden', () => false);
        try {
            Object.defineProperty(doc, 'hasFocus', {
                configurable: true,
                value: () => true,
            });
        } catch (_) {
            try { doc.hasFocus = () => true; } catch (_) {}
        }
        const silent = (e) => { e.stopImmediatePropagation(); };
        window.addEventListener('blur', silent, true);
        doc.addEventListener('visibilitychange', silent, true);
        doc.addEventListener('webkitvisibilitychange', silent, true);
        window.addEventListener('pagehide', silent, true);
        window.addEventListener('freeze', silent, true);
    };
})(window.__SB);
