// ==UserScript==
// @name         Tab-Isolated Zoom (Gemini)
// @namespace    http://tampermonkey.net/
// @version      1.1
// @description  Zoom a single tab using Ctrl + Mouse Wheel on Gemini (isolated per tab)
// @match        https://gemini.google.com/*
// @grant        none
// ==/UserScript==

(function() {
    'use strict';

    // Give every tab its own unique id so duplicated tabs don't share a zoom.
    // sessionStorage is per-tab, but duplicating a tab copies it; a random id
    // means a fresh tab always starts clean and never inherits another's zoom.
    let tabId = sessionStorage.getItem('tabZoomId');
    if (!tabId) {
        tabId = Date.now().toString(36) + Math.random().toString(36).slice(2);
        sessionStorage.setItem('tabZoomId', tabId);
    }
    const STORAGE_KEY = 'tabZoomLevel:' + tabId;

    let zoomLevel = parseFloat(sessionStorage.getItem(STORAGE_KEY)) || 1.0;

    function applyZoom() {
        if (document.body) {
            document.body.style.zoom = zoomLevel;
        }
    }

    applyZoom();

    window.addEventListener('wheel', function(e) {
        // Hold Ctrl while scrolling to trigger the isolated zoom.
        // preventDefault stops Chrome's native zoom, which is shared across
        // all gemini.google.com tabs, so we replace it with our own per-tab zoom.
        if (e.ctrlKey) {
            e.preventDefault();

            // Scroll up to zoom in, scroll down to zoom out
            zoomLevel += (e.deltaY < 0) ? 0.1 : -0.1;

            // Limits the zoom so it doesn't get infinitely big or small (30% to 400%)
            zoomLevel = Math.min(Math.max(0.3, zoomLevel), 4.0);

            applyZoom();

            // Saves it so a page refresh doesn't reset it (scoped to this tab)
            sessionStorage.setItem(STORAGE_KEY, zoomLevel);
        }
    }, { passive: false });

    // Gemini is a single-page app and re-renders the DOM as you navigate,
    // which can wipe the inline zoom. Re-apply it whenever the body changes.
    const observer = new MutationObserver(function() {
        if (document.body && document.body.style.zoom !== String(zoomLevel)) {
            applyZoom();
        }
    });
    if (document.body) {
        observer.observe(document.body, { attributes: true, attributeFilter: ['style'] });
    }
})();
