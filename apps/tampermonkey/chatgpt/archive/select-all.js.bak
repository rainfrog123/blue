// ==UserScript==
// @name         Select All
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Makes Ctrl+A behave like Meta+A (select all) for web pages.
// @author       You
// @grant        none
// @license      GPL
// @match        https://chat.openai.com/*
// @match        https://*.chatgpt.com/*
// @match        https://*.oaifree.com/*
// ==/UserScript==

(function () {
    'use strict';

    // Handler for keydown event
    function keydownHandler(event) {
        // Check if Ctrl+A is pressed, but Meta+A is not
        if (event.key === 'a' && event.ctrlKey && !event.metaKey) {
            event.preventDefault(); // Prevent the default browser action

            // Dispatch a synthetic Meta+A event
            const metaEvent = new KeyboardEvent(event.type, {
                key: 'a',
                code: 'KeyA',
                keyCode: 65, // Key code for 'A'
                bubbles: true,
                cancelable: true,
                ctrlKey: false, // Ensure Ctrl is not active
                metaKey: true  // Simulate Meta+A
            });

            event.target.dispatchEvent(metaEvent); // Dispatch the event to the current target
        }
    }

    // Add the keydown listener to the document
    document.addEventListener('keydown', keydownHandler);
})();
