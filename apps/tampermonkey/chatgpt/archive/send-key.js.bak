// ==UserScript==
// @name         Send Hotkey
// @namespace    http://tampermonkey.net/
// @version      0.5
// @description  Send messages on ChatGPT with Ctrl+Enter, use Enter for new lines (Only for window width < 772px)
// @author       15d23
// @match        https://chat.openai.com/*
// @match        https://*.chatgpt.com/*
// @match        https://*.oaifree.com/*
// @match        https://*.rawchat.top/*
// @match        https://*.dairoot.cn/*
// @grant        none
// @license      GPL
// @downloadURL  https://update.greasyfork.org/scripts/464200/ChatGPT%20Ctrl%2BEnter%20Send%20and%20Enter%20New%20Line.user.js
// @updateURL    https://update.greasyfork.org/scripts/464200/ChatGPT%20Ctrl%2BEnter%20Send%20and%20Enter%20New%20Line.meta.js
// ==/UserScript==

(function () {
    'use strict';

    let resizeTimeout;

    // Handler for debouncing window resize
    function debounceResize() {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(checkWindowWidthAndAddListener, 200); // Debounce by 200ms
    }

    // Check window width and add or remove keydown listener
    function checkWindowWidthAndAddListener() {
        const shouldAddListener = window.innerWidth < 772;
        if (shouldAddListener) {
            document.addEventListener('keydown', keydownHandler);
        } else {
            document.removeEventListener('keydown', keydownHandler);
        }
    }

    // Keydown event handler for Ctrl+Enter
    function keydownHandler(event) {
        if (event.key === 'Enter' && event.ctrlKey) {
            event.preventDefault();

            const sendButton = document.querySelector('button[data-testid="send-button"]');

            if (sendButton) {
                sendButton.click();
            } else {
                console.error('Send button not found.');
            }
        }
    }

    // Initial load window width check
    checkWindowWidthAndAddListener();

    // Debounce window resize event
    window.addEventListener('resize', debounceResize);
})();
