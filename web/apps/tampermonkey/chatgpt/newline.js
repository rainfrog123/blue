// ==UserScript==
// @name         Newline
// @namespace    http://tampermonkey.net/
// @version      1.4
// @description  Makes Enter create a new <p> under #prompt-textarea and Ctrl+Enter sends the message.
// @author       You
// @match        https://*.rawchat.top/*
// @match        https://*.chatgpt.com/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function () {
    'use strict';

    console.log("Global Enter-to-New Paragraph Script Initialized.");

    // Add a global keydown event listener
    document.addEventListener("keydown", function (event) {
        const activeElement = document.activeElement;

        // Check if the active element is the #prompt-textarea or a child of it
        if (activeElement.closest && activeElement.closest("#prompt-textarea")) {

            // CTRL+Enter logic (send button click)
            if (event.key === 'Enter' && event.ctrlKey) {
                event.preventDefault(); // Prevent default behavior

                // Find and click the "send" button
                const sendButton = document.querySelector('button[data-testid="send-button"]');
                if (sendButton) {
                    sendButton.click();
                } else {
                    console.error('Send button not found.');
                }
                return; // Exit to prevent further code execution
            }

            // Regular Enter logic (insert a new <p>)
            if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault(); // Prevent default behavior

                const parent = document.querySelector("#prompt-textarea");
                if (parent) {
                    // Create a new <p> element with a placeholder
                    const newP = document.createElement("p");
                    newP.textContent = "\u00a0"; // Add a non-breaking space to make it visible

                    // Insert the new <p> after the currently active element
                    if (activeElement.tagName === "P") {
                        activeElement.insertAdjacentElement("afterend", newP);
                    } else {
                        // Fallback: append it to the parent if no specific active <p>
                        parent.appendChild(newP);
                    }

                    // Move the caret into the new <p>
                    const range = document.createRange();
                    range.setStart(newP, 0);
                    range.collapse(true);

                    const selection = window.getSelection();
                    selection.removeAllRanges();
                    selection.addRange(range);
                }
            }
        }
    }, true); // Capture phase to ensure priority
})();
