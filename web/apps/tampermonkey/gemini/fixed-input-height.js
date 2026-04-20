// ==UserScript==
// @name         Gemini Fix Chat Input Auto-Resize
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Forces the Gemini chat input box to maintain a fixed height and stops it from auto-resizing.
// @author       You
// @match        https://gemini.google.com/*
// @grant        GM_addStyle
// ==/UserScript==

(function() {
    'use strict';

    // Set your preferred fixed height here
    const fixedHeight = '33px';

    // Inject CSS to override the dynamic inline styles applied by the site's JS
    GM_addStyle(`
        /* Target the outer input area wrapper */
        input-area-v2 .text-input-field {
            height: ${fixedHeight} !important;
            min-height: ${fixedHeight} !important;
            max-height: ${fixedHeight} !important;
        }

        /* Target the textarea wrapper */
        .text-input-field_textarea-wrapper {
            height: ${fixedHeight} !important;
            min-height: ${fixedHeight} !important;
            max-height: ${fixedHeight} !important;
        }

        /* Target the inner textarea container */
        .text-input-field_textarea-inner {
            height: 100% !important;
            min-height: 100% !important;
            max-height: 100% !important;
        }

        /* Target the rich-textarea custom element */
        rich-textarea.text-input-field_textarea {
            height: 100% !important;
            min-height: 100% !important;
            max-height: 100% !important;
        }

        /* Target the actual editable text area (Quill editor) and enable scrolling */
        .ql-editor.textarea {
            height: 100% !important;
            min-height: 100% !important;
            max-height: 100% !important;
            overflow-y: auto !important;
        }

        /* Ensure the main text field area respects the height */
        .text-input-field-main-area {
            height: 100% !important;
            min-height: 100% !important;
            max-height: 100% !important;
        }

        /* ===== Header Title Centering Fix ===== */
        /* Force the top bar to use proper centering */
        .top-bar-actions {
            display: flex !important;
            justify-content: space-between !important;
            align-items: center !important;
        }

        /* Make left and right sections equal width so center is truly centered */
        .top-bar-actions .left-section,
        .top-bar-actions .right-section {
            flex: 1 1 0 !important;
            min-width: 0 !important;
        }

        /* Right section aligns its content to the right */
        .top-bar-actions .right-section {
            display: flex !important;
            justify-content: flex-end !important;
        }

        /* Center section doesn't grow, stays centered */
        .top-bar-actions .center-section {
            flex: 0 1 auto !important;
            text-align: center !important;
        }
    `);
})();
