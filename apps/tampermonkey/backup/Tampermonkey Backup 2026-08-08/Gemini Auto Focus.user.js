// ==UserScript==
// @name         Gemini Auto Focus
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Type anywhere and it goes to Gemini input
// @author       You
// @match        https://gemini.google.com/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(function() {
    'use strict';

    function getPromptInput() {
        return document.querySelector('[aria-label="Enter a prompt for Gemini"]') ||
               document.querySelector('input-area-v2 .ql-editor') ||
               document.querySelector('.ql-editor[contenteditable="true"]');
    }

    function isInInput() {
        const el = document.activeElement;
        if (!el) return false;
        const tag = el.tagName.toLowerCase();
        return tag === 'input' || tag === 'textarea' || el.isContentEditable;
    }

    function focusAtEnd(el) {
        el.focus();
        if (el.isContentEditable) {
            const sel = window.getSelection();
            const range = document.createRange();
            range.selectNodeContents(el);
            range.collapse(false);
            sel.removeAllRanges();
            sel.addRange(range);
        } else if (el.setSelectionRange) {
            const len = el.value.length;
            el.setSelectionRange(len, len);
        }
    }

    document.addEventListener('keydown', (e) => {
        if (isInInput()) return;

        const input = getPromptInput();
        if (!input) return;

        // Allow Ctrl+V / Cmd+V to paste into input
        if ((e.ctrlKey || e.metaKey) && e.key === 'v') {
            focusAtEnd(input);
            return;
        }

        if (e.ctrlKey || e.metaKey || e.altKey) return;
        if (e.key.length !== 1) return;

        focusAtEnd(input);
    });

    console.log('[Gemini Auto Focus] Script loaded - type anywhere to focus input');
})();
