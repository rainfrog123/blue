// ==UserScript==
// @name         Gemini Tab Focus
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Press Tab to instantly focus the Gemini prompt input
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

    function isEditableElement(el) {
        if (!el) return false;
        const tagName = el.tagName.toLowerCase();
        if (tagName === 'input' || tagName === 'textarea') return true;
        if (el.isContentEditable) return true;
        return false;
    }

    document.addEventListener('keydown', (e) => {
        // Only trigger on "Tab" key
        if (e.key !== 'Tab') return;

        // Don't trigger if user is already typing in an input field
        // if (isEditableElement(document.activeElement)) return;

        // Don't trigger with modifier keys
        if (e.ctrlKey || e.metaKey || e.altKey) return;

        const input = getPromptInput();
        if (input) {
            e.preventDefault();
            input.focus();
            console.log('[Gemini Tab Focus] Focused prompt input');
        }
    });

    console.log('[Gemini Tab Focus] Script loaded - press Tab to focus prompt');
})();
