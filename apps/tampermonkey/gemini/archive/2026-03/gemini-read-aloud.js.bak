// ==UserScript==
// @name         Gemini Read Aloud Shortcut
// @namespace    http://tampermonkey.net/
// @version      1.3
// @description  Press Ctrl+X to trigger read aloud (TTS) on the last Gemini response
// @author       You
// @match        https://gemini.google.com/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(function() {
    'use strict';

    let isProcessing = false;

    function debug(...args) {
        console.log('[Gemini Read Aloud]', ...args);
    }

    function getLastTTSButton() {
        // The TTS button is directly visible in tts-control component
        // It has class "tts-button" and contains mat-icon with fonticon="volume_up"
        const ttsButtons = document.querySelectorAll('tts-control button.tts-button');
        debug('Found tts-control buttons:', ttsButtons.length);
        
        if (ttsButtons.length > 0) {
            return ttsButtons[ttsButtons.length - 1];
        }

        // Fallback: find by aria-label
        const listenButtons = document.querySelectorAll('button[aria-label="Listen"]');
        debug('Found Listen buttons:', listenButtons.length);
        
        if (listenButtons.length > 0) {
            return listenButtons[listenButtons.length - 1];
        }

        // Fallback: find volume_up icon and get parent button
        const volumeIcons = document.querySelectorAll('mat-icon[fonticon="volume_up"]');
        debug('Found volume_up icons:', volumeIcons.length);
        
        if (volumeIcons.length > 0) {
            const lastIcon = volumeIcons[volumeIcons.length - 1];
            const button = lastIcon.closest('button');
            debug('Found button from icon:', button);
            return button;
        }

        return null;
    }

    function triggerReadAloud() {
        if (isProcessing) {
            debug('Already processing, skipping');
            return;
        }
        isProcessing = true;
        debug('=== Starting triggerReadAloud ===');

        try {
            const ttsButton = getLastTTSButton();
            
            if (!ttsButton) {
                debug('ERROR: No TTS button found');
                return;
            }

            debug('Found TTS button:', ttsButton);
            debug('Button classes:', ttsButton.className);
            debug('Clicking TTS button...');
            ttsButton.click();
            debug('=== Done! ===');

        } catch (e) {
            debug('ERROR:', e);
        } finally {
            setTimeout(() => {
                isProcessing = false;
                debug('Processing reset');
            }, 500);
        }
    }

    document.addEventListener('keydown', (e) => {
        // Ctrl+X to trigger read aloud
        if (e.key === 'x' && e.ctrlKey && !e.altKey && !e.metaKey && !e.shiftKey) {
            debug('Ctrl+X detected!');
            e.preventDefault();
            triggerReadAloud();
        }
    });

    debug('Script loaded - press Ctrl+X to read aloud');
    debug('Current page:', window.location.href);
})();
