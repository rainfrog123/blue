'use strict';

/**
 * Isolated-world bridge. MAIN-world scripts (src/*.js) have no chrome.* APIs.
 * postMessage <-> chrome.runtime.sendMessage for debugger, storage, HUD bus.
 */
window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const d = event.data;
    if (!d || d.source !== 'sb-page') return;

    if (d.type === 'trustedClick' || d.type === 'attachDebugger') {
        const payload = {
            type: d.type,
            id: d.id,
            x: d.x,
            y: d.y,
            gapMs: d.gapMs,
        };
        chrome.runtime.sendMessage(payload, (res) => {
            const err = chrome.runtime.lastError;
            window.postMessage({
                source: 'sb-ext',
                id: d.id,
                ok: !err && !!(res && res.ok),
                error: err ? err.message : (res && res.error) || null,
            }, '*');
        });
        return;
    }

    if (d.type === 'storageGet') {
        chrome.storage.local.get(d.keys || [d.key], (data) => {
            const err = chrome.runtime.lastError;
            window.postMessage({
                source: 'sb-ext',
                id: d.id,
                ok: !err,
                data: data || {},
                error: err ? err.message : null,
            }, '*');
        });
        return;
    }

    if (d.type === 'storageSet') {
        chrome.storage.local.set(d.data || {}, () => {
            const err = chrome.runtime.lastError;
            window.postMessage({
                source: 'sb-ext',
                id: d.id,
                ok: !err,
                error: err ? err.message : null,
            }, '*');
        });
        return;
    }

    if (d.type === 'hudBus') {
        chrome.runtime.sendMessage({ type: 'hudBus', payload: d.payload }, () => {
            void chrome.runtime.lastError;
        });
        window.postMessage({ source: 'sb-ext', id: d.id, ok: true }, '*');
    }
});

chrome.runtime.onMessage.addListener((msg) => {
    if (!msg || msg.type !== 'hudBus') return;
    window.postMessage({ source: 'sb-ext-hud', payload: msg.payload }, '*');
});
