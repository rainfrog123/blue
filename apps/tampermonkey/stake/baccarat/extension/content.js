'use strict';

/**
 * Isolated-world bridge. page.js (MAIN world) has no chrome.* APIs.
 * postMessage <-> chrome.runtime.sendMessage for debugger attach + trusted clicks.
 */
window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const d = event.data;
    if (!d || d.source !== 'sb-page') return;
    if (d.type !== 'trustedClick' && d.type !== 'attachDebugger') return;

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
});
