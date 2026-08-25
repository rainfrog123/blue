'use strict';

/** debuggee key -> { targetId } */
const attached = new Map();

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const urlsMatch = (a, b) => {
    try {
        const ua = new URL(a);
        const ub = new URL(b);
        return ua.origin === ub.origin && ua.pathname === ub.pathname;
    } catch (_) {
        return a === b;
    }
};

const debuggeeKey = (debuggee) =>
    debuggee.targetId ? `id:${debuggee.targetId}` : `tab:${debuggee.tabId}`;

async function findDebuggee(sender) {
    const tabId = sender?.tab?.id;
    const url = sender?.url || '';
    const targets = await chrome.debugger.getTargets();
    const inTab = tabId != null ? targets.filter((t) => t.tabId === tabId) : targets;

    const byUrl = inTab.filter((t) => url && urlsMatch(t.url || '', url));
    const iframeHit = byUrl.find((t) => t.type === 'iframe') || byUrl[0];
    if (iframeHit?.id) return { targetId: iframeHit.id };

    const mb = inTab.find((t) => /multibaccarat/i.test(t.url || ''));
    if (mb?.id) return { targetId: mb.id };

    throw new Error('no matching debugger target (iframe)');
}

async function ensureAttached(debuggee) {
    const key = debuggeeKey(debuggee);
    if (attached.has(key)) return debuggee;
    try {
        await chrome.debugger.attach(debuggee, '1.3');
    } catch (err) {
        const msg = String(err?.message || err);
        if (!/already attached/i.test(msg)) throw err;
    }
    attached.set(key, debuggee);
    return debuggee;
}

async function dispatchClick(debuggee, x, y, gapMs) {
    const px = Math.round(Number(x) * 100) / 100;
    const py = Math.round(Number(y) * 100) / 100;
    if (!Number.isFinite(px) || !Number.isFinite(py)) {
        throw new Error('bad click coords');
    }
    const gap = Math.max(0, Math.min(80, Number(gapMs) || 12));
    const base = { x: px, y: py, pointerType: 'mouse' };
    await chrome.debugger.sendCommand(debuggee, 'Input.dispatchMouseEvent', {
        ...base,
        type: 'mouseMoved',
    });
    await sleep(4 + Math.floor(Math.random() * 10));
    await chrome.debugger.sendCommand(debuggee, 'Input.dispatchMouseEvent', {
        ...base,
        type: 'mousePressed',
        button: 'left',
        buttons: 1,
        clickCount: 1,
    });
    if (gap > 0) await sleep(gap);
    await chrome.debugger.sendCommand(debuggee, 'Input.dispatchMouseEvent', {
        ...base,
        type: 'mouseReleased',
        button: 'left',
        buttons: 0,
        clickCount: 1,
    });
}

chrome.debugger.onDetach.addListener((source) => {
    attached.delete(debuggeeKey(source));
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
    const targets = await chrome.debugger.getTargets().catch(() => []);
    for (const t of targets) {
        if (t.tabId !== tabId || !t.id) continue;
        const debuggee = { targetId: t.id };
        const key = debuggeeKey(debuggee);
        if (!attached.has(key)) continue;
        try {
            await chrome.debugger.detach(debuggee);
        } catch (_) {}
        attached.delete(key);
    }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg || (msg.type !== 'trustedClick' && msg.type !== 'attachDebugger')) {
        return false;
    }
    (async () => {
        const debuggee = await ensureAttached(await findDebuggee(sender));
        if (msg.type === 'attachDebugger') {
            sendResponse({ ok: true });
            return;
        }
        await dispatchClick(debuggee, msg.x, msg.y, msg.gapMs);
        sendResponse({ ok: true });
    })().catch((err) => {
        sendResponse({ ok: false, error: String(err?.message || err) });
    });
    return true;
});
