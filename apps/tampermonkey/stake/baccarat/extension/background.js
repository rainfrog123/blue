'use strict';

/** debuggee key -> debuggee */
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

const uniqueDebuggees = (list) => {
    const seen = new Set();
    const out = [];
    for (const d of list) {
        if (!d || (d.targetId == null && d.tabId == null)) continue;
        const k = debuggeeKey(d);
        if (seen.has(k)) continue;
        seen.add(k);
        out.push(d);
    }
    return out;
};

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

/** Stake page + every PP / Multiplay iframe in the same tab (DevTools “emulate focused page”). */
async function findFocusDebuggees(sender) {
    const tabId = sender?.tab?.id;
    const targets = await chrome.debugger.getTargets();
    const inTab = tabId != null ? targets.filter((t) => t.tabId === tabId) : [];
    const out = [];
    for (const t of inTab) {
        if (!t.id) continue;
        const url = t.url || '';
        const isPage = t.type === 'page';
        const isGame =
            t.type === 'iframe' &&
            /pragmaticplaylive\.net|stake\.com|multibaccarat/i.test(url);
        if (isPage || isGame) out.push({ targetId: t.id });
    }
    try {
        out.push(await findDebuggee(sender));
    } catch (_) {}
    if (!out.length && tabId != null) out.push({ tabId });
    return uniqueDebuggees(out);
}

async function emulateFocusedPage(debuggee) {
    try {
        await chrome.debugger.sendCommand(debuggee, 'Emulation.setFocusEmulationEnabled', {
            enabled: true,
        });
    } catch (_) {}
    try {
        await chrome.debugger.sendCommand(debuggee, 'Page.setWebLifecycleState', {
            state: 'active',
        });
    } catch (_) {}
}

async function ensureAttached(debuggee) {
    const key = debuggeeKey(debuggee);
    if (!attached.has(key)) {
        try {
            await chrome.debugger.attach(debuggee, '1.3');
        } catch (err) {
            const msg = String(err?.message || err);
            if (!/already attached/i.test(msg)) throw err;
        }
        attached.set(key, debuggee);
    }
    await emulateFocusedPage(debuggee);
    return debuggee;
}

async function attachFocusForSender(sender) {
    const list = await findFocusDebuggees(sender);
    for (const d of list) {
        try {
            await ensureAttached(d);
        } catch (_) {}
    }
    return list;
}

async function reassertFocus() {
    for (const debuggee of attached.values()) {
        await emulateFocusedPage(debuggee);
    }
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

chrome.tabs.onActivated.addListener(() => {
    void reassertFocus();
});

chrome.windows.onFocusChanged.addListener(() => {
    void reassertFocus();
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg && msg.type === 'hudBus' && sender.tab?.id != null) {
        chrome.tabs.sendMessage(sender.tab.id, {
            type: 'hudBus',
            payload: msg.payload,
        }, () => { void chrome.runtime.lastError; });
        sendResponse({ ok: true });
        return true;
    }
    if (!msg || (msg.type !== 'trustedClick' && msg.type !== 'attachDebugger')) {
        return false;
    }
    (async () => {
        await attachFocusForSender(sender);
        if (msg.type === 'attachDebugger') {
            sendResponse({ ok: true });
            return;
        }
        const debuggee = await ensureAttached(await findDebuggee(sender));
        await dispatchClick(debuggee, msg.x, msg.y, msg.gapMs);
        sendResponse({ ok: true });
    })().catch((err) => {
        sendResponse({ ok: false, error: String(err?.message || err) });
    });
    return true;
});
