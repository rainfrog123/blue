'use strict';

(function (global) {
    const SB = window.__SB;
    const VERSION = SB.VERSION;

    SB.maskPageFocus();
    try {
        window.postMessage({
            source: 'sb-page',
            type: 'attachDebugger',
            id: `sb-attach-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        }, '*');
    } catch (_) {}

    const isMultibaccarat = /pragmaticplaylive\.net\/desktop\/multibaccarat/i.test(String(location.href || ''));
    const isStakeHost = /(?:^|\.)stake\.com$/i.test(String(location.hostname || ''));
    const isTopWindow = window === window.top;

    if (!isMultibaccarat) {
        if (isStakeHost && isTopWindow) {
            const kick = () => {
                setInterval(() => {
                    const bal = SB.readDomWallet();
                    if (bal > 0) SB.hudBusSend({ kind: 'wallet', balance: bal });
                }, 800);
            };
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', kick, { once: true });
            } else {
                kick();
            }
            global.sb = { version: VERSION, focusOnly: true, walletRelay: true };
            console.log(`[SB] v${VERSION} · extension · focus + wallet relay (${location.host})`);
        } else {
            global.sb = { version: VERSION, focusOnly: true };
            console.log(`[SB] v${VERSION} · extension · focus mask + CDP focus emulation (${location.host})`);
        }
        return;
    }

    try {
        const util = SB.util;
        const pp = SB.createPp();
        const pick = SB.createPick(pp);
        const play = SB.createPlay(pp, pick);

        global.pp = pp;
        global.pick = pick;
        global.play = play;
        global.sb = { version: VERSION, util, pp, pick, play };

        console.log(`[SB] v${VERSION} · extension · pp + pick + play HUD · trusted CDP clicks · sb.version`);
    } catch (err) {
        console.error(`[SB] v${VERSION} · HUD boot failed`, err);
    }
})(typeof window !== 'undefined' ? window : this);
