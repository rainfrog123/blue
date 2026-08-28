'use strict';

(function (SB, global) {
    const extCall = SB.extCall;
    const util = {
        displayName: (s) => String(s ?? '').replace(/_/g, ' '),
        sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
        money: SB.moneyFromText,
        ensureDebugger: async () => !!(await extCall('attachDebugger')).ok,
        trustedClick: async (clientX, clientY, gapMs) =>
            !!(await extCall('trustedClick', { x: clientX, y: clientY, gapMs })).ok,
        click: async (el, opts = {}) => {
            if (!el) return false;
            const r = el.getBoundingClientRect();
            const padX = Math.min(8, r.width * 0.2);
            const padY = Math.min(8, r.height * 0.2);
            const spanX = Math.max(1, r.width - padX * 2);
            const spanY = Math.max(1, r.height - padY * 2);
            const clientX = r.left + padX + Math.random() * spanX;
            const clientY = r.top + padY + Math.random() * spanY;
            const screenX = clientX + (global.screenX || 0);
            const screenY = clientY + (global.screenY || 0);
            const gap = opts.eventGapMs != null
                ? opts.eventGapMs
                : (4 + Math.floor(Math.random() * 18));
            if (await util.trustedClick(clientX, clientY, gap)) return true;
            await util.ensureDebugger();
            if (await util.trustedClick(clientX, clientY, gap)) return true;
            if (!util._trustedFallbackWarned) {
                util._trustedFallbackWarned = true;
                console.warn('[SB] trusted CDP click failed — synthetic dispatchEvent fallback');
            }
            const shared = {
                bubbles: true,
                cancelable: true,
                composed: true,
                view: global,
                clientX,
                clientY,
                screenX,
                screenY,
                button: 0,
                which: 1,
                pointerId: 1,
                pointerType: 'mouse',
                isPrimary: true,
            };
            const fire = (type, extra) => {
                const init = { ...shared, ...extra };
                try {
                    if (typeof PointerEvent === 'function' && type.startsWith('pointer')) {
                        el.dispatchEvent(new PointerEvent(type, init));
                        return;
                    }
                } catch (_) {}
                el.dispatchEvent(new MouseEvent(type.startsWith('pointer') ? type.replace('pointer', 'mouse') : type, init));
            };
            fire('pointerover', { buttons: 0 });
            fire('mouseover', { buttons: 0 });
            fire('pointerdown', { buttons: 1 });
            fire('mousedown', { buttons: 1 });
            if (gap > 0) await util.sleep(gap);
            fire('pointerup', { buttons: 0 });
            fire('mouseup', { buttons: 0 });
            fire('click', { buttons: 0, detail: 1 });
            return true;
        },
        esc: (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
        }[c])),
        signed: (n, digits = 2) => {
            const v = Number(n) || 0;
            return `${v > 0 ? '+' : ''}${v.toFixed(digits)}`;
        },
    };
    SB.util = util;
})(window.__SB, typeof window !== 'undefined' ? window : this);
