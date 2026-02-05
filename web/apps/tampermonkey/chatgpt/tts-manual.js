// ==UserScript==
// @name         TTS Trigger
// @description  Press Alt+S to trigger Read Aloud (朗读) for the latest assistant answer
// @match        https://chat.openai.com/*
// @match        https://chatgpt.com/*
// @match        https://www.chatgpt.com/*
// @grant        none
// ==/UserScript==

(function () {
  'use strict';

  const sleep = ms => new Promise(r => setTimeout(r, ms));

  function simulatePointerSequence(el) {
    const r = el.getBoundingClientRect();
    const cx = r.left + r.width / 2;
    const cy = r.top + r.height / 2;

    el.scrollIntoView({ block: 'center', inline: 'center' });
    try { el.focus({ preventScroll: true }); } catch {}

    const baseMouse = { bubbles: true, cancelable: true, view: window, clientX: cx, clientY: cy, button: 0, buttons: 1 };
    const basePtr = { ...baseMouse, pointerId: 1, pointerType: 'mouse', isPrimary: true };

    el.dispatchEvent(new PointerEvent('pointerover', basePtr));
    el.dispatchEvent(new MouseEvent('mouseover', baseMouse));
    el.dispatchEvent(new PointerEvent('pointerenter', basePtr));
    el.dispatchEvent(new MouseEvent('mouseenter', baseMouse));
    el.dispatchEvent(new PointerEvent('pointerdown', basePtr));
    el.dispatchEvent(new MouseEvent('mousedown', baseMouse));
    el.dispatchEvent(new PointerEvent('pointerup', basePtr));
    el.dispatchEvent(new MouseEvent('mouseup', baseMouse));
    el.dispatchEvent(new MouseEvent('click', baseMouse));

    return { cx, cy, topAtPoint: document.elementFromPoint(cx, cy) };
  }

  async function waitFor(sel, root = document, timeout = 2000) {
    const start = performance.now();
    let el;
    while (!(el = root.querySelector(sel))) {
      if (performance.now() - start > timeout) return null;
      await sleep(16);
    }
    return el;
  }

  function tryReactHandler(el) {
    const key = Object.keys(el).find(k => k.startsWith('__reactProps$'));
    if (!key) return false;
    const props = el[key] || {};
    const ev = { isTrusted: true, target: el, currentTarget: el, preventDefault() {}, stopPropagation() {}, nativeEvent: { isTrusted: true } };
    for (const n of ['onPointerDown', 'onClick', 'onMouseDown', 'onMouseUp', 'onKeyDown', 'onKeyUp']) {
      if (typeof props[n] === 'function') { try { props[n](ev); return true; } catch {} }
    }
    return false;
  }

  const clickReadAloud = async (copyBtn) => {
    const actionsContainer = copyBtn.parentElement;
    if (!actionsContainer) return false;

    const btn = actionsContainer.querySelector('button[aria-label="More actions"][aria-haspopup="menu"][id^="radix-"]');
    if (!btn) return false;
    let res = simulatePointerSequence(btn);

    let overlayEl = null;
    let origVal = null;

    try {
      if (res.topAtPoint && res.topAtPoint !== btn) {
        overlayEl = res.topAtPoint;
        origVal = overlayEl.style.pointerEvents;
        overlayEl.style.pointerEvents = 'none';
      }
      res = simulatePointerSequence(btn);
    } finally {
      if (overlayEl && document.contains(overlayEl)) {
        overlayEl.style.pointerEvents = origVal || '';
      }
    }

    ['keydown', 'keypress', 'keyup'].forEach(type =>
      btn.dispatchEvent(new KeyboardEvent(type, { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }))
    );

    tryReactHandler(btn);

    const menu = await waitFor('[role="menu"][data-state="open"]', document, 2500);
    if (!menu) return false;

    let item = menu.querySelector('[role="menuitem"][aria-label="Read aloud"]');

    if (!item) {
      item = menu.querySelector('[data-testid="voice-play-turn-action-button"]');
    }

    if (!item) {
      const candidates = menu.querySelectorAll('[role="menuitem"], .__menu-item, [data-radix-collection-item]');
      item = Array.from(candidates).find(el => /read\s*aloud/i.test(el.textContent || ''));
    }

    if (!item) return false;
    let r2 = simulatePointerSequence(item);

    let overlayEl2 = null;
    let origVal2 = null;

    try {
      if (r2.topAtPoint && r2.topAtPoint !== item) {
        overlayEl2 = r2.topAtPoint;
        origVal2 = overlayEl2.style.pointerEvents;
        overlayEl2.style.pointerEvents = 'none';
        r2 = simulatePointerSequence(item);
      }
    } finally {
      if (overlayEl2 && document.contains(overlayEl2)) {
        overlayEl2.style.pointerEvents = origVal2 || '';
      }
    }

    if (document.activeElement !== item) { try { item.focus({ preventScroll: true }); } catch {} }
    ['keydown', 'keypress', 'keyup'].forEach(type =>
      item.dispatchEvent(new KeyboardEvent(type, { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }))
    );

    tryReactHandler(item);

    await sleep(500);

    const allCopyButtons = [...document.querySelectorAll('button[aria-label="Copy"][data-testid="copy-turn-action-button"]')];
    const secondToLastCopyBtn = allCopyButtons.at(-2);
    if (secondToLastCopyBtn) {
      secondToLastCopyBtn.scrollIntoView({ block: 'start', inline: 'nearest' });
    }

    return true;
  };

  // Debounce repeated key presses
  let lastPress = 0;
  const MIN_INTERVAL_MS = 150;

  // Handle Alt+S keyboard shortcut
  window.addEventListener(
    'keydown',
    async (e) => {
      // Alt+S (case-insensitive)
      if (!e.altKey || e.key.toLowerCase() !== 's') return;

      const now = performance.now();
      if (now - lastPress < MIN_INTERVAL_MS) return;
      lastPress = now;
      e.preventDefault();
      e.stopPropagation();

      const allCopyButtons = document.querySelectorAll('button[aria-label="Copy"][data-testid="copy-turn-action-button"]');
      const latestCopyBtn = allCopyButtons[allCopyButtons.length - 1];
      if (latestCopyBtn) {
        await clickReadAloud(latestCopyBtn);
      }
    },
    { capture: true }
  );
})();

