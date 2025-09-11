// ==UserScript==
// @name         auto-read
// @description  Auto-clicks the Read Aloud (朗读) button after each new assistant answer
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

  // Click read aloud using the new method (via More actions menu)
  const clickReadAloud = async () => {
    // Find all visible "More actions" buttons
    const allBtns = Array.from(document.querySelectorAll(
      'button[aria-label="More actions"], button[id^="radix-"][aria-haspopup="menu"]'
    )).filter(el => {
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    });

    // Use the second-to-last one (usually the newest assistant message)
    const btn = allBtns.at(-2);
    if (!btn) return false;

    // Check if already processed
    if (btn.dataset._autoVoiceClicked) return false;
    btn.dataset._autoVoiceClicked = '1';

    // Click More actions button
    let res = simulatePointerSequence(btn);
    
    // Handle overlays
    if (res.topAtPoint && res.topAtPoint !== btn) {
      const prev = res.topAtPoint.style.pointerEvents;
      res.topAtPoint.style.pointerEvents = 'none';
      res = simulatePointerSequence(btn);
      res.topAtPoint.style.pointerEvents = prev;
    }

    // Keyboard fallback
    ['keydown', 'keypress', 'keyup'].forEach(type =>
      btn.dispatchEvent(new KeyboardEvent(type, { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }))
    );

    // React handler fallback
    tryReactHandler(btn);

    // Wait for menu to open
    const menu = await waitFor('[role="menu"][data-state="open"]', document, 2500);
    if (!menu) return false;

    // Find "Read aloud" item
    let item = menu.querySelector('[role="menuitem"][aria-label="Read aloud"]') ||
               menu.querySelector('[data-testid="voice-play-turn-action-button"]');

    if (!item) {
      const candidates = menu.querySelectorAll('[role="menuitem"], .__menu-item, [data-radix-collection-item]');
      item = Array.from(candidates).find(el => /read\s*aloud/i.test(el.textContent || ''));
    }

    if (!item) return false;

    // Click read aloud item
    let r2 = simulatePointerSequence(item);
    if (r2.topAtPoint && r2.topAtPoint !== item) {
      const prev = r2.topAtPoint.style.pointerEvents;
      r2.topAtPoint.style.pointerEvents = 'none';
      r2 = simulatePointerSequence(item);
      r2.topAtPoint.style.pointerEvents = prev;
    }

    // Keyboard fallback for menu items
    if (document.activeElement !== item) { try { item.focus({ preventScroll: true }); } catch {} }
    ['keydown', 'keypress', 'keyup'].forEach(type =>
      item.dispatchEvent(new KeyboardEvent(type, { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }))
    );

    // Final fallback
    tryReactHandler(item);

    // After read aloud is triggered, scroll to the last edit button
    await sleep(500); // Give time for menu to close
    
    const editBtns = Array.from(document.querySelectorAll('button[aria-label="Edit message"]'));
    const lastEditBtn = editBtns.at(-1);
    if (lastEditBtn) {
      lastEditBtn.scrollIntoView({ block: 'center', inline: 'center' });
    }

    return true;
  };

  // Check for new assistant messages and trigger read aloud
  const checkForNewMessage = async () => {
    const allBtns = Array.from(document.querySelectorAll(
      'button[aria-label="More actions"], button[id^="radix-"][aria-haspopup="menu"]'
    )).filter(el => {
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    });

    const newest = allBtns.at(-2); // Second-to-last is usually newest assistant
    if (newest && !newest.dataset._autoVoiceClicked) {
      await sleep(300); // Give UI time to settle
      await clickReadAloud();
    }
  };

  // MutationObserver for detecting new content
  const obs = new MutationObserver((mutations) => {
    let shouldCheck = false;

    for (const m of mutations) {
      for (const n of m.addedNodes) {
        if (n.nodeType !== 1) continue;
        if (n.querySelector?.('button[aria-label="More actions"], button[id^="radix-"][aria-haspopup="menu"]')) {
          shouldCheck = true;
          break;
        }
      }
      if (shouldCheck) break;
    }

    if (shouldCheck) {
      setTimeout(checkForNewMessage, 120);
    }
  });

  obs.observe(document.body, { childList: true, subtree: true });
})();
