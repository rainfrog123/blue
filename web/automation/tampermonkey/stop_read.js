// ==UserScript==
// @name         stop-read
// @description  Stops voice playback by clicking Stop in More actions menu - Press Alt+Z to trigger
// @match        https://chat.openai.com/*
// @match        https://chatgpt.com/*
// @match        https://www.chatgpt.com/*
// @grant        none
// ==/UserScript==

(function () {
  'use strict';

  console.log('🛑 Stop-read script loaded (Alt+Z shortcut)');

  // Emergency cleanup function
  window._stopReadCleanup = () => {
    document.querySelectorAll('[style*="pointer-events: none"]').forEach(el => {
      el.style.pointerEvents = '';
    });
    console.log('🚑 Emergency cleanup completed - pointer events restored');
  };

  const sleep = ms => new Promise(r => setTimeout(r, ms));

  function simulatePointerSequence(el) {
    const r = el.getBoundingClientRect();
    const cx = r.left + r.width / 2;
    const cy = r.top + r.height / 2;

    el.scrollIntoView({ block: 'nearest', inline: 'center' });
    // Scroll down to position between center and end
    window.scrollBy(0, 200);
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

  // Stop voice playback using the same method as auto_read (via More actions menu)
  const stopVoicePlayback = async () => {
    console.log('🛑 stopVoicePlayback called');

    // Find all copy buttons and get the last one (most recent response)
    const allCopyButtons = [...document.querySelectorAll('button[aria-label="Copy"][data-testid="copy-turn-action-button"]')];
    const lastCopyBtn = allCopyButtons.at(-1);
    
    console.log('🔍 Last copy button found:', !!lastCopyBtn, `(${allCopyButtons.length} total copy buttons)`);
    
    if (!lastCopyBtn) {
      console.log('❌ No copy buttons found');
      return false;
    }

    // Find the parent actions container (contains both Copy and More actions buttons)
    const actionsContainer = lastCopyBtn.parentElement;
    console.log('🔍 Actions container found:', !!actionsContainer);

    if (!actionsContainer) {
      console.log('❌ No actions container found');
      return false;
    }

    // Find the More actions button inside the same actions container
    const btn = actionsContainer.querySelector('button[aria-label="More actions"][aria-haspopup="menu"][id^="radix-"]');
    console.log('🔍 More actions button found:', !!btn, btn?.id);

    if (!btn) {
      console.log('🔍 More actions button not found, listing all buttons in container:');
      const allButtons = actionsContainer.querySelectorAll('button');
      allButtons.forEach((b, i) => {
        console.log(`  Button ${i}: "${b.getAttribute('aria-label')}" | ${b.tagName} | ${b.id}`);
      });
      return false;
    }

    // Click More actions button
    console.log('🖱️ Clicking More actions button');
    let res = simulatePointerSequence(btn);

    // Handle overlays with safe restoration
    let overlayEl = null;
    let origVal = null;

    try {
      if (res.topAtPoint && res.topAtPoint !== btn) {
        console.log('🚧 Overlay detected, bypassing');
        overlayEl = res.topAtPoint;
        origVal = overlayEl.style.pointerEvents;
        overlayEl.style.pointerEvents = 'none';
      }
      res = simulatePointerSequence(btn);
    } finally {
      // ALWAYS restore pointer events
      if (overlayEl && document.contains(overlayEl)) {
        overlayEl.style.pointerEvents = origVal || '';
      }
    }

    // Keyboard fallback
    console.log('⌨️ Trying keyboard fallback');
    ['keydown', 'keypress', 'keyup'].forEach(type =>
      btn.dispatchEvent(new KeyboardEvent(type, { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }))
    );

    // React handler fallback
    console.log('⚛️ Trying React handler');
    tryReactHandler(btn);

    // Wait for menu to open
    console.log('⏳ Waiting for menu to open...');
    const menu = await waitFor('[role="menu"][data-state="open"]', document, 2500);
    console.log('📋 Menu found:', !!menu);
    if (!menu) return false;

    // Find "Stop" item (same testid as Read aloud, but aria-label changes to "Stop" when playing)
    console.log('🔍 Looking for Stop item...');
    let item = menu.querySelector('[role="menuitem"][aria-label="Stop"]') ||
               menu.querySelector('[data-testid="voice-play-turn-action-button"][aria-label="Stop"]');

    if (!item) {
      console.log('🔍 Direct selectors failed, trying text search...');
      const candidates = menu.querySelectorAll('[role="menuitem"], .__menu-item, [data-radix-collection-item]');
      console.log('🔍 Menu candidates:', candidates.length);
      candidates.forEach((el, i) => console.log(`  ${i}: "${el.textContent?.trim()}" | ${el.tagName} | ${el.getAttribute('aria-label')}`));
      
      // Look for Stop by text content or aria-label
      item = Array.from(candidates).find(el => 
        el.getAttribute('aria-label')?.toLowerCase() === 'stop' ||
        el.textContent?.trim().toLowerCase() === 'stop'
      );
    }

    console.log('🛑 Stop item found:', !!item);
    if (!item) {
      console.log('❌ No Stop item found - voice might not be playing');
      return false;
    }

    // Click stop item with safe restoration
    console.log('🛑 Clicking stop item');
    let r2 = simulatePointerSequence(item);

    let overlayEl2 = null;
    let origVal2 = null;

    try {
      if (r2.topAtPoint && r2.topAtPoint !== item) {
        console.log('🚧 Overlay over stop item, bypassing');
        overlayEl2 = r2.topAtPoint;
        origVal2 = overlayEl2.style.pointerEvents;
        overlayEl2.style.pointerEvents = 'none';
        r2 = simulatePointerSequence(item);
      }
    } finally {
      // ALWAYS restore pointer events
      if (overlayEl2 && document.contains(overlayEl2)) {
        overlayEl2.style.pointerEvents = origVal2 || '';
      }
    }

    // Keyboard fallback for menu items
    console.log('⌨️ Keyboard fallback for stop item');
    if (document.activeElement !== item) { try { item.focus({ preventScroll: true }); } catch {} }
    ['keydown', 'keypress', 'keyup'].forEach(type =>
      item.dispatchEvent(new KeyboardEvent(type, { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }))
    );

    // Final fallback
    console.log('⚛️ React handler fallback for stop item');
    tryReactHandler(item);

    // Simple click fallback
    console.log('🖱️ Simple click fallback for stop item');
    item.click();

    // Visual feedback
    item.animate([
      { outline: '2px solid #ff4d4f', outlineOffset: '2px' }, 
      { outline: 'none' }
    ], { duration: 300 });

    console.log('✅ stopVoicePlayback completed successfully');
    return true;
  };


  // Debounce repeated key presses
  let lastPress = 0;
  const MIN_INTERVAL_MS = 150;

  // Keyboard shortcut: Alt+Z
  window.addEventListener(
    'keydown',
    (e) => {
      // Alt+Z (case-insensitive)
      if (!e.altKey || e.key.toLowerCase() !== 'z') return;

      const now = performance.now();
      if (now - lastPress < MIN_INTERVAL_MS) {
        console.log('⏭️ Skipping Alt+Z due to debounce');
        return;
      }
      lastPress = now;

      console.log('🎹 Alt+Z pressed, attempting to stop voice');
      e.preventDefault();
      e.stopPropagation();
      stopVoicePlayback();
    },
    { capture: true }
  );

  console.log('🎹 Alt+Z listener registered');
  
  // Expose function for manual testing
  window.__stopVoicePlayback = stopVoicePlayback;
  console.log('🔧 Debug: window.__stopVoicePlayback() available in console');

})();
