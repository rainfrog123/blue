// ==UserScript==
// @name         read aloud stop
// @description  Press Alt+M to stop voice playback (finds Stop in open menu) on ChatGPT
// @namespace    gp-voice-stop
// @version      3.1.0
// @match        https://chat.openai.com/*
// @match        https://chatgpt.com/*
// @match        https://www.chatgpt.com/*
// @grant        none
// ==/UserScript==

(function () {
  'use strict';

  console.log('🛑 Voice stop script loaded (Alt+M)');

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

  const isEditable = (el) => {
    if (!el) return false;
    const tag = el.tagName?.toLowerCase();
    if (tag === 'input' || tag === 'textarea') return true;
    if (el.isContentEditable) return true;
    return false;
  };

  // Find Stop item in the already-open menu
  function findStopInOpenMenu() {
    console.log('🔍 Looking for Stop in open menu...');
    
    // Look for open menu (should already be open when voice is playing)
    const menu = document.querySelector('[role="menu"][data-state="open"]');
    if (!menu) {
      console.log('❌ No open menu found');
      return null;
    }

    console.log('📋 Found open menu, looking for Stop item...');
    
    // Primary selectors for Stop item
    let stopItem = menu.querySelector('[role="menuitem"][aria-label="Stop"]') ||
                   menu.querySelector('[data-testid="voice-play-turn-action-button"][aria-label="Stop"]');

    if (!stopItem) {
      console.log('🔍 Primary selectors failed, trying text search...');
      // Fallback: search by text content
      const candidates = menu.querySelectorAll('[role="menuitem"], .__menu-item, [data-radix-collection-item]');
      console.log('🔍 Menu candidates:', candidates.length);
      candidates.forEach((el, i) => console.log(`  ${i}: "${el.textContent?.trim()}" | ${el.tagName} | ${el.getAttribute('aria-label')}`));
      
      stopItem = Array.from(candidates).find(el => 
        el.getAttribute('aria-label')?.toLowerCase() === 'stop' ||
        el.textContent?.trim().toLowerCase() === 'stop'
      );
    }

    if (stopItem) {
      console.log('✅ Stop item found in open menu');
      return stopItem;
    }

    console.log('❌ No Stop item found in open menu');
    return null;
  }

  function clickStop() {
    console.log('🛑 clickStop called');
    
    const stopItem = findStopInOpenMenu();
    if (!stopItem) {
      console.log('❌ No Stop item found');
      return false;
    }

    console.log('🛑 Clicking Stop menu item');
    
    // Try comprehensive clicking sequence for menu item
    let res = simulatePointerSequence(stopItem);
    
    // Handle overlays
    if (res.topAtPoint && res.topAtPoint !== stopItem) {
      console.log('🚧 Overlay over Stop item, bypassing');
      const prev = res.topAtPoint.style.pointerEvents;
      res.topAtPoint.style.pointerEvents = 'none';
      res = simulatePointerSequence(stopItem);
      res.topAtPoint.style.pointerEvents = prev;
    }

    // Keyboard fallback for menu items
    console.log('⌨️ Keyboard fallback for Stop item');
    if (document.activeElement !== stopItem) { 
      try { stopItem.focus({ preventScroll: true }); } catch {} 
    }
    ['keydown', 'keypress', 'keyup'].forEach(type =>
      stopItem.dispatchEvent(new KeyboardEvent(type, { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }))
    );

    // React handler fallback
    console.log('⚛️ React handler fallback for Stop item');
    tryReactHandler(stopItem);

    // Simple click fallback
    console.log('🖱️ Simple click fallback for Stop item');
    stopItem.click();

    // Visual feedback
    stopItem.animate([
      { outline: '2px solid #ff4d4f', outlineOffset: '2px' }, 
      { outline: 'none' }
    ], { duration: 300 });

    console.log('✅ Stop item clicked successfully');
    return true;
  }

  // Debounce repeated key presses
  let lastPress = 0;
  const MIN_INTERVAL_MS = 150;

  window.addEventListener(
    'keydown',
    (e) => {
      // Alt+M (case-insensitive)
      if (!e.altKey || e.key.toLowerCase() !== 'm') return;

      // Avoid triggering while typing in fields/editors
      if (isEditable(document.activeElement)) {
        console.log('⏭️ Skipping Alt+M in editable field');
        return;
      }

      const now = performance.now();
      if (now - lastPress < MIN_INTERVAL_MS) {
        console.log('⏭️ Skipping Alt+M due to debounce');
        return;
      }
      lastPress = now;

      console.log('🎹 Alt+M pressed, attempting to stop voice');
      const clicked = clickStop();
      if (clicked) {
        e.preventDefault();
        e.stopPropagation();
      }
    },
    { capture: true }
  );

  console.log('🎹 Alt+M listener registered');
  
  // Optional: expose command in console for testing
  window.__voiceStop = clickStop;
  console.log('🔧 Debug: window.__voiceStop() available in console');
})();
