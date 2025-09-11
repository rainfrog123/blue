// ==UserScript==
// @name         read aloud stop
// @description  Press Alt+M to click the "Stop" (voice) button on ChatGPT
// @namespace    gp-voice-stop
// @version      2.0.0
// @match        https://chat.openai.com/*
// @match        https://chatgpt.com/*
// @match        https://www.chatgpt.com/*
// @grant        none
// ==/UserScript==

(function () {
  'use strict';

  console.log('🛑 Voice stop script loaded (Alt+M)');

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

  // Find the Stop button with robust detection
  function findStopButton() {
    console.log('🔍 Looking for Stop button...');
    
    // Primary: aria-label="Stop" + data-testid
    let btn = document.querySelector(
      'button[aria-label="Stop"][data-testid="voice-play-turn-action-button"]'
    );
    if (btn) {
      console.log('✅ Stop button found via primary selector');
      return btn;
    }

    console.log('🔍 Primary selector failed, trying fallback methods...');
    
    // Fallback: same testid, check aria-label and SVG patterns
    const candidates = Array.from(
      document.querySelectorAll('button[data-testid="voice-play-turn-action-button"]')
    ).filter((b) => {
      const rect = b.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0; // visible
    });

    console.log('🔍 Found voice button candidates:', candidates.length);
    
    for (const b of candidates) {
      const aria = (b.getAttribute('aria-label') || '').toLowerCase();
      console.log(`🔍 Checking candidate: aria-label="${aria}"`);
      
      if (aria.includes('stop')) {
        console.log('✅ Stop button found via aria-label');
        return b;
      }
      
      // Extra fallback: look for square stop icon pattern
      const hasSquarePath = !!b.querySelector('svg path[fill-rule][clip-rule]');
      if (hasSquarePath) {
        console.log('✅ Stop button found via SVG pattern');
        return b;
      }
    }

    console.log('❌ No Stop button found');
    return null;
  }

  function clickStop() {
    console.log('🛑 clickStop called');
    
    const btn = findStopButton();
    if (!btn) {
      console.log('❌ No Stop button found');
      return false;
    }

    console.log('🖱️ Clicking Stop button');
    
    // Try comprehensive clicking sequence
    let res = simulatePointerSequence(btn);
    
    // Handle overlays
    if (res.topAtPoint && res.topAtPoint !== btn) {
      console.log('🚧 Overlay detected, bypassing');
      const prev = res.topAtPoint.style.pointerEvents;
      res.topAtPoint.style.pointerEvents = 'none';
      res = simulatePointerSequence(btn);
      res.topAtPoint.style.pointerEvents = prev;
    }

    // Keyboard fallback
    console.log('⌨️ Keyboard fallback for Stop');
    ['keydown', 'keypress', 'keyup'].forEach(type =>
      btn.dispatchEvent(new KeyboardEvent(type, { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }))
    );

    // React handler fallback
    console.log('⚛️ React handler fallback for Stop');
    tryReactHandler(btn);

    // Simple click fallback
    console.log('🖱️ Simple click fallback');
    btn.click();

    // Visual feedback
    btn.animate([
      { outline: '2px solid #ff4d4f', outlineOffset: '2px' }, 
      { outline: 'none' }
    ], { duration: 300 });

    console.log('✅ Stop button clicked successfully');
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
