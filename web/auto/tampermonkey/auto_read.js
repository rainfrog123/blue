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

  console.log('🤖 Auto-read script loaded (copy button approach)');

  // Emergency cleanup function
  window._autoReadCleanup = () => {
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
  const clickReadAloud = async (copyBtn) => {
    console.log('🎯 clickReadAloud called with copy button');
    console.log('🔍 Copy button element:', copyBtn);

    // Find the parent actions container (contains both Copy and More actions buttons)
    const actionsContainer = copyBtn.parentElement;
    console.log('🔍 Actions container found:', !!actionsContainer);
    console.log('🔍 Actions container class:', actionsContainer?.className);

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

    // Check if already processed
    if (btn.dataset._autoVoiceClicked) {
      console.log('⏭️ Button already processed, skipping');
      return false;
    }
    console.log('✅ Marking button as processed');
    btn.dataset._autoVoiceClicked = '1';

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

    // Find "Read aloud" item
    console.log('🔍 Looking for Read aloud item...');
    let item = menu.querySelector('[role="menuitem"][aria-label="Read aloud"]') ||
               menu.querySelector('[data-testid="voice-play-turn-action-button"]');

    if (!item) {
      console.log('🔍 Direct selectors failed, trying text search...');
      const candidates = menu.querySelectorAll('[role="menuitem"], .__menu-item, [data-radix-collection-item]');
      console.log('🔍 Menu candidates:', candidates.length);
      candidates.forEach((el, i) => console.log(`  ${i}: "${el.textContent?.trim()}" | ${el.tagName} | ${el.getAttribute('aria-label')}`));
      item = Array.from(candidates).find(el => /read\s*aloud/i.test(el.textContent || ''));
    }

    console.log('🎵 Read aloud item found:', !!item);
    if (!item) return false;

    // Click read aloud item with safe restoration
    console.log('🎵 Clicking read aloud item');
    let r2 = simulatePointerSequence(item);

    let overlayEl2 = null;
    let origVal2 = null;

    try {
      if (r2.topAtPoint && r2.topAtPoint !== item) {
        console.log('🚧 Overlay over read aloud, bypassing');
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
    console.log('⌨️ Keyboard fallback for read aloud');
    if (document.activeElement !== item) { try { item.focus({ preventScroll: true }); } catch {} }
    ['keydown', 'keypress', 'keyup'].forEach(type =>
      item.dispatchEvent(new KeyboardEvent(type, { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }))
    );

    // Final fallback
    console.log('⚛️ React handler fallback for read aloud');
    tryReactHandler(item);

    // After read aloud is triggered, scroll to the second-to-last copy button
    console.log('📜 Scrolling to second-to-last copy button...');
    await sleep(500); // Give time for menu to close

    // Find all copy buttons and get the second-to-last one (-2)
    const allCopyButtons = [...document.querySelectorAll('button[aria-label="Copy"][data-testid="copy-turn-action-button"]')];
    const secondToLastCopyBtn = allCopyButtons.at(-2);
    console.log('📋 Second-to-last copy button found:', !!secondToLastCopyBtn, `(${allCopyButtons.length} total copy buttons)`);
    if (secondToLastCopyBtn) {
      secondToLastCopyBtn.scrollIntoView({ block: 'start', inline: 'nearest' });
    }

    console.log('✅ clickReadAloud completed successfully');
    return true;
  };

  // Check for new copy buttons and trigger read aloud
  const checkForNewCopy = async (copyBtn) => {
    console.log('🔄 checkForNewCopy called');

    // Check if this copy button was already processed
    if (copyBtn.dataset._autoProcessed) {
      console.log('⏭️ Copy button already processed');
      return;
    }

    console.log('✅ Marking copy button as processed');
    copyBtn.dataset._autoProcessed = '1';

    // Give UI time to settle
    await sleep(300);

    console.log('🚀 Triggering read aloud for new copy button...');
    await clickReadAloud(copyBtn);
  };

  // MutationObserver for detecting new copy buttons
  const obs = new MutationObserver((mutations) => {
    const newCopyButtons = [];

    for (const m of mutations) {
      for (const n of m.addedNodes) {
        if (n.nodeType !== 1) continue;

        // Check if the added node is a copy button
        if (n.matches?.('button[aria-label="Copy"][data-testid="copy-turn-action-button"]')) {
          console.log('📋 Direct copy button detected');
          newCopyButtons.push(n);
        }

        // Check if the added node contains copy buttons
        const copyBtns = n.querySelectorAll?.('button[aria-label="Copy"][data-testid="copy-turn-action-button"]');
        if (copyBtns?.length) {
          console.log('📋 Copy buttons found in added node:', copyBtns.length);
          newCopyButtons.push(...copyBtns);
        }
      }
    }

    // Process new copy buttons with extra validation
    newCopyButtons.forEach(copyBtn => {
      if (!copyBtn.dataset._autoProcessed) {
        // Double-check this is truly a new button by checking if it's visible and in viewport
        const rect = copyBtn.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0) {
          console.log('📋 New copy button detected, processing...');
          setTimeout(() => checkForNewCopy(copyBtn), 120);
        } else {
          console.log('📋 Skipping invisible copy button');
          copyBtn.dataset._autoProcessed = '1'; // Mark as processed to avoid future checks
        }
      } else {
        console.log('📋 Copy button already processed, skipping');
      }
    });
  });

  // Wait for page to fully settle, then mark existing buttons and start observing
  const initializeScript = async () => {
    // Wait for page to settle
    await sleep(2000);

    // Mark existing copy buttons as already processed
    const existingCopyButtons = document.querySelectorAll('button[aria-label="Copy"][data-testid="copy-turn-action-button"]');
    console.log(`🔧 Marking ${existingCopyButtons.length} existing copy buttons as processed`);
    existingCopyButtons.forEach(btn => btn.dataset._autoProcessed = '1');

    // Add additional delay before starting observer
    await sleep(5000);

    console.log('👁️ MutationObserver started (watching for copy buttons)');
    obs.observe(document.body, { childList: true, subtree: true });
  };

  initializeScript();
})();
