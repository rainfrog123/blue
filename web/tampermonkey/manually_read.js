// ==UserScript==
// @name         manually-read
// @description  Press Alt+Q to trigger Read Aloud (朗读) for the latest assistant answer
// @match        https://chat.openai.com/*
// @match        https://chatgpt.com/*
// @match        https://www.chatgpt.com/*
// @grant        none
// ==/UserScript==

(function () {
  'use strict';

  console.log('═══════════════════════════════════════════════════');
  console.log('🤖 Manual-read script loaded (Alt+Q to trigger)');
  console.log('📅 Loaded at:', new Date().toLocaleTimeString());
  console.log('🌐 URL:', window.location.href);
  console.log('═══════════════════════════════════════════════════');

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
    console.log('🎯 clickReadAloud called with copy button:', copyBtn);
    console.log('🔍 Copy button details:', {
      tagName: copyBtn.tagName,
      ariaLabel: copyBtn.getAttribute('aria-label'),
      testId: copyBtn.getAttribute('data-testid'),
      className: copyBtn.className
    });

    const actionsContainer = copyBtn.parentElement;
    console.log('🔍 Actions container:', actionsContainer);
    console.log('🔍 Actions container class:', actionsContainer?.className);
    
    if (!actionsContainer) {
      console.log('❌ No actions container found');
      return false;
    }

    console.log('🔍 Searching for More actions button with selector: button[aria-label="More actions"][aria-haspopup="menu"][id^="radix-"]');
    const btn = actionsContainer.querySelector('button[aria-label="More actions"][aria-haspopup="menu"][id^="radix-"]');
    console.log('🔍 More actions button found:', !!btn, btn);
    
    if (!btn) {
      console.log('❌ More actions button not found');
      console.log('🔍 All buttons in actions container:');
      const allBtns = actionsContainer.querySelectorAll('button');
      allBtns.forEach((b, i) => {
        console.log(`  Button ${i}: aria-label="${b.getAttribute('aria-label')}", id="${b.id}", aria-haspopup="${b.getAttribute('aria-haspopup')}"`);
      });
      return false;
    }

    console.log('🖱️ Clicking More actions button');
    let res = simulatePointerSequence(btn);

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
      if (overlayEl && document.contains(overlayEl)) {
        overlayEl.style.pointerEvents = origVal || '';
      }
    }

    console.log('⌨️ Keyboard fallback');
    ['keydown', 'keypress', 'keyup'].forEach(type =>
      btn.dispatchEvent(new KeyboardEvent(type, { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }))
    );

    console.log('⚛️ React handler');
    tryReactHandler(btn);

    console.log('⏳ Waiting for menu with selector: [role="menu"][data-state="open"]');
    const menu = await waitFor('[role="menu"][data-state="open"]', document, 2500);
    console.log('📋 Menu element:', menu);
    
    if (!menu) {
      console.log('❌ Menu not found - checking for any menus...');
      const anyMenus = document.querySelectorAll('[role="menu"]');
      console.log(`🔍 Found ${anyMenus.length} menus in total (any state)`);
      anyMenus.forEach((m, i) => {
        console.log(`  Menu ${i}: data-state="${m.getAttribute('data-state')}", id="${m.id}"`);
      });
      return false;
    }

    console.log('✅ Menu opened successfully');
    console.log('🔍 Looking for Read aloud item...');
    console.log('🔍 Trying selector: [role="menuitem"][aria-label="Read aloud"]');
    let item = menu.querySelector('[role="menuitem"][aria-label="Read aloud"]');
    console.log('🔍 First selector result:', !!item);
    
    if (!item) {
      console.log('🔍 Trying selector: [data-testid="voice-play-turn-action-button"]');
      item = menu.querySelector('[data-testid="voice-play-turn-action-button"]');
      console.log('🔍 Second selector result:', !!item);
    }

    if (!item) {
      console.log('🔍 Trying text content search...');
      const candidates = menu.querySelectorAll('[role="menuitem"], .__menu-item, [data-radix-collection-item]');
      console.log(`🔍 Found ${candidates.length} menu item candidates`);
      candidates.forEach((el, i) => {
        console.log(`  Item ${i}: text="${el.textContent?.trim()}", aria-label="${el.getAttribute('aria-label')}", data-testid="${el.getAttribute('data-testid')}"`);
      });
      item = Array.from(candidates).find(el => /read\s*aloud/i.test(el.textContent || ''));
      console.log('🔍 Text search result:', !!item);
    }

    if (!item) {
      console.log('❌ Read aloud item not found in menu');
      return false;
    }
    
    console.log('✅ Read aloud item found:', item);

    console.log('🎵 Clicking read aloud');
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
      if (overlayEl2 && document.contains(overlayEl2)) {
        overlayEl2.style.pointerEvents = origVal2 || '';
      }
    }

    console.log('⌨️ Keyboard fallback for read aloud');
    if (document.activeElement !== item) { try { item.focus({ preventScroll: true }); } catch {} }
    ['keydown', 'keypress', 'keyup'].forEach(type =>
      item.dispatchEvent(new KeyboardEvent(type, { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }))
    );

    console.log('⚛️ React handler fallback');
    tryReactHandler(item);

    console.log('📜 Scrolling to second-to-last copy button...');
    await sleep(500);

    const allCopyButtons = [...document.querySelectorAll('button[aria-label="Copy"][data-testid="copy-turn-action-button"]')];
    const secondToLastCopyBtn = allCopyButtons.at(-2);
    if (secondToLastCopyBtn) {
      secondToLastCopyBtn.scrollIntoView({ block: 'start', inline: 'nearest' });
    }

    console.log('✅ Read aloud triggered successfully');
    return true;
  };

  // Debounce repeated key presses
  let lastPress = 0;
  const MIN_INTERVAL_MS = 150;

  // Handle Alt+Q keyboard shortcut
  window.addEventListener(
    'keydown',
    async (e) => {
      console.log(`🔍 Key pressed: key="${e.key}", altKey=${e.altKey}, ctrlKey=${e.ctrlKey}, shiftKey=${e.shiftKey}`);
      
      // Alt+Q (case-insensitive)
      if (!e.altKey || e.key.toLowerCase() !== 'q') return;

      const now = performance.now();
      if (now - lastPress < MIN_INTERVAL_MS) {
        console.log('⏭️ Skipping Alt+Q due to debounce');
        return;
      }
      lastPress = now;

      console.log('✅✅✅ Alt+Q detected! Starting read aloud process...');
      e.preventDefault();
      e.stopPropagation();

      // Find the latest copy button (last one in the DOM)
      console.log('🔍 Searching for copy buttons with selector: button[aria-label="Copy"][data-testid="copy-turn-action-button"]');
      const allCopyButtons = document.querySelectorAll('button[aria-label="Copy"][data-testid="copy-turn-action-button"]');
      console.log(`📊 Total copy buttons found: ${allCopyButtons.length}`);

      if (allCopyButtons.length > 0) {
        console.log('📋 Copy buttons details:');
        allCopyButtons.forEach((btn, idx) => {
          console.log(`  [${idx}] aria-label="${btn.getAttribute('aria-label')}", data-testid="${btn.getAttribute('data-testid')}", visible=${btn.offsetParent !== null}`);
        });
      }

      const latestCopyBtn = allCopyButtons[allCopyButtons.length - 1];

      if (!latestCopyBtn) {
        console.log('❌ No copy buttons found - trying alternative selectors...');
        const altButtons = document.querySelectorAll('button[aria-label="Copy"]');
        console.log(`🔍 Alternative search found ${altButtons.length} buttons with aria-label="Copy"`);
        return;
      }

      console.log(`✅ Using latest copy button (index ${allCopyButtons.length - 1})`);
      console.log('🚀 Calling clickReadAloud...');
      const result = await clickReadAloud(latestCopyBtn);
      console.log(`🏁 clickReadAloud completed with result: ${result}`);
    },
    { capture: true }
  );

  console.log('🎹 Alt+Q listener registered');

  // Expose function for manual testing
  window.__clickReadAloud = async () => {
    const allCopyButtons = document.querySelectorAll('button[aria-label="Copy"][data-testid="copy-turn-action-button"]');
    const latestCopyBtn = allCopyButtons[allCopyButtons.length - 1];
    if (latestCopyBtn) {
      return await clickReadAloud(latestCopyBtn);
    }
    console.log('❌ No copy buttons found');
    return false;
  };
  console.log('🔧 Debug: window.__clickReadAloud() available in console');

  console.log('═══════════════════════════════════════════════════');
  console.log('✅ Ready! Press Alt+Q to trigger read aloud for the latest message');
  console.log('═══════════════════════════════════════════════════');
})();

