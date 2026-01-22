(async () => {
    const sleep = ms => new Promise(r => setTimeout(r, ms));
  
    function simulatePointerSequence(el) {
      const r = el.getBoundingClientRect();
      const cx = r.left + r.width / 2;
      const cy = r.top + r.height / 2;
  
      el.scrollIntoView({ block: 'center', inline: 'center' });
      try { el.focus({ preventScroll: true }); } catch {}
  
      const baseMouse = { bubbles: true, cancelable: true, view: window, clientX: cx, clientY: cy, button: 0, buttons: 1 };
      const basePtr   = { ...baseMouse, pointerId: 1, pointerType: 'mouse', isPrimary: true };
  
      // full sequence
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
      for (const n of ['onPointerDown','onClick','onMouseDown','onMouseUp','onKeyDown','onKeyUp']) {
        if (typeof props[n] === 'function') { try { props[n](ev); return true; } catch {} }
      }
      return false;
    }
  
    // --- Step 1: click the second-to-last "More actions" button ---
    const all = Array.from(document.querySelectorAll(
      'button[aria-label="More actions"], button[id^="radix-"][aria-haspopup="menu"]'
    )).filter(el => {
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0; // visible
    });
  
    const btn = all.at(-2);
    if (!btn) { console.warn('No second-to-last (visible) "More actions" button found.'); return; }
  
    const rect = btn.getBoundingClientRect();
    const baseMouseBtn = { bubbles: true, cancelable: true, view: window, clientX: rect.left + rect.width/2, clientY: rect.top + rect.height/2, button: 0 };
    const basePtrBtn   = { ...baseMouseBtn, pointerId: 1, pointerType: 'mouse', isPrimary: true };
  
    // try normal sequence
    let res = simulatePointerSequence(btn);
  
    // overlay bypass if needed
    if (res.topAtPoint && res.topAtPoint !== btn) {
      console.log('Overlay over More actions:', res.topAtPoint);
      const prev = res.topAtPoint.style.pointerEvents;
      res.topAtPoint.style.pointerEvents = 'none';
      res = simulatePointerSequence(btn);
      res.topAtPoint.style.pointerEvents = prev;
    }
  
    // keyboard fallback
    ['keydown','keypress','keyup'].forEach(type =>
      btn.dispatchEvent(new KeyboardEvent(type, { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }))
    );
  
    // as a last resort, poke React handler
    tryReactHandler(btn);
  
    // --- Step 2: wait for the open Radix menu ---
    const menu = await waitFor('[role="menu"][data-state="open"]', document, 2500);
    if (!menu) { console.warn('Open Radix menu not detected.'); return; }
  
    // --- Step 3: find "Read aloud" item and real-click it ---
    let item =
      menu.querySelector('[role="menuitem"][aria-label="Read aloud"]') ||
      menu.querySelector('[data-testid="voice-play-turn-action-button"]');
  
    if (!item) {
      const candidates = menu.querySelectorAll('[role="menuitem"], .__menu-item, [data-radix-collection-item]');
      item = Array.from(candidates).find(el => /read\s*aloud/i.test(el.textContent || ''));
    }
    if (!item) { console.warn('"Read aloud" menu item not found.'); return; }
  
    let r2 = simulatePointerSequence(item);
    if (r2.topAtPoint && r2.topAtPoint !== item) {
      console.log('Overlay over Read aloud:', r2.topAtPoint);
      const prev = r2.topAtPoint.style.pointerEvents;
      r2.topAtPoint.style.pointerEvents = 'none';
      r2 = simulatePointerSequence(item);
      r2.topAtPoint.style.pointerEvents = prev;
    }
  
    // keyboard fallback for menuitems
    if (document.activeElement !== item) { try { item.focus({ preventScroll: true }); } catch {} }
    ['keydown','keypress','keyup'].forEach(type =>
      item.dispatchEvent(new KeyboardEvent(type, { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }))
    );
  
    // final fallback
    tryReactHandler(item);
  
    // Visual cues
    btn.style.outline = '2px solid red'; btn.style.outlineOffset = '2px';
    item.style.outline = '2px solid lime'; item.style.outlineOffset = '2px';
    console.log('Clicked second-to-last More actions, then activated "Read aloud".');
  })();
  