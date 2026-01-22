(() => {
  // Collect ALL candidates, then pick the second-to-last visible one
  const all = Array.from(document.querySelectorAll(
    'button[aria-label="More actions"], button[id^="radix-"][aria-haspopup="menu"]'
  )).filter(el => {
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0; // must be visible
  });

  const btn = all.at(-2); // second-to-last
  if (!btn) {
    console.warn('No second-to-last (visible) "More actions" button found.');
    return;
  }

  // Ensure visible & focused
  btn.scrollIntoView({ block: 'center', inline: 'center' });
  try { btn.focus({ preventScroll: true }); } catch {}

  const rect = btn.getBoundingClientRect();
  const baseMouse = { bubbles: true, cancelable: true, view: window, clientX: rect.left + rect.width/2, clientY: rect.top + rect.height/2, button: 0 };
  const basePtr   = { ...baseMouse, pointerId: 1, pointerType: 'mouse', isPrimary: true };

  // Pointer/mouse sequence
  btn.dispatchEvent(new PointerEvent('pointerover', basePtr));
  btn.dispatchEvent(new MouseEvent('mouseover', baseMouse));
  btn.dispatchEvent(new PointerEvent('pointerenter', basePtr));
  btn.dispatchEvent(new MouseEvent('mouseenter', baseMouse));
  btn.dispatchEvent(new PointerEvent('pointerdown', basePtr));
  btn.dispatchEvent(new MouseEvent('mousedown', baseMouse));
  btn.dispatchEvent(new PointerEvent('pointerup', basePtr));
  btn.dispatchEvent(new MouseEvent('mouseup', baseMouse));
  btn.dispatchEvent(new MouseEvent('click', baseMouse));

  // Also try keyboard activation (Enter/Space)
  ['keydown','keypress','keyup'].forEach(type =>
    btn.dispatchEvent(new KeyboardEvent(type, { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }))
  );
  ['keydown','keypress','keyup'].forEach(type =>
    btn.dispatchEvent(new KeyboardEvent(type, { key: ' ', code: 'Space', bubbles: true, cancelable: true }))
  );

  // Handle overlay interceptors
  const top = document.elementFromPoint(baseMouse.clientX, baseMouse.clientY);
  if (top && top !== btn) {
    console.log('Another element is on top of the button:', top);
    const prev = top.style.pointerEvents;
    top.style.pointerEvents = 'none';
    btn.dispatchEvent(new PointerEvent('pointerdown', basePtr));
    btn.dispatchEvent(new MouseEvent('mousedown', baseMouse));
    btn.dispatchEvent(new PointerEvent('pointerup', basePtr));
    btn.dispatchEvent(new MouseEvent('mouseup', baseMouse));
    btn.dispatchEvent(new MouseEvent('click', baseMouse));
    top.style.pointerEvents = prev;
  }

  // Visual cue + which index we picked
  btn.style.outline = '2px solid red';
  btn.style.outlineOffset = '2px';
  console.log(`Clicked the second-to-last button (#${all.length - 1} of ${all.length}).`);
})();
