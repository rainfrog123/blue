// Tile helpers — prepended before workflow scripts
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function tiles() { return [...document.querySelectorAll('.glass-agent-conversation-tiling__tile')]; }
function tileAt(i) { return tiles()[i] ?? null; }
function visMenu() {
  return [...document.querySelectorAll('[role^="menuitem"],[role="option"]')].filter(e => e.offsetParent);
}
function findMenu(txt) {
  return visMenu().find(e => e.textContent.trim().toLowerCase().startsWith(txt.toLowerCase()));
}
function stopIn(el) {
  return el?.querySelector('.ui-prompt-input-submit-button[data-state="stop"]') ?? null;
}

function focusEditor(t) {
  const ed = t?.querySelector('.tiptap.ProseMirror.ui-prompt-input-editor__input');
  if (!ed) return null;
  ed.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
  ed.focus(); ed.click();
  return ed;
}

function tileMenuTrigger(i) {
  const t = tiles()[i];
  const inTile = t?.querySelector('[aria-label="Tile actions"],.glass-agent-conversation-tiling__menu-trigger');
  if (inTile) return inTile;
  const actions = [...document.querySelectorAll('[aria-label="Tile actions"]')];
  return actions[i] ?? null;
}

async function closeTile(idx) {
  const countBefore = tiles().length;
  if (idx <= 0) return { error: 'refuse to close tile 0 (base tile)', idx };
  const trig = tileMenuTrigger(idx);
  if (!trig) return { error: 'no Tile actions', idx, countBefore };
  trig.click();
  await sleep(350);
  const close = findMenu('Close');
  if (!close) { trig.click(); return { error: 'no Close menu item', idx, countBefore }; }
  close.click();
  await sleep(900);
  return { ok: true, closed: idx, remaining: tiles().length, countBefore };
}

async function closeExtraTiles(keep) {
  const log = [];
  while (tiles().length > keep) {
    const idx = tiles().length - 1;
    if (keep >= 1 && idx < 1) break;
    const r = await closeTile(idx);
    log.push(r);
    if (r.error) return { error: r.error, count: tiles().length, log };
  }
  return { kept: tiles().length, log };
}

function dismissMenus() {
  document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true }));
}

async function waitForAiResponse(idx, beforeCount, maxMs) {
  maxMs = maxMs || 90000;
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    await sleep(300);
    const msgs = aiMessagesInTile(idx);
    if (msgs.length > beforeCount) {
      const text = latestAiText(idx);
      if (text.length > 15 && !/^Planning next move/i.test(text)) {
        return { ok: true, aiCount: msgs.length, preview: text.slice(0, 160) };
      }
    }
  }
  return { ok: false, aiCount: aiMessagesInTile(idx).length, preview: latestAiText(idx).slice(0, 160) };
}

async function waitIdle(idx, maxMs) {
  maxMs = maxMs || 15000;
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    if (!stopInIdx(idx)) return true;
    await sleep(200);
  }
  return false;
}

async function selectModel(t, namePattern) {
  const re = typeof namePattern === 'string' ? new RegExp(namePattern, 'i') : namePattern;
  let idx = typeof t === 'number' ? t : tiles().indexOf(t);
  if (idx < 0) idx = Math.max(0, tiles().length - 1);
  focusEditorIn(idx);
  await sleep(120);
  let trigger = modelTriggerIn(idx);
  let before = trigger?.querySelector('.ui-model-picker__trigger-text')?.textContent?.trim();
  if (before && re.test(before)) return { ok: true, model: before, skipped: true, idx };
  if (!trigger) return { error: 'no picker', idx };

  async function openMenu() {
    dismissMenus();
    await sleep(150);
    trigger = modelTriggerIn(idx);
    if (!trigger) return [];
    trigger.click();
    await sleep(550);
    return visMenu();
  }

  async function closeMenu() {
    trigger?.click();
    await sleep(200);
  }

  async function pickFromOpen(items) {
    const pick = (list) => list.find(e => {
      const txt = (e.textContent || '').trim();
      return re.test(txt) || re.test(txt.replace(/Edit$/i, ''));
    });
    return pick(items.filter(e => e.getAttribute('role') === 'menuitem'))
        || pick(items.filter(e => (e.getAttribute('role') || '').includes('menuitem')));
  }

  async function pickOpusFromTile0() {
    if (idx === 0) return null;
    focusEditorIn(0);
    await sleep(100);
    const refTrig = modelTriggerIn(0);
    refTrig?.click();
    await sleep(500);
    const items = visMenu();
    const opus = items.find(e => /Opus 4\.8 1M High/i.test(e.textContent.trim()));
    refTrig?.click();
    return opus ? opus.textContent.trim().replace(/\s*Edit\s*$/i, '').trim() : null;
  }

  async function clickItem(item) {
    const el = item?.querySelector?.('[role="menuitem"],button,a') || item;
    if (el && typeof el.click === 'function') { el.click(); return true; }
    return false;
  }

  let items = await openMenu();
  let item = await pickFromOpen(items);

  if (!item && /^auto/i.test(before || '') && !/^auto/i.test(re.source)) {
    // compact Auto menu — toggle Auto off via checkbox/switch inside the row
    const autoRow = items.find(e => /^auto/i.test((e.textContent || '').trim()));
    const sw = autoRow?.querySelector('button,[role="switch"],input[type="checkbox"]');
    if (sw) { sw.click(); await sleep(600); }
    else if (autoRow) { await clickItem(autoRow); await sleep(600); }
    trigger = modelTriggerIn(idx);
    before = trigger?.querySelector('.ui-model-picker__trigger-text')?.textContent?.trim();
    items = await openMenu();
    item = await pickFromOpen(items);
  }

  // still stuck in compact Auto — read exact Opus label from tile 0's full picker, retry
  if (!item && idx > 0) {
    await closeMenu();
    const opusLabel = await pickOpusFromTile0();
    if (opusLabel) {
      focusEditorIn(idx);
      await sleep(100);
      items = await openMenu();
      const loose = new RegExp(opusLabel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').split(/\s+/).slice(0, 3).join('.*'), 'i');
      item = items.find(e => loose.test(e.textContent.trim())) || await pickFromOpen(items);
    }
  }

  if (!item) {
    await closeMenu();
    // keyboard walk: open menu and arrow until pattern matches focused/highlighted item
    items = await openMenu();
    for (let n = 0; n < 12; n++) {
      items = visMenu();
      item = await pickFromOpen(items);
      if (item) break;
      document.activeElement?.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', code: 'ArrowDown', bubbles: true }));
      await sleep(120);
    }
  }

  if (!item) {
    await closeMenu();
    return { error: 'model not found', before, options: items.map(e => e.textContent.trim()) };
  }
  if (!(await clickItem(item))) return { error: 'click failed', before };
  await sleep(350);
  const after = modelTriggerIn(idx)?.querySelector('.ui-model-picker__trigger-text')?.textContent?.trim();
  return { ok: true, idx, before, after };
}

function focusTileFocusEval(idx) {
  return `(()=>{
    const ts=[...document.querySelectorAll('.glass-agent-conversation-tiling__tile')];
    if(ts.length>0){const t=ts[${idx}];const ed=t?.querySelector('.tiptap.ProseMirror.ui-prompt-input-editor__input');ed&&ed.focus();return !!ed;}
    const ed=document.querySelector('.tiptap.ProseMirror.ui-prompt-input-editor__input');ed&&ed.focus();return !!ed;
  })()`;
}
