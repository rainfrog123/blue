(async () => {
  const TARGET = __TARGET__;
  const PROMPT = __PROMPT__;
  const log = [];
  const idx = TARGET >= 0 ? TARGET : 1;

  log.push({ step: 'start', snapshot: snapshot() });

  if (tiles().length > 0 && !tileAt(idx)) {
    return { error: 'target tile missing', idx, count: tiles().length, log };
  }
  if (tiles().length === 0) {
    return { error: 'still single-pane? split may have failed', log, snapshot: snapshot() };
  }

  const aiBefore = aiMessagesInTile(idx).length;

  let r = await selectModel(idx, /^auto/i);
  log.push({ step: 'selectAuto', ...r });
  if (r.error) return { error: r.error, log, snapshot: snapshot() };

  let ed = focusEditorIn(idx);
  if (!ed) return { error: 'no editor on NEW tile', idx, log, snapshot: snapshot() };

  document.execCommand('selectAll', false, null);
  document.execCommand('insertText', false, PROMPT);
  await sleep(120);
  if (!ed.textContent.includes(PROMPT)) return { error: 'insert failed', log, snapshot: snapshot() };

  const send = submitIn(idx);
  if (!(send && send.getAttribute('data-state') !== 'stop' && !/voice|mic/i.test(send.getAttribute('aria-label') || '')))
    return { error: 'no send on NEW tile', log, snapshot: snapshot() };
  send.click();
  log.push({ step: 'sent', prompt: PROMPT, snapshot: snapshot() });

  let planning = false;
  let planningText = null;
  for (let i = 0; i < 80; i++) {
    await sleep(200);
    const shimmer = tileAt(idx)?.querySelector('.ui-collapsible-shimmer')?.textContent || '';
    if (/planning\s+next\s+move/i.test(shimmer)) { planning = true; planningText = shimmer.trim(); break; }
  }
  log.push({ step: 'planning', planning, planningText });

  const response = await waitForAiResponse(idx, aiBefore, 90000);
  log.push({ step: 'aiResponse', ...response, snapshot: snapshot() });
  if (!response.ok) return { error: 'no ai response on NEW tile', log, snapshot: snapshot() };

  await sleep(1000);
  const stopBtn = stopInIdx(idx);
  if (stopBtn) { stopBtn.click(); log.push({ step: 'stopped' }); }
  else log.push({ step: 'stopSkipped' });

  await waitIdle(idx, 12000);
  dismissMenus();
  await sleep(300);

  r = await selectModel(idx, /Opus 4\.8 1M High/i);
  log.push({ step: 'selectOpus', ...r, snapshot: snapshot() });
  if (r.error) return { error: r.error, log, snapshot: snapshot() };

  focusEditorIn(idx);
  return {
    ok: true, idx, tileCount: tiles().length, prompt: PROMPT,
    planning, planningText, responsePreview: response.preview,
    opusModel: r.after || r.model, log, snapshot: snapshot(),
  };
})()
