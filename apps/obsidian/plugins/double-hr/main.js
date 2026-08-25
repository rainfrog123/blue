'use strict';

const { Plugin, MarkdownView } = require('obsidian');
const { EditorView } = require('@codemirror/view');
const { foldEffect, unfoldEffect } = require('@codemirror/language');

const SLOT_HEAD = /^#{1,2} (?:\/ )?(?:End )?(?:\w+ )?(\d+) · (.+?)\s*$/;
const CLIP_UNTITLED = /^# Clip (\d+) · ([^·]+?)\s*$/;
const CLIP_ANY = /^# Clip (\d+) · /;
const CLIP_END = /^# End Clip (\d+) · /;
const FALLBACK_TIME_FMT = 'h:mm a';

function stripBold(s) {
  return String(s || '').replace(/\*\*/g, '');
}

function timeFormat(app) {
  const inst =
    app.internalPlugins?.getEnabledPluginById?.('templates') ||
    app.internalPlugins?.plugins?.templates?.instance;
  return stripBold(inst?.options?.timeFormat || FALLBACK_TIME_FMT);
}

function formatClock(now, fmt) {
  fmt = stripBold(fmt);
  if (typeof window !== 'undefined' && window.moment) {
    return window.moment(now).format(fmt);
  }
  const h24 = now.getHours();
  const h12 = h24 % 12 || 12;
  const mm = String(now.getMinutes()).padStart(2, '0');
  const ss = String(now.getSeconds()).padStart(2, '0');
  const ap = h24 < 12 ? 'am' : 'pm';
  if (/ss/.test(fmt)) return `${h12}:${mm}:${ss} ${ap}`;
  return `${h12}:${mm} ${ap}`;
}

function nextSlotMeta(text, now, fmt) {
  let max = 0;
  for (const line of text.split('\n')) {
    const m = line.match(SLOT_HEAD);
    if (!m) continue;
    max = Math.max(max, Number(m[1]));
  }
  return { n: max + 1, clock: formatClock(now, fmt.replace(/:?ss/g, '')) };
}

function sectionStart(state, from) {
  if (from <= 0) return 0;
  const line = state.doc.lineAt(from);
  if (from === line.from) return state.doc.lineAt(from - 1).from;
  return line.from;
}

function firstEightWords(text) {
  const lines = String(text || '')
    .replace(/\r/g, '')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
  if (!lines.length) return '';
  let line = lines[0]
    .replace(/^#{1,6}\s+/, '')
    .replace(/^>\s+/, '')
    .replace(/\*\*/g, '')
    .replace(/__|[_*]/g, '')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/\\\[/g, '[')
    .replace(/\\\]/g, ']');
  const sent = (line.split(/(?<=[.!?])\s+/)[0] || line).trim();
  const words = sent.split(/\s+/).filter(Boolean);
  return words.slice(0, 8).join(' ').replace(/[.,;:]+$/, '');
}

function untitledClipLine(editor, fromLine) {
  for (let i = fromLine; i >= 0; i--) {
    const s = editor.getLine(i);
    if (CLIP_END.test(s)) return -1;
    if (CLIP_UNTITLED.test(s)) return i;
    if (CLIP_ANY.test(s)) return -1;
  }
  return -1;
}

function largestInsert(update) {
  let best = '';
  update.changes.iterChanges((_a, _b, _c, _d, text) => {
    const s = text.toString();
    if (s.length > best.length) best = s;
  });
  return best;
}

function looksLikePaste(text) {
  return text.includes('\n') || text.trim().length >= 40;
}

module.exports = class DoubleHr extends Plugin {
  onload() {
    this._saved = null;

    this.addCommand({
      id: 'insert',
      name: 'Insert foldable paste section',
      editorCallback: (editor) => {
        const to = editor.getCursor('to');
        let anchor = to.line;
        while (anchor > 0 && editor.getLine(anchor).trim() === '') anchor--;
        const from = { line: anchor, ch: editor.getLine(anchor).length };
        const { n, clock } = nextSlotMeta(
          editor.getValue(),
          new Date(),
          timeFormat(this.app),
        );
        editor.replaceRange(
          `\n\n\n---\n# Clip ${n} · ${clock}\n\n\n\n\n---\n# End Clip ${n} · ${clock}\n`,
          from,
        );
        editor.setCursor({ line: anchor + 6, ch: 0 });
      },
    });

    const remember = () => {
      const md = this.app.workspace.getActiveViewOfType(MarkdownView);
      const cm = md?.editor?.cm;
      if (!cm) return;
      this._saved = { top: cm.scrollDOM.scrollTop, t: Date.now() };
    };
    this.registerDomEvent(document, 'pointerdown', remember, true);
    this.registerDomEvent(document, 'keydown', remember, true);

    this.registerEditorExtension(
      EditorView.updateListener.of((update) => {
        if (update.docChanged) {
          const pasted = largestInsert(update);
          if (looksLikePaste(pasted)) {
            const md = this.app.workspace.getActiveViewOfType(MarkdownView);
            const editor = md?.editor;
            if (editor) {
              const fromLine = editor.getCursor('from').line;
              const head = untitledClipLine(editor, fromLine);
              const title = head >= 0 ? firstEightWords(pasted) : '';
              if (head >= 0 && title) {
                const m = editor.getLine(head).match(CLIP_UNTITLED);
                if (m) {
                  const next = `# Clip ${m[1]} · ${m[2]} · ${title}`;
                  window.setTimeout(() => {
                    if (editor.getLine(head) !== next && CLIP_UNTITLED.test(editor.getLine(head))) {
                      editor.setLine(head, next);
                    }
                  }, 0);
                }
              }
            }
          }
        }

        let range = null;
        let n = 0;
        let unfolded = false;
        for (const tr of update.transactions) {
          for (const e of tr.effects) {
            if (e.is(unfoldEffect) || e.is(foldEffect)) {
              n += 1;
              range = e.value;
              if (e.is(unfoldEffect)) unfolded = true;
            }
          }
        }
        if (n !== 1 || !range) return;
        const saved = this._saved;
        if (!saved || Date.now() - saved.t > 800) return;
        const view = update.view;
        const pos = sectionStart(view.state, range.from);
        const top = saved.top;
        const pinScroll = () => {
          if (!view.dom.isConnected) return;
          view.scrollDOM.scrollTop = top;
        };
        if (unfolded) {
          view.dispatch({
            selection: { anchor: pos },
            userEvent: 'select.foldpin',
          });
        }
        pinScroll();
        requestAnimationFrame(() => {
          pinScroll();
          requestAnimationFrame(pinScroll);
        });
        window.setTimeout(pinScroll, 50);
        window.setTimeout(pinScroll, 120);
      }),
    );
  }
};
