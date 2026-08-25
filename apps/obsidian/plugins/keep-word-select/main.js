'use strict';

const { Plugin, MarkdownView } = require('obsidian');
const { EditorSelection } = require('@codemirror/state');

function wordish(state, sel) {
  if (sel.empty) return false;
  const trimmed = state.doc.sliceString(sel.from, sel.to).trim();
  return trimmed.length > 0 && !/\s/.test(trimmed);
}

function moveHead(view, head, goingLeft, byGroup) {
  const range = EditorSelection.cursor(head);
  if (byGroup && typeof view.moveByGroup === 'function') {
    return view.moveByGroup(range, !goingLeft).head;
  }
  if (!byGroup && typeof view.moveByChar === 'function') {
    return view.moveByChar(range, !goingLeft).head;
  }
  const doc = view.state.doc;
  if (!byGroup) {
    return goingLeft ? Math.max(0, head - 1) : Math.min(doc.length, head + 1);
  }
  return fallbackGroup(doc, head, goingLeft);
}

function fallbackGroup(doc, pos, goingLeft) {
  const line = doc.lineAt(pos);
  const text = line.text;
  let i = pos - line.from;
  const letter = /[\p{L}\p{N}_']/u;

  if (goingLeft) {
    if (i <= 0) return Math.max(0, line.from - (line.from > 0 ? 1 : 0));
    i -= 1;
    while (i > 0 && /\s/.test(text[i])) i -= 1;
    if (letter.test(text[i] || '')) {
      while (i > 0 && letter.test(text[i - 1])) i -= 1;
    } else {
      while (i > 0 && text[i - 1] && !/\s/.test(text[i - 1]) && !letter.test(text[i - 1])) {
        i -= 1;
      }
    }
    return line.from + i;
  }

  if (i >= text.length) {
    return line.to < doc.length ? line.to + 1 : doc.length;
  }
  if (letter.test(text[i] || '')) {
    while (i < text.length && letter.test(text[i])) i += 1;
  } else if (text[i] && !/\s/.test(text[i])) {
    while (i < text.length && text[i] && !/\s/.test(text[i]) && !letter.test(text[i])) {
      i += 1;
    }
  }
  while (i < text.length && /\s/.test(text[i])) i += 1;
  return line.from + i;
}

function extend(view, goingLeft, byGroup) {
  const sel = view.state.selection.main;
  let anchor = sel.anchor;
  let head = sel.head;

  if (wordish(view.state, sel)) {
    if (goingLeft && head >= anchor) {
      anchor = sel.to;
      head = sel.from;
    } else if (!goingLeft && head <= anchor) {
      anchor = sel.from;
      head = sel.to;
    }
  }

  const next = moveHead(view, head, goingLeft, byGroup);
  view.dispatch({
    selection: EditorSelection.range(anchor, next),
    scrollIntoView: true,
    userEvent: 'select',
  });
}

function shiftClickKeep(view, event) {
  if (!event.shiftKey || event.altKey || event.button !== 0) return false;
  const sel = view.state.selection.main;
  if (!wordish(view.state, sel)) return false;

  const pos = view.posAtCoords({ x: event.clientX, y: event.clientY });
  if (pos == null) return false;
  if (pos >= sel.from && pos <= sel.to) return false;

  const pin = pos < sel.from ? sel.to : sel.from;
  event.preventDefault();
  event.stopPropagation();
  view.dispatch({
    selection: EditorSelection.range(pin, pos),
    scrollIntoView: true,
    userEvent: 'select.keepword',
  });
  return true;
}

module.exports = class KeepWordSelect extends Plugin {
  onload() {
    this.registerDomEvent(document, 'keydown', (evt) => this.onDocKey(evt), true);
    this.registerDomEvent(document, 'mousedown', (evt) => this.onDocMouse(evt), true);

    this.addCommand({
      id: 'extend-left-word',
      name: 'Extend selection left (keep word)',
      editorCallback: (editor) => {
        const view = editor.cm;
        if (view) extend(view, true, true);
      },
    });

    this.addCommand({
      id: 'extend-right-word',
      name: 'Extend selection right (keep word)',
      editorCallback: (editor) => {
        const view = editor.cm;
        if (view) extend(view, false, true);
      },
    });

    console.log('[keep-word-select] loaded');
  }

  editorView() {
    const view = this.app.workspace.getActiveViewOfType(MarkdownView);
    return view?.editor?.cm || null;
  }

  inEditor(el) {
    if (!el) return false;
    if (
      el.closest?.(
        ".jefr-cdp-input, .jefr-cdp-root, .modal, .prompt, .workspace-leaf-content[data-type='jefr-cdp']",
      )
    ) {
      return false;
    }
    const md = this.app.workspace.getActiveViewOfType(MarkdownView);
    if (!md) return false;
    const cm =
      md.contentEl?.querySelector?.('.cm-editor') ||
      md.containerEl?.querySelector?.('.cm-editor');
    return !!(cm && cm.contains(el));
  }

  onDocKey(evt) {
    if (evt.defaultPrevented || evt.altKey || !evt.shiftKey) return;
    const key = evt.key;
    if (key !== 'ArrowLeft' && key !== 'ArrowRight' && key !== 'Left' && key !== 'Right') {
      return;
    }
    if (!this.inEditor(document.activeElement)) return;
    const view = this.editorView();
    if (!view) return;
    evt.preventDefault();
    evt.stopPropagation();
    extend(view, key === 'ArrowLeft' || key === 'Left', evt.ctrlKey || evt.metaKey);
  }

  onDocMouse(evt) {
    if (evt.defaultPrevented) return;
    if (!this.inEditor(evt.target)) return;
    const view = this.editorView();
    if (view) shiftClickKeep(view, evt);
  }
};
