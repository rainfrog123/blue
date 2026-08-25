'use strict';

const { Plugin, MarkdownView, PluginSettingTab, Setting, Platform } = require('obsidian');

const MAX_HISTORY = 250;
const SAVE_DEBOUNCE_MS = 500;
// After a nav-intent click, wait this long before checking whether the
// position actually moved (lets the jump/scroll settle).
// 80ms is often too short for heading/block scroll in reading + live preview.
const JUMP_SETTLE_MS = 50;
const JUMP_POLL_MS = 60;
const JUMP_POLL_ATTEMPTS = 10;
// Clicks that count as navigation intent (vs. just placing the cursor):
// internal links (reading + live preview) and outline / tree items.
const NAV_CLICK_SELECTOR =
  '.internal-link, a.internal-link, .cm-hmd-internal-link, .cm-link, .tree-item-self, [data-href*="#"]';
// Search inputs whose focus means the user is about to jump: editor find
// (Cmd+F), quick switcher / command palette / heading search, and the global
// search panel. Focusing one anchors the pre-search position.
const SEARCH_INPUT_SELECTOR = '.document-search-input, .cm-search input, .prompt-input, .search-input-container input';
// After a search input blurs, keep the anchor this long so a result-click jump
// (which blurs the input before its position change registers) still consumes it.
const SEARCH_ANCHOR_GRACE_MS = 250;
const IGNORE_PATHS = new Set(['_Vault/Response Log.md']);

module.exports = class InFileNavHistory extends Plugin {
  async onload() {
    // Per-pane stacks for Alt+←/→ (this tab only). Workspace stack for
    // Shift+Alt+←/→ (can focus another tab). Entries: { leafId, path, state }.
    this.history = {};
    this.global = { back: [], fwd: [] };
    // Live position per leaf, keyed by leaf id. Not persisted — the baseline
    // used to detect when a pane's file (or, on click, position) changed.
    this.snapshots = {};
    // Most recent markdown leaf, so outline/sidebar clicks (which steal focus)
    // still resolve to the editor pane they act on.
    this.lastMarkdownLeaf = null;
    // Suppresses recording while we are programmatically navigating.
    this.navigating = false;
    this._saveTimer = null;
    // Position to record when a search drives the editor somewhere new:
    // { leafId, entry }. Captured when a search input gains focus, consumed
    // (once) the first time the editor's position actually changes.
    this.searchAnchor = null;
    this._searchClearTimer = null;
    // Pre-position for keyboard jumps (Ctrl+End/Home, PageUp/Down, etc.).
    this.keyJumpAnchor = null;

    const data = await this.loadData();
    if (data && data.history) this.history = data.history;
    if (data && data.global && (data.global.back || data.global.fwd)) {
      this.global = {
        back: Array.isArray(data.global.back) ? data.global.back : [],
        fwd: Array.isArray(data.global.fwd) ? data.global.fwd : [],
      };
    }
    this.seedLocalFromGlobal();

    // Track the active pane's live position — and detect file changes — on any
    // activity. Quick Switcher (cmd+O), command palette, graph, links to other
    // files, etc. all surface here as a path change.
    const refresh = (evt) => this.refresh(evt);
    this.registerDomEvent(document, 'mouseup', refresh, true);
    this.registerDomEvent(document, 'keyup', refresh, true);
    this.registerDomEvent(document, 'scroll', refresh, true);
    this.registerEvent(this.app.workspace.on('editor-change', refresh));
    this.registerEvent(this.app.workspace.on('active-leaf-change', refresh));
    this.registerEvent(this.app.workspace.on('file-open', refresh));

    // Same-file jumps (heading/block links, outline clicks) don't change the
    // path, so catch the originating position before the jump.
    this.registerDomEvent(document, 'click', (evt) => this.onNavClick(evt), true);

    // Keyboard jumps (Ctrl+End/Home, PageUp/Down): anchor before
    // the key moves the cursor, then record in refresh() once position changes.
    this.registerDomEvent(document, 'keydown', (evt) => this.onKeyJump(evt), true);

    // Search jumps (editor find, switcher, search panel): anchor where the
    // editor was when the search input takes focus, so we can record the
    // pre-search position rather than each incremental match.
    this.registerDomEvent(document, 'focusin', (evt) => this.onSearchFocus(evt), true);
    this.registerDomEvent(document, 'focusout', (evt) => this.onSearchBlur(evt), true);

    // No default hotkeys: per Obsidian's plugin guidelines, leave them unbound
    // so users can assign their own (e.g. Mod+[ / Mod+]) without conflicts.
    this.addCommand({
      id: 'go-back',
      name: 'Go back (cursor + scroll position)',
      callback: () => this.navigateLocal('back'),
    });

    this.addCommand({
      id: 'go-forward',
      name: 'Go forward (cursor + scroll position)',
      callback: () => this.navigateLocal('fwd'),
    });

    this.addCommand({
      id: 'go-back-any-tab',
      name: 'Go back (cursor + scroll, any tab)',
      callback: () => this.navigateGlobal('back'),
    });

    this.addCommand({
      id: 'go-forward-any-tab',
      name: 'Go forward (cursor + scroll, any tab)',
      callback: () => this.navigateGlobal('fwd'),
    });

    this.addSettingTab(new InFileNavHistorySettingTab(this.app, this));

    // Baseline existing panes and drop history for panes that no longer exist.
    this.app.workspace.onLayoutReady(() => {
      const live = new Set();
      this.app.workspace.iterateAllLeaves((leaf) => {
        live.add(leaf.id);
        if (leaf.view instanceof MarkdownView) this.lastMarkdownLeaf = leaf;
        const entry = this.entryForLeaf(leaf);
        if (entry) this.snapshots[leaf.id] = entry;
      });
      for (const id of Object.keys(this.history)) {
        if (!live.has(id)) delete this.history[id];
      }
    });
  }

  onunload() {
    if (this._saveTimer) window.clearTimeout(this._saveTimer);
    if (this._searchClearTimer) window.clearTimeout(this._searchClearTimer);
    this.saveData({ history: this.history, global: this.global });
  }

  historyCounts() {
    let back = 0;
    let fwd = 0;
    for (const stacks of Object.values(this.history || {})) {
      back += (stacks.back || []).length;
      fwd += (stacks.fwd || []).length;
    }
    return {
      back,
      fwd,
      panes: Object.keys(this.history || {}).length,
      globalBack: (this.global.back || []).length,
      globalFwd: (this.global.fwd || []).length,
    };
  }

  clearHistory() {
    this.history = {};
    this.global = { back: [], fwd: [] };
    this.snapshots = {};
    this.searchAnchor = null;
    this.keyJumpAnchor = null;
    this.saveData({ history: this.history, global: this.global });
  }

  // The markdown leaf to act on. Falls back to the last active one so clicks in
  // the outline / sidebar (which can steal focus) still target the editor.
  markdownLeaf() {
    const view = this.app.workspace.getActiveViewOfType(MarkdownView);
    if (view) {
      this.lastMarkdownLeaf = view.leaf;
      return view.leaf;
    }
    return this.lastMarkdownLeaf;
  }

  entryForLeaf(leaf) {
    if (!leaf) return null;
    const view = leaf.view;
    if (!(view instanceof MarkdownView) || !view.file) return null;
    // getEphemeralState() returns { cursor, scroll } in exactly the shape
    // setEphemeralState()/openFile's eState expects — works in reading and
    // editing modes alike.
    return {
      leafId: leaf.id,
      path: view.file.path,
      state: view.getEphemeralState(),
      pixelScroll: readPixelScroll(view),
    };
  }

  stacksFor(leafId) {
    if (!this.history[leafId]) this.history[leafId] = { back: [], fwd: [] };
    return this.history[leafId];
  }

  recordLocal(leafId, entry) {
    if (!leafId || !entry || isIgnoredPath(entry.path)) return;
    const stacks = this.stacksFor(leafId);
    this.pushEntry(stacks.back, entry);
    stacks.fwd.length = 0;
  }

  recordGlobal(entry) {
    if (!entry || isIgnoredPath(entry.path)) return;
    this.pushEntry(this.global.back, entry);
    this.global.fwd.length = 0;
  }

  seedLocalFromGlobal() {
    const byLeaf = {};
    for (const e of this.global.back || []) {
      if (!e || !e.leafId || isIgnoredPath(e.path)) continue;
      if (!byLeaf[e.leafId]) byLeaf[e.leafId] = [];
      byLeaf[e.leafId].push(e);
    }
    for (const [id, entries] of Object.entries(byLeaf)) {
      const stacks = this.stacksFor(id);
      if (stacks.back.length) continue;
      for (const e of entries) this.pushEntry(stacks.back, e);
    }
  }

  recordJump(leafId, entry) {
    this.recordLocal(leafId, entry);
    this.recordGlobal(entry);
    this.scheduleSave();
  }

  // Update snapshots. In-tab jumps go on the per-pane stack (Alt+←).
  // Leaving a markdown tab also goes on the workspace stack (Shift+Alt+←).
  refresh(evt) {
    if (this.navigating) return;
    const prevLeaf = this.lastMarkdownLeaf;
    const leaf = this.markdownLeaf();
    if (!leaf) return;
    const entry = this.entryForLeaf(leaf);
    if (!entry) return;

    if (prevLeaf && prevLeaf.id !== leaf.id) {
      const left = this.snapshots[prevLeaf.id] || this.entryForLeaf(prevLeaf);
      if (left) {
        this.recordGlobal(left.leafId ? left : Object.assign({}, left, { leafId: prevLeaf.id }));
        this.scheduleSave();
      }
    }

    const prev = this.snapshots[leaf.id];
    if (prev && prev.path !== entry.path) {
      this.recordJump(leaf.id, prev.leafId ? prev : Object.assign({}, prev, { leafId: leaf.id }));
      this.searchAnchor = null;
      this.keyJumpAnchor = null;
    } else if (
      this.searchAnchor &&
      this.searchAnchor.leafId === leaf.id &&
      this.searchAnchor.entry.path === entry.path &&
      !sameEntry(this.searchAnchor.entry, entry)
    ) {
      this.recordJump(leaf.id, this.searchAnchor.entry);
      this.searchAnchor = null;
      this.keyJumpAnchor = null;
    } else if (
      this.keyJumpAnchor &&
      this.keyJumpAnchor.leafId === leaf.id &&
      this.keyJumpAnchor.entry.path === entry.path &&
      !sameEntry(this.keyJumpAnchor.entry, entry)
    ) {
      this.recordJump(leaf.id, this.keyJumpAnchor.entry);
      this.keyJumpAnchor = null;
    } else if (
      evt &&
      evt.type === 'mouseup' &&
      prev &&
      prev.path === entry.path &&
      !sameEntry(prev, entry) &&
      isEditorCaretClick(evt)
    ) {
      // Plain click in the editor: remember the caret we left.
      this.recordJump(leaf.id, prev);
    }
    this.snapshots[leaf.id] = entry;
  }

  onKeyJump(evt) {
    if (this.navigating) return;
    if (!isKeyboardJumpEvent(evt)) return;
    // Ignore while typing in inputs/prompts (except the markdown editor itself).
    const t = evt.target;
    if (t && t.closest && t.closest(SEARCH_INPUT_SELECTOR)) return;
    if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable) &&
        !(t.closest && t.closest('.cm-editor, .markdown-source-view, .markdown-preview-view'))) {
      // Allow CodeMirror editor; block generic form fields.
      if (!(t.closest && t.closest('.cm-content, .cm-editor'))) return;
    }

    const leaf = this.markdownLeaf();
    if (!leaf) return;
    const entry = this.entryForLeaf(leaf);
    if (!entry) return;
    this.keyJumpAnchor = { leafId: leaf.id, entry };
    this.snapshots[leaf.id] = entry;
  }

  onSearchFocus(evt) {
    const el = evt.target;
    if (!el || !el.closest || !el.closest(SEARCH_INPUT_SELECTOR)) return;
    if (this._searchClearTimer) {
      window.clearTimeout(this._searchClearTimer);
      this._searchClearTimer = null;
    }
    const leaf = this.markdownLeaf();
    if (!leaf) return;
    const entry = this.entryForLeaf(leaf);
    if (!entry) return;
    // Anchor the editor's position before the search starts moving the cursor.
    this.searchAnchor = { leafId: leaf.id, entry };
  }

  onSearchBlur(evt) {
    const el = evt.target;
    if (!el || !el.closest || !el.closest(SEARCH_INPUT_SELECTOR)) return;
    // Keep the anchor briefly: a result click blurs the input before its
    // position change registers in refresh(). After the grace window, drop it
    // so an unrelated later cursor move isn't mistaken for a search jump.
    if (this._searchClearTimer) window.clearTimeout(this._searchClearTimer);
    this._searchClearTimer = window.setTimeout(() => {
      this.searchAnchor = null;
      this._searchClearTimer = null;
    }, SEARCH_ANCHOR_GRACE_MS);
  }

  onNavClick(evt) {
    const el = evt.target;
    if (!el || !el.closest) return;
    const link = el.closest(NAV_CLICK_SELECTOR);
    if (!link) return;
    const leaf = this.markdownLeaf();
    if (!leaf) return;
    const before = this.entryForLeaf(leaf);
    if (!before) return;
    // Anchor the pre-jump position so a cross-file jump records exactly this.
    this.snapshots[leaf.id] = before;

    const href = (link.getAttribute('data-href') || link.getAttribute('href') || '').trim();
    const isInFileTarget =
      href.startsWith('#') ||
      href.includes('#') ||
      link.classList.contains('tree-item-self');

    let attempts = 0;
    const tryRecord = () => {
      if (this.navigating) return true;
      const after = this.entryForLeaf(leaf);
      if (!after) return false;
      // Cross-file jumps are recorded by refresh() via the path change; here we
      // only handle same-file jumps, and only if the position actually moved.
      if (after.path === before.path && !sameEntry(before, after)) {
        this.recordJump(leaf.id, before);
        return true;
      }
      return false;
    };

    // Poll: heading scroll often lands after the original 80ms settle window.
    const poll = () => {
      if (tryRecord()) return;
      attempts += 1;
      if (attempts < JUMP_POLL_ATTEMPTS) {
        window.setTimeout(poll, JUMP_POLL_MS);
        return;
      }
      // Last resort for in-file targets: record pre-click position even if
      // ephemeral state did not visibly change (some reading-mode jumps).
      if (isInFileTarget) {
        this.recordJump(leaf.id, before);
      }
    };
    window.setTimeout(poll, JUMP_SETTLE_MS);
  }

  pushEntry(stack, entry) {
    if (!entry) return;
    const top = stack[stack.length - 1];
    if (sameEntry(top, entry)) return;
    stack.push(entry);
    if (stack.length > MAX_HISTORY) stack.shift();
  }

  async navigateLocal(direction) {
    const leaf = this.markdownLeaf();
    if (!leaf) return;
    this.seedLocalFromGlobal();
    const stacks = this.stacksFor(leaf.id);
    const from = direction === 'back' ? stacks.back : stacks.fwd;
    const to = direction === 'back' ? stacks.fwd : stacks.back;
    if (from.length === 0) return;

    const current = this.entryForLeaf(leaf);
    const target = from.pop();
    if (current) this.pushEntry(to, current);

    this.searchAnchor = null;
    this.keyJumpAnchor = null;
    this.navigating = true;
    try {
      if (current && current.path === target.path) {
        restoreView(leaf.view, target);
      } else {
        const file = this.app.vault.getAbstractFileByPath(target.path);
        if (file) {
          await leaf.openFile(file, { eState: target.state, active: true });
          restoreView(leaf.view, target);
        }
      }
      this.snapshots[leaf.id] = Object.assign({}, target, { leafId: leaf.id });
      this.scheduleSave();
    } finally {
      window.setTimeout(() => {
        this.navigating = false;
      }, 180);
    }
  }

  async navigateGlobal(direction) {
    const from = direction === 'back' ? this.global.back : this.global.fwd;
    const to = direction === 'back' ? this.global.fwd : this.global.back;
    if (!from.length) return;

    const currentLeaf = this.markdownLeaf();
    const current = currentLeaf ? this.entryForLeaf(currentLeaf) : null;
    const target = from.pop();
    if (current) this.pushEntry(to, current);

    this.searchAnchor = null;
    this.keyJumpAnchor = null;
    this.navigating = true;
    try {
      const dest = this.resolveRestoreLeaf(target) || currentLeaf;
      if (!dest) return;
      const file = this.app.vault.getAbstractFileByPath(target.path);
      try {
        if (typeof this.app.workspace.revealLeaf === 'function') {
          await this.app.workspace.revealLeaf(dest);
        }
      } catch (_) {}
      this.app.workspace.setActiveLeaf(dest, { focus: true });
      const view = dest.view;
      if (view instanceof MarkdownView && view.file && view.file.path === target.path) {
        restoreView(view, target);
      } else if (file) {
        await dest.openFile(file, { eState: target.state, active: true });
        restoreView(dest.view, target);
      }
      this.lastMarkdownLeaf = dest;
      this.snapshots[dest.id] = Object.assign({}, target, { leafId: dest.id });
      this.scheduleSave();
    } finally {
      window.setTimeout(() => {
        this.navigating = false;
      }, 180);
    }
  }

  resolveRestoreLeaf(target) {
    if (!target) return null;
    let byId = null;
    let byPath = null;
    this.app.workspace.iterateAllLeaves((leaf) => {
      if (!(leaf.view instanceof MarkdownView)) return;
      if (!byId && target.leafId && leaf.id === target.leafId) byId = leaf;
      if (!byPath && leaf.view.file && leaf.view.file.path === target.path) byPath = leaf;
    });
    if (byId && byId.view.file && byId.view.file.path === target.path) return byId;
    if (byPath) return byPath;
    if (byId) return byId;
    return null;
  }

  scheduleSave() {
    if (this._saveTimer) window.clearTimeout(this._saveTimer);
    this._saveTimer = window.setTimeout(() => {
      this._saveTimer = null;
      this.saveData({ history: this.history, global: this.global });
    }, SAVE_DEBOUNCE_MS);
  }
};

function readPixelScroll(view) {
  const el = scrollerFor(view);
  if (!el) return null;
  return { top: el.scrollTop, left: el.scrollLeft };
}

function scrollerFor(view) {
  if (!view) return null;
  const cm = view.editor && view.editor.cm;
  if (cm && cm.scrollDOM) return cm.scrollDOM;
  const root = view.contentEl || view.containerEl;
  if (!root || !root.querySelector) return null;
  return (
    root.querySelector('.cm-scroller') ||
    root.querySelector('.markdown-preview-view') ||
    null
  );
}

function writePixelScroll(view, pix) {
  if (!view || !pix || typeof pix.top !== 'number') return;
  const el = scrollerFor(view);
  if (!el) return;
  el.scrollTop = pix.top;
  if (typeof pix.left === 'number') el.scrollLeft = pix.left;
}

function restoreView(view, entry) {
  if (!view || typeof view.setEphemeralState !== 'function') return;
  const state = (entry && entry.state) || {};
  view.setEphemeralState(state);
  const paint = () => {
    try {
      if (typeof state.scroll === 'number' && view.currentMode && typeof view.currentMode.applyScroll === 'function') {
        view.currentMode.applyScroll(state.scroll);
      }
    } catch (_) {}
    writePixelScroll(view, entry && entry.pixelScroll);
  };
  paint();
  if (typeof requestAnimationFrame === 'function') {
    requestAnimationFrame(() => {
      paint();
      requestAnimationFrame(paint);
    });
  }
  window.setTimeout(paint, 40);
  window.setTimeout(paint, 100);
  window.setTimeout(paint, 160);
}

function isIgnoredPath(path) {
  return IGNORE_PATHS.has(String(path || ''));
}

function isEditorCaretClick(evt) {
  const t = evt && evt.target;
  if (!t || !t.closest) return false;
  if (t.closest(NAV_CLICK_SELECTOR)) return false;
  if (t.closest(SEARCH_INPUT_SELECTOR)) return false;
  return !!(t.closest('.cm-editor, .cm-content, .markdown-source-view, .markdown-preview-view'));
}

function sameEntry(a, b) {
  return (
    !!a &&
    !!b &&
    a.path === b.path &&
    (!a.leafId || !b.leafId || a.leafId === b.leafId) &&
    JSON.stringify(a.state) === JSON.stringify(b.state)
  );
}

function isKeyboardJumpEvent(evt) {
  const key = evt.key;
  const mod = evt.ctrlKey || evt.metaKey;
  if (mod && (key === 'Home' || key === 'End')) return true;
  if (key === 'PageUp' || key === 'PageDown') return true;
  return false;
}

class InFileNavHistorySettingTab extends PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  display() {
    const { containerEl } = this;
    containerEl.empty();

    containerEl.createEl('h2', { text: 'In-File Navigation History' });

    containerEl.createEl('p', {
      text: 'Alt+← / Alt+→ restore cursor in this tab. Shift+Alt+← / Shift+Alt+→ can also focus another tab.',
    });

    const counts = this.plugin.historyCounts();
    new Setting(containerEl)
      .setName('History status')
      .setDesc(
        `This tab — back: ${counts.back} · forward: ${counts.fwd} · panes: ${counts.panes}. Any tab — back: ${counts.globalBack} · forward: ${counts.globalFwd}`
      );

    containerEl.createEl('h3', { text: 'Hotkeys' });

    this.addHotkeySetting(
      containerEl,
      'Go back (this tab)',
      'in-file-nav-history:go-back',
      'Restore previous cursor + scroll in this tab'
    );
    this.addHotkeySetting(
      containerEl,
      'Go forward (this tab)',
      'in-file-nav-history:go-forward',
      'Restore next cursor + scroll in this tab'
    );
    this.addHotkeySetting(
      containerEl,
      'Go back (any tab)',
      'in-file-nav-history:go-back-any-tab',
      'Restore previous caret; may switch tabs'
    );
    this.addHotkeySetting(
      containerEl,
      'Go forward (any tab)',
      'in-file-nav-history:go-forward-any-tab',
      'Restore next caret; may switch tabs'
    );

    new Setting(containerEl)
      .setName('Clear history')
      .setDesc('Wipe all saved back/forward positions (every tab).')
      .addButton((btn) =>
        btn
          .setButtonText('Clear')
          .setWarning()
          .onClick(() => {
            this.plugin.clearHistory();
            this.display();
          })
      );
  }

  addHotkeySetting(containerEl, name, commandId, desc) {
    const current = formatHotkeysForCommand(this.app, commandId);
    new Setting(containerEl)
      .setName(name)
      .setDesc(`${desc}. Current: ${current}`)
      .addButton((btn) =>
        btn.setButtonText('Change hotkey').onClick(() => {
          openHotkeySettings(this.app, commandId);
        })
      );
  }
}

function formatHotkeysForCommand(app, commandId) {
  const hm = app.hotkeyManager;
  if (!hm) return '(none)';
  const keys =
    (typeof hm.getHotkeys === 'function' && hm.getHotkeys(commandId)) ||
    (hm.customKeys && hm.customKeys[commandId]) ||
    (typeof hm.getDefaultHotkeys === 'function' && hm.getDefaultHotkeys(commandId)) ||
    (hm.defaultKeys && hm.defaultKeys[commandId]) ||
    [];
  if (!keys.length) return '(none — click Change hotkey)';
  return keys.map(formatHotkey).join(', ');
}

function formatHotkey(hk) {
  const mods = (hk.modifiers || []).map((m) => {
    if (m === 'Mod') return Platform.isMacOS ? 'Cmd' : 'Ctrl';
    return m;
  });
  const key = hk.key || '';
  return mods.length ? `${mods.join('+')}+${key}` : key;
}

function openHotkeySettings(app, commandId) {
  const command = app.commands.findCommand(commandId);
  const query = command ? command.name : 'In-File Navigation History';

  app.setting.open();
  app.setting.openTabById('hotkeys');

  // Hotkeys tab search API varies slightly across Obsidian versions.
  window.setTimeout(() => {
    const tab = app.setting.activeTab;
    if (!tab) return;
    if (typeof tab.setQuery === 'function') {
      tab.setQuery(query);
      return;
    }
    if (tab.searchComponent && typeof tab.searchComponent.setValue === 'function') {
      tab.searchComponent.setValue(query);
      if (typeof tab.updateHotkeyVisibility === 'function') tab.updateHotkeyVisibility();
      return;
    }
    if (tab.searchInputEl) {
      tab.searchInputEl.value = query;
      tab.searchInputEl.dispatchEvent(new Event('input'));
    }
  }, 50);
}

/* nosourcemap */