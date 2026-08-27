const {
  Plugin,
  Notice,
  MarkdownView,
  PluginSettingTab,
  Setting,
  Platform,
} = require("obsidian");

const DEFAULT_SETTINGS = {
  emptyCopyMode: "full-path", // full-path | basename | basename-ext
  showNotices: true,
  pasteKeepScroll: true,
  pasteCursorAt: "start", // start | end
};

/**
 * Shortcuts are bound with a document keydown listener that only runs when
 * focus is inside the note CodeMirror editor. They are NOT registered as
 * Obsidian global hotkeys — those steal Ctrl+V from panels like jefr-cdp.
 */
module.exports = class SmartCopyPlugin extends Plugin {
  async onload() {
    await this.loadSettings();

    // Palette-only (no default hotkeys — see registerEditorScopedKeys)
    this.addCommand({
      id: "smart-copy",
      name: "Copy selection or full path",
      checkCallback: (checking) => {
        if (!this.isMarkdownEditorFocused()) return false;
        if (!checking) this.smartCopy();
        return true;
      },
    });

    this.addCommand({
      id: "copy-section",
      name: "Copy current paragraph",
      checkCallback: (checking) => {
        if (!this.isMarkdownEditorFocused()) return false;
        if (!checking) this.copyParagraph();
        return true;
      },
    });

    this.addCommand({
      id: "paste-keep-view",
      name: "Paste (keep scroll position)",
      checkCallback: (checking) => {
        if (!this.isMarkdownEditorFocused()) return false;
        if (!checking) {
          const ctx = this.getFocusedEditorContext();
          if (ctx) this.pasteKeepView(ctx.editor, ctx.view);
        }
        return true;
      },
    });

    this.addCommand({
      id: "move-block-up",
      name: "Move caret to previous block",
      checkCallback: (checking) => {
        if (!this.isMarkdownEditorFocused()) return false;
        if (!checking) this.moveBlock(-1);
        return true;
      },
    });

    this.addCommand({
      id: "move-block-down",
      name: "Move caret to next block",
      checkCallback: (checking) => {
        if (!this.isMarkdownEditorFocused()) return false;
        if (!checking) this.moveBlock(1);
        return true;
      },
    });

    this.registerEditorScopedKeys();
    this.registerBlockJumpKeys();
    this.registerEditorPaste();
    this.addSettingTab(new SmartCopySettingTab(this.app, this));
  }

  /**
   * Editor-scoped Ctrl/Cmd/Alt shortcuts. Early-return without preventDefault
   * when focus is outside the markdown editor (jefr-cdp, settings, etc.),
   * except Alt+C / Alt+V which do native copy/paste in those fields.
   */
  registerEditorScopedKeys() {
    this.registerDomEvent(
      document,
      "keydown",
      (evt) => {
        if (evt.defaultPrevented) return;
        if (evt.repeat) return;
        const ctrl = evt.ctrlKey || evt.metaKey;
        const alt = evt.altKey;
        if (ctrl && alt) return;
        if (!ctrl && !alt) return;

        const key =
          evt.code === "KeyC"
            ? "c"
            : evt.code === "KeyV"
              ? "v"
              : (evt.key || "").toLowerCase();
        if (key !== "c" && key !== "v") return;

        if (this.isMarkdownEditorFocused()) {
          const ctx = this.getFocusedEditorContext();
          if (!ctx) return;

          if (key === "v" && !evt.shiftKey) {
            evt.preventDefault();
            evt.stopImmediatePropagation();
            void this.pasteKeepView(ctx.editor, ctx.view);
            return;
          }

          if (key === "c" && evt.shiftKey && ctrl) {
            evt.preventDefault();
            evt.stopImmediatePropagation();
            this.copyParagraph();
            return;
          }

          if (key === "c" && !evt.shiftKey) {
            evt.preventDefault();
            evt.stopImmediatePropagation();
            this.smartCopy();
          }
          return;
        }

        if (!alt || ctrl) return;
        if (key === "c" && !evt.shiftKey) {
          evt.preventDefault();
          evt.stopImmediatePropagation();
          this.nativeCopy();
          return;
        }
        if (key === "v" && !evt.shiftKey) {
          evt.preventDefault();
          evt.stopImmediatePropagation();
          void this.nativePaste();
        }
      },
      true
    );
  }

  registerBlockJumpKeys() {
    this.registerDomEvent(
      document,
      "keydown",
      (evt) => {
        if (evt.defaultPrevented) return;
        if (!evt.altKey || evt.ctrlKey || evt.metaKey || evt.shiftKey) return;
        const up = evt.key === "ArrowUp" || evt.code === "ArrowUp";
        const down = evt.key === "ArrowDown" || evt.code === "ArrowDown";
        if (!up && !down) return;
        if (!this.isMarkdownEditorFocused()) return;
        evt.preventDefault();
        evt.stopImmediatePropagation();
        this.moveBlock(down ? 1 : -1);
      },
      true
    );
  }

  registerEditorPaste() {
    this.registerDomEvent(
      document,
      "paste",
      (evt) => {
        if (!this.isMarkdownEditorFocused()) return;
        evt.preventDefault();
        evt.stopImmediatePropagation();
        const ctx = this.getFocusedEditorContext();
        if (ctx) void this.pasteKeepView(ctx.editor, ctx.view, evt);
      },
      true
    );
  }

  getFocusedEditorContext() {
    const view = this.app.workspace.getActiveViewOfType(MarkdownView);
    if (!view?.editor) return null;
    if (!this.isMarkdownEditorFocused()) return null;
    return { view, editor: view.editor };
  }

  /**
   * True only when the focused element lives inside the active note's
   * CodeMirror editor.
   */
  isMarkdownEditorFocused() {
    const ae = document.activeElement;
    if (!ae) return false;

    // Hard exclude known plugin / UI editables
    if (
      ae.closest?.(
        ".jefr-cdp-input, .jefr-cdp-root, .jefr-cdp-composer, .modal, .prompt, .workspace-leaf-content[data-type='jefr-cdp']"
      )
    ) {
      return false;
    }

    const tag = (ae.tagName || "").toUpperCase();
    if (tag === "TEXTAREA" || tag === "INPUT") {
      // Only allow if it's somehow inside CM (unusual)
      if (!ae.closest?.(".cm-editor")) return false;
    }

    const view = this.app.workspace.getActiveViewOfType(MarkdownView);
    if (!view) return false;

    const cm =
      view.contentEl?.querySelector?.(".cm-editor") ||
      view.containerEl?.querySelector?.(".cm-editor");
    if (cm && cm.contains(ae)) return true;

    if (ae.classList?.contains("cm-content") && view.contentEl?.contains(ae)) {
      return true;
    }

    return false;
  }

  async loadSettings() {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
  }

  async saveSettings() {
    await this.saveData(this.settings);
  }

  notice(msg) {
    if (this.settings.showNotices) new Notice(msg);
  }

  restoreCaretAndView(editor, view, from, to, scrollTop) {
    try {
      editor.setSelection(from, to);
    } catch (_) {}
    try {
      editor.focus();
    } catch (_) {}
    const scroller = this.getScroller(view);
    if (scroller && scrollTop != null) scroller.scrollTop = scrollTop;
  }

  keepViewAround(editor, view, work) {
    const scroller = this.getScroller(view);
    const scrollTop = scroller ? scroller.scrollTop : null;
    const from = editor.getCursor("from");
    const to = editor.getCursor("to");
    const restore = () =>
      this.restoreCaretAndView(editor, view, from, to, scrollTop);
    const done = work();
    restore();
    requestAnimationFrame(() => {
      restore();
      requestAnimationFrame(restore);
    });
    if (done && typeof done.then === "function") {
      done.finally(() => {
        restore();
        requestAnimationFrame(restore);
      });
    }
  }

  smartCopy() {
    const view = this.app.workspace.getActiveViewOfType(MarkdownView);
    const editor = view?.editor;

    const run = () => {
      if (editor) {
        const selected = editor.getSelection();
        if (selected && selected.length > 0) {
          return this.writeClipboard(selected);
        }
      }

      const file = this.app.workspace.getActiveFile();
      if (!file) {
        this.notice("Nothing to copy");
        return;
      }

      const text = this.resolveEmptyCopy(file);
      const p = this.writeClipboard(text);
      this.notice(
        this.settings.emptyCopyMode === "full-path"
          ? "Copied path"
          : `Copied: ${text}`
      );
      return p;
    };

    if (editor && view) this.keepViewAround(editor, view, run);
    else run();
  }

  resolveEmptyCopy(file) {
    switch (this.settings.emptyCopyMode) {
      case "basename":
        return file.basename;
      case "basename-ext":
        return file.name;
      case "full-path":
      default:
        return this.app.vault.adapter.getFullPath(file.path);
    }
  }

  copyParagraph() {
    const view = this.app.workspace.getActiveViewOfType(MarkdownView);
    const editor = view?.editor;
    if (!editor) {
      this.notice("No editor");
      return;
    }

    const { from, to } = this.getParagraphRange(editor);
    const text = editor
      .getRange(from, to)
      .replace(/\s+$/, "")
      .replace(/^\s+/, "");
    if (!text) {
      this.notice("Empty paragraph");
      return;
    }

    this.keepViewAround(editor, view, () => {
      const p = this.writeClipboard(text);
      this.notice("Copied paragraph");
      return p;
    });
  }

  async pasteKeepView(editor, view, evt) {
    if (this._pasting) return;
    this._pasting = true;
    let text = "";
    try {
      if (evt && evt.clipboardData) {
        text = evt.clipboardData.getData("text/plain") || "";
      }
      if (!text) {
        try {
          text = await navigator.clipboard.readText();
        } catch (e) {
          this.notice("Clipboard read failed — use default paste");
          return;
        }
      }
      if (text == null || text === "") return;

      const scroller = this.getScroller(view);
      const scrollTop = scroller ? scroller.scrollTop : null;
      const from = editor.getCursor("from");

      editor.replaceSelection(text);
      this.restoreCaretAndView(editor, view, from, from, scrollTop);
      requestAnimationFrame(() => {
        this.restoreCaretAndView(editor, view, from, from, scrollTop);
        requestAnimationFrame(() => {
          this.restoreCaretAndView(editor, view, from, from, scrollTop);
        });
      });
    } finally {
      window.setTimeout(() => {
        this._pasting = false;
      }, 80);
    }
  }

  getScroller(view) {
    return (
      view?.contentEl?.querySelector?.(".cm-scroller") ||
      view?.containerEl?.querySelector?.(".cm-scroller") ||
      null
    );
  }

  moveBlock(dir) {
    const ctx = this.getFocusedEditorContext();
    if (!ctx) return;
    const editor = ctx.editor;
    const last = editor.lastLine();
    const blank = (n) =>
      n < 0 || n > last || editor.getLine(n).trim() === "";
    const cur = editor.getCursor().line;
    let dest;

    if (dir > 0) {
      let n = cur;
      if (!blank(n)) while (n <= last && !blank(n)) n++;
      while (n <= last && blank(n)) n++;
      dest = n > last ? last : n;
    } else if (!blank(cur) && cur > 0 && !blank(cur - 1)) {
      let n = cur;
      while (n > 0 && !blank(n - 1)) n--;
      dest = n;
    } else {
      let n = cur;
      if (!blank(n)) n--;
      while (n >= 0 && blank(n)) n--;
      while (n > 0 && !blank(n - 1)) n--;
      dest = n < 0 ? 0 : n;
    }

    const pos = { line: dest, ch: 0 };
    editor.setCursor(pos);
    this.scrollLineForReading(ctx.view, editor, pos);
  }

  /**
   * Pin the caret line near the top of the pane (a little previous context)
   * so reading Alt+↑/↓ does not leave the cursor below the text you look at.
   */
  scrollLineForReading(view, editor, pos) {
    const scroller = this.getScroller(view);
    const cm = editor.cm;
    const pin = () => {
      try {
        const coords =
          cm && typeof cm.coordsAtPos === "function"
            ? cm.coordsAtPos(editor.posToOffset(pos))
            : null;
        if (coords && scroller) {
          const box = scroller.getBoundingClientRect();
          const lineH = Math.max(
            16,
            (coords.bottom || 0) - (coords.top || 0) || 22
          );
          const pad = lineH * 4.5;
          scroller.scrollTop += coords.top - box.top - pad;
          return;
        }
      } catch (_) {}
      try {
        editor.scrollIntoView({ from: pos, to: pos }, false);
      } catch (_) {}
    };
    requestAnimationFrame(pin);
  }

  getParagraphRange(editor) {
    const lastLine = editor.lastLine();
    let line = editor.getCursor().line;

    const isBlank = (n) => {
      if (n < 0 || n > lastLine) return true;
      return editor.getLine(n).trim() === "";
    };

    if (isBlank(line)) {
      let found = -1;
      for (let i = line - 1; i >= 0; i--) {
        if (!isBlank(i)) {
          found = i;
          break;
        }
      }
      if (found < 0) {
        for (let i = line + 1; i <= lastLine; i++) {
          if (!isBlank(i)) {
            found = i;
            break;
          }
        }
      }
      if (found < 0) {
        return {
          from: { line: 0, ch: 0 },
          to: { line: 0, ch: 0 },
        };
      }
      line = found;
    }

    let startLine = line;
    while (startLine > 0 && !isBlank(startLine - 1)) startLine--;

    let endLine = line;
    while (endLine < lastLine && !isBlank(endLine + 1)) endLine++;

    return {
      from: { line: startLine, ch: 0 },
      to: { line: endLine, ch: editor.getLine(endLine).length },
    };
  }

  async writeClipboard(text) {
    const ae = document.activeElement;
    try {
      await navigator.clipboard.writeText(text);
    } catch (_) {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.cssText = "position:fixed;left:-9999px;top:0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    } finally {
      if (ae && ae.isConnected && typeof ae.focus === "function") {
        try {
          ae.focus({ preventScroll: true });
        } catch (_) {
          ae.focus();
        }
      }
    }
  }

  nativeCopy() {
    try {
      document.execCommand("copy");
    } catch (_) {}
  }

  async nativePaste() {
    const el = document.activeElement;
    let text = "";
    try {
      text = await navigator.clipboard.readText();
    } catch (_) {
      try {
        document.execCommand("paste");
      } catch (__) {}
      return;
    }
    if (
      el &&
      (el.tagName === "TEXTAREA" || el.tagName === "INPUT") &&
      typeof el.selectionStart === "number"
    ) {
      const start = el.selectionStart;
      const end = el.selectionEnd;
      const val = el.value || "";
      el.value = val.slice(0, start) + text + val.slice(end);
      const pos = start + text.length;
      el.selectionStart = el.selectionEnd = pos;
      el.dispatchEvent(new Event("input", { bubbles: true }));
      return;
    }
    if (el && el.isContentEditable) {
      document.execCommand("insertText", false, text);
    }
  }
};

class SmartCopySettingTab extends PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  display() {
    const { containerEl } = this;
    containerEl.empty();

    containerEl.createEl("h2", { text: "Smart Copy" });
    containerEl.createEl("p", {
      text: "Ctrl or Alt + C / V run while the note editor is focused. They are not Obsidian global hotkeys, so jefr-cdp and other panels keep native paste/copy. Alt+C / Alt+V also copy/paste in those fields.",
    });

    containerEl.createEl("h3", { text: "Ctrl+C — empty selection" });

    new Setting(containerEl)
      .setName("Copy when nothing is selected")
      .setDesc("What Ctrl+C copies if the editor has no selection.")
      .addDropdown((dd) =>
        dd
          .addOption("full-path", "Full system path")
          .addOption("basename", "File name (no extension)")
          .addOption("basename-ext", "File name with .md")
          .setValue(this.plugin.settings.emptyCopyMode)
          .onChange(async (v) => {
            this.plugin.settings.emptyCopyMode = v;
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName("Show notices")
      .setDesc("Toast when a path or paragraph is copied.")
      .addToggle((t) =>
        t.setValue(this.plugin.settings.showNotices).onChange(async (v) => {
          this.plugin.settings.showNotices = v;
          await this.plugin.saveSettings();
        })
      );

    containerEl.createEl("h3", { text: "Ctrl+V — paste" });

    new Setting(containerEl)
      .setName("Keep scroll position")
      .setDesc(
        "After paste in the note editor, restore scroll so a long insert doesn’t jump the view."
      )
      .addToggle((t) =>
        t.setValue(this.plugin.settings.pasteKeepScroll).onChange(async (v) => {
          this.plugin.settings.pasteKeepScroll = v;
          await this.plugin.saveSettings();
        })
      );

    new Setting(containerEl)
      .setName("Caret after paste")
      .setDesc("Paste leaves the caret at the insert point. End-of-block jumps the view.")
      .addDropdown((dd) =>
        dd
          .addOption("start", "Stay (insert point)")
          .addOption("end", "End of pasted block (stock)")
          .setValue(this.plugin.settings.pasteCursorAt)
          .onChange(async (v) => {
            this.plugin.settings.pasteCursorAt = v;
            await this.plugin.saveSettings();
          })
      );

    containerEl.createEl("h3", { text: "Commands" });
    containerEl.createEl("p", {
      cls: "setting-item-description",
      text: "Do not bind these to Ctrl+V in Settings → Hotkeys — a global Mod+V hotkey will break paste in jefr-cdp. Shortcuts are already editor-scoped in the plugin.",
    });

    this.addHotkeySetting(
      containerEl,
      "Copy selection or path",
      "smart-copy:smart-copy",
      "Palette command (editor-scoped Ctrl+C already active)"
    );
    this.addHotkeySetting(
      containerEl,
      "Copy current paragraph",
      "smart-copy:copy-section",
      "Palette command (editor-scoped Ctrl+Shift+C already active)"
    );
    this.addHotkeySetting(
      containerEl,
      "Paste (keep scroll)",
      "smart-copy:paste-keep-view",
      "Palette command (editor-scoped Ctrl+V already active)"
    );
  }

  addHotkeySetting(containerEl, name, commandId, desc) {
    const current = formatHotkeysForCommand(this.app, commandId);
    new Setting(containerEl)
      .setName(name)
      .setDesc(`${desc}. Obsidian hotkey: ${current}`)
      .addButton((btn) =>
        btn.setButtonText("Open Hotkeys").onClick(() => {
          openHotkeySettings(this.app, commandId);
        })
      );
  }
}

function formatHotkeysForCommand(app, commandId) {
  const hm = app.hotkeyManager;
  if (!hm) return "(none)";
  const keys =
    (typeof hm.getHotkeys === "function" && hm.getHotkeys(commandId)) ||
    (hm.customKeys && hm.customKeys[commandId]) ||
    (typeof hm.getDefaultHotkeys === "function" &&
      hm.getDefaultHotkeys(commandId)) ||
    (hm.defaultKeys && hm.defaultKeys[commandId]) ||
    [];
  if (!keys.length) return "(none — keep it this way for Ctrl+V)";
  return keys.map(formatHotkey).join(", ");
}

function formatHotkey(hk) {
  const mods = (hk.modifiers || []).map((m) => {
    if (m === "Mod") return Platform.isMacOS ? "Cmd" : "Ctrl";
    return m;
  });
  const key = hk.key || "";
  return mods.length ? `${mods.join("+")}+${key}` : key;
}

function openHotkeySettings(app, commandId) {
  const command = app.commands.findCommand(commandId);
  const query = command ? command.name : "Smart Copy";

  app.setting.open();
  app.setting.openTabById("hotkeys");

  window.setTimeout(() => {
    const tab = app.setting.activeTab;
    if (!tab) return;
    if (typeof tab.setQuery === "function") {
      tab.setQuery(query);
      return;
    }
    if (tab.searchInputEl) {
      tab.searchInputEl.value = query;
      tab.searchInputEl.dispatchEvent(new Event("input"));
    }
  }, 100);
}
