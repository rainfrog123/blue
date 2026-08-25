"use strict";

/**
 * JEFR CDP — Obsidian plugin.
 *
 * Talks to Cursor's Agents window over Chrome DevTools Protocol (port 9222).
 * No MCP. No Cursor extension. Enter in this panel = type + Enter in the
 * focused Agents tile composer.
 */

const http = require("http");
const net = require("net");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { Plugin, ItemView, PluginSettingTab, Setting, Notice, setIcon, Scope } = require("obsidian");

const VIEW_TYPE = "jefr-cdp-view";

const PROMPT_PLAIN = "{{message}}";

/**
 * Was: No-MCP standing rules (check_messages / user-jefr loop).
 * MCP messenger configs archived 2026-08-11 — leave commented; Plain is enough.
 */
const DEFAULT_INJECT = [
  // "Standing rules for this entire conversation (every turn — do not drop mid-chat):",
  // "No MCP. Never call check_messages, ask_question, send_progress, CallMcpTool, GetMcpTools,",
  // "or any MCP / user-jefr tool. Ignore workspace rules that require an MCP loop.",
  // "Reply as normal chat text only.",
  // "",
  "{{message}}",
].join("\n");

/**
 * Response Log only. MCP ban lines commented out (files archived).
 * Bookmark id kept as bm-no-mcp-log for settings compatibility.
 */
const PROMPT_NO_MCP_LOG = [
  "Standing rules for this entire conversation (every turn — do not drop mid-chat):",
  "Response log. After every substantive reply, overwrite",
  "C:\\Users\\jar71\\obsidian\\_Vault\\Response Log.md",
  "with the FULL user-facing reply as a standalone Obsidian note — not a stub, not a chat excerpt.",
  "Follow vault Note Formatting: one H1, a one-line what-it-is, optional > [!summary] callout,",
  "## sections separated by ---, 2-column tables, callouts for asides, [[wikilinks]].",
  "The file must be readable in Obsidian without opening this chat.",
  "Skip only for STAND BY / trivial acks.",
  "",
  "{{message}}",
].join("\n");

/** Built-in prompt bookmarks (id/name/template). User can add more. */
function defaultPromptBookmarks() {
  return [
    { id: "bm-no-mcp-log", name: "Log only", template: PROMPT_NO_MCP_LOG },
    { id: "bm-no-mcp", name: "Plain (was No MCP)", template: DEFAULT_INJECT },
    { id: "bm-plain", name: "Plain", template: PROMPT_PLAIN },
  ];
}

function normalizeBookmark(raw, fallbackName) {
  const b = raw && typeof raw === "object" ? raw : {};
  return {
    id: String(b.id || makeId()),
    name: String(b.name || fallbackName || "Prompt").trim() || "Prompt",
    template: String(b.template != null ? b.template : PROMPT_PLAIN),
  };
}

/** Ensure promptBookmarks + activePromptId exist; keep injectTemplate synced. */
function normalizePromptSettings(settings) {
  let bookmarks = Array.isArray(settings.promptBookmarks)
    ? settings.promptBookmarks.map((b, i) => normalizeBookmark(b, "Prompt " + (i + 1)))
    : [];

  if (!bookmarks.length) {
    bookmarks = defaultPromptBookmarks();
    const current = String(settings.injectTemplate || "").trim();
    if (current && !bookmarks.some((b) => b.template === current)) {
      bookmarks.unshift(normalizeBookmark({ name: "Custom", template: current }));
    }
  } else {
    // Drop retired built-ins; merge/refresh current built-ins from code.
    const retired = new Set(["bm-no-mcp-short", "bm-concise"]);
    bookmarks = bookmarks.filter((b) => !retired.has(b.id));
    const byId = new Map(bookmarks.map((b) => [b.id, b]));
    for (const bi of defaultPromptBookmarks()) {
      if (!byId.has(bi.id)) {
        bookmarks.push(normalizeBookmark(bi));
      } else {
        const cur = byId.get(bi.id);
        cur.name = bi.name;
        cur.template = bi.template;
      }
    }
  }

  // De-dupe ids
  const seen = new Set();
  for (const b of bookmarks) {
    if (seen.has(b.id)) b.id = makeId();
    seen.add(b.id);
  }

  let activeId = String(settings.activePromptId || "");
  if (!bookmarks.some((b) => b.id === activeId)) {
    const byTemplate = bookmarks.find((b) => b.template === settings.injectTemplate);
    activeId = (byTemplate || bookmarks[0]).id;
  }

  const active = bookmarks.find((b) => b.id === activeId) || bookmarks[0];
  settings.promptBookmarks = bookmarks;
  settings.activePromptId = active.id;
  settings.injectTemplate = active.template;
  return settings;
}

const DEFAULT_SETTINGS = {
  cdpHost: "127.0.0.1",
  cdpPort: 9222,
  injectEnabled: false,
  injectOnNewAgent: false,
  injectTemplate: PROMPT_PLAIN,
  promptBookmarks: defaultPromptBookmarks(),
  activePromptId: "bm-plain",
  autoReconnect: true,
  pollMs: 800,
  maxHistory: 200,
  autoSendImages: true,
  // Compact mode (same idea as jefr-chat minimized): tall input, thin chrome.
  minimized: true,
  attachThumbSize: 26,
  // Context usage from Agents status bar via CDP.
  showContextUsage: true,
  /** Opt-in: briefly open the Agents context tray for used/limit tokens. Default off (avoids flicker). */
  showContextTokens: false,
  /** How often to peek the tray when showContextTokens is on (ms). */
  contextDetailMs: 8000,
};

function makeId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function getElectron() {
  try {
    return require("electron");
  } catch {
    return null;
  }
}

/** Above this size, paste via clipboard+Ctrl+V instead of Runtime.evaluate insertText. */
const PASTE_TEXT_THRESHOLD = 1500;

/** Write a data-URL image onto the native Electron clipboard. */
function writeClipboardImage(dataUrl) {
  const electron = getElectron();
  if (!electron) throw new Error("electron unavailable");
  const nativeImage = electron.nativeImage || (electron.remote && electron.remote.nativeImage);
  const clipboard = electron.clipboard || (electron.remote && electron.remote.clipboard);
  if (!nativeImage || !clipboard) throw new Error("electron clipboard/nativeImage missing");
  const img = nativeImage.createFromDataURL(dataUrl);
  if (!img || (typeof img.isEmpty === "function" && img.isEmpty())) {
    throw new Error("invalid image data");
  }
  clipboard.writeImage(img);
}

/** Write plain text onto the native Electron clipboard. */
function writeClipboardText(text) {
  const electron = getElectron();
  if (!electron) throw new Error("electron unavailable");
  const clipboard = electron.clipboard || (electron.remote && electron.remote.clipboard);
  if (!clipboard || typeof clipboard.writeText !== "function") {
    throw new Error("electron clipboard.writeText missing");
  }
  clipboard.writeText(String(text || ""));
}

/** Read bitmap from Electron clipboard as data URL, or "". */
function readClipboardImage() {
  try {
    const electron = getElectron();
    if (!electron) return "";
    const clipboard = electron.clipboard || (electron.remote && electron.remote.clipboard);
    if (!clipboard || typeof clipboard.readImage !== "function") return "";
    const img = clipboard.readImage();
    if (!img || (typeof img.isEmpty === "function" && img.isEmpty())) return "";
    return img.toDataURL() || "";
  } catch {
    return "";
  }
}

/** Read image files referenced on the clipboard (Explorer copy). */
function readClipboardFileImages() {
  const out = [];
  try {
    const electron = getElectron();
    const clip = electron && electron.clipboard;
    if (!clip) return out;
    let txt = "";
    try {
      if (typeof clip.read === "function") txt = clip.read("text/uri-list") || "";
    } catch {
      /* ignore */
    }
    if (!txt && typeof clip.readText === "function") txt = clip.readText() || "";
    if (!txt) return out;
    const imageExts = ["png", "jpg", "jpeg", "gif", "webp", "bmp"];
    const uris = txt.split(/\r?\n/).map((s) => s.trim()).filter((s) => s && s[0] !== "#");
    for (const uri of uris) {
      let p = uri;
      if (/^file:\/\//i.test(p)) {
        p = decodeURIComponent(p.replace(/^file:\/\//i, ""));
        if (/^\/[A-Za-z]:/.test(p)) p = p.slice(1);
      }
      const ext = (path.extname(p).slice(1) || "").toLowerCase();
      if (imageExts.indexOf(ext) === -1) continue;
      try {
        const buf = fs.readFileSync(p);
        const mime = ext === "jpg" || ext === "jpeg" ? "image/jpeg" : "image/" + ext;
        out.push({ dataUrl: "data:" + mime + ";base64," + buf.toString("base64"), name: path.basename(p) });
      } catch {
        /* ignore */
      }
    }
  } catch {
    /* ignore */
  }
  return out;
}

function fileToDataUrl(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result || ""));
    r.onerror = () => reject(new Error("read failed"));
    r.readAsDataURL(file);
  });
}

/* ------------------------------------------------------------------ */
/* Minimal WebSocket client (Node built-ins only)                      */
/* ------------------------------------------------------------------ */

class MiniWebSocket {
  constructor(url) {
    this.url = url;
    this.listeners = { open: [], message: [], error: [], close: [] };
    this.socket = null;
    this.buffer = Buffer.alloc(0);
    this.readyState = 0; // 0 connecting, 1 open, 2 closing, 3 closed
  }

  on(ev, fn) {
    if (this.listeners[ev]) this.listeners[ev].push(fn);
  }

  emit(ev, ...args) {
    for (const fn of this.listeners[ev] || []) {
      try {
        fn(...args);
      } catch {
        /* ignore */
      }
    }
  }

  send(data) {
    if (this.readyState !== 1 || !this.socket) throw new Error("WebSocket not open");
    const payload = Buffer.from(typeof data === "string" ? data : String(data), "utf8");
    const len = payload.length;
    const mask = crypto.randomBytes(4);
    const masked = Buffer.alloc(len);
    for (let i = 0; i < len; i++) masked[i] = payload[i] ^ mask[i % 4];
    let header;
    if (len < 126) {
      header = Buffer.alloc(2);
      header[0] = 0x81;
      header[1] = 0x80 | len;
    } else if (len < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x81;
      header[1] = 0x80 | 126;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x81;
      header[1] = 0x80 | 127;
      header.writeUInt32BE(0, 2);
      header.writeUInt32BE(len, 6);
    }
    this.socket.write(Buffer.concat([header, mask, masked]));
  }

  close() {
    this.readyState = 2;
    try {
      if (this.socket) this.socket.end();
    } catch {
      /* ignore */
    }
    this.readyState = 3;
  }

  connect() {
    return new Promise((resolve, reject) => {
      let u;
      try {
        u = new URL(this.url);
      } catch (e) {
        reject(e);
        return;
      }
      const key = crypto.randomBytes(16).toString("base64");
      const port = Number(u.port) || (u.protocol === "wss:" ? 443 : 80);
      const path = (u.pathname || "/") + (u.search || "");
      const reqHeaders = [
        `GET ${path} HTTP/1.1`,
        `Host: ${u.hostname}:${port}`,
        "Upgrade: websocket",
        "Connection: Upgrade",
        `Sec-WebSocket-Key: ${key}`,
        "Sec-WebSocket-Version: 13",
        "\r\n",
      ].join("\r\n");

      const sock = net.connect({ host: u.hostname, port }, () => {
        sock.write(reqHeaders);
      });
      this.socket = sock;

      let handshakeDone = false;
      let headerBuf = Buffer.alloc(0);

      const fail = (err) => {
        if (!handshakeDone) {
          handshakeDone = true;
          this.readyState = 3;
          reject(err);
        }
        this.emit("error", err);
      };

      sock.on("data", (chunk) => {
        if (!handshakeDone) {
          headerBuf = Buffer.concat([headerBuf, chunk]);
          const idx = headerBuf.indexOf("\r\n\r\n");
          if (idx < 0) return;
          const head = headerBuf.slice(0, idx).toString("utf8");
          const rest = headerBuf.slice(idx + 4);
          if (!/^HTTP\/1\.1 101/i.test(head)) {
            fail(new Error("WS handshake failed: " + head.split("\r\n")[0]));
            sock.destroy();
            return;
          }
          handshakeDone = true;
          this.readyState = 1;
          this.buffer = rest;
          this.emit("open");
          resolve();
          if (this.buffer.length) this._consume();
          return;
        }
        this.buffer = Buffer.concat([this.buffer, chunk]);
        this._consume();
      });

      sock.on("error", fail);
      sock.on("close", () => {
        this.readyState = 3;
        if (!handshakeDone) fail(new Error("socket closed before handshake"));
        this.emit("close");
      });

      sock.setTimeout(10000, () => {
        if (!handshakeDone) {
          fail(new Error("WS connect timeout"));
          sock.destroy();
        }
      });
    });
  }

  _consume() {
    while (this.buffer.length >= 2) {
      const b0 = this.buffer[0];
      const b1 = this.buffer[1];
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let off = 2;
      if (len === 126) {
        if (this.buffer.length < 4) return;
        len = this.buffer.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        if (this.buffer.length < 10) return;
        len = this.buffer.readUInt32BE(6);
        off = 10;
      }
      const maskLen = masked ? 4 : 0;
      if (this.buffer.length < off + maskLen + len) return;
      let payload = this.buffer.slice(off + maskLen, off + maskLen + len);
      if (masked) {
        const mask = this.buffer.slice(off, off + 4);
        payload = Buffer.from(payload);
        for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
      }
      this.buffer = this.buffer.slice(off + maskLen + len);
      if (opcode === 0x8) {
        this.close();
        return;
      }
      if (opcode === 0x9) {
        // ping → pong
        try {
          const frame = Buffer.alloc(2 + payload.length);
          frame[0] = 0x8a;
          frame[1] = payload.length;
          payload.copy(frame, 2);
          this.socket.write(frame);
        } catch {
          /* ignore */
        }
        continue;
      }
      if (opcode === 0x1 || opcode === 0x2) {
        this.emit("message", opcode === 0x1 ? payload.toString("utf8") : payload);
      }
    }
  }
}

/* ------------------------------------------------------------------ */
/* CDP session                                                         */
/* ------------------------------------------------------------------ */

class CdpSession {
  constructor() {
    this.ws = null;
    this.id = 0;
    this.pending = new Map();
    this.wsUrl = null;
    this.pageTitle = null;
    /** Optional hook when a call times out / socket is force-closed as dead. */
    this.onDead = null;
  }

  get connected() {
    return !!(this.ws && this.ws.readyState === 1);
  }

  async connect(wsUrl, pageTitle) {
    await this.close();
    this.wsUrl = wsUrl;
    this.pageTitle = pageTitle || null;
    const ws = new MiniWebSocket(wsUrl);
    this.ws = ws;
    ws.on("message", (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw);
      } catch {
        return;
      }
      if (typeof msg.id === "number" && this.pending.has(msg.id)) {
        const { resolve } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        resolve(msg);
      }
    });
    ws.on("close", () => {
      for (const { reject } of this.pending.values()) reject(new Error("CDP closed"));
      this.pending.clear();
    });
    await ws.connect();
    await this.call("Runtime.enable");
  }

  async call(method, params, timeoutMs = 10000) {
    if (!this.connected) throw new Error("CDP not connected");
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        // Half-open / stuck target: drop the socket so the next ensureCdp() reconnects.
        const onDead = this.onDead;
        void this.close();
        if (typeof onDead === "function") {
          try {
            onDead();
          } catch {
            /* ignore */
          }
        }
        reject(new Error("CDP timeout: " + method));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (msg) => {
          clearTimeout(timer);
          resolve(msg);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
      });
      try {
        this.ws.send(JSON.stringify({ id, method, params: params || {} }));
      } catch (e) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(e);
      }
    });
  }

  async evaluate(expression, awaitPromise = true, timeoutMs = 10000) {
    const resp = await this.call(
      "Runtime.evaluate",
      {
        expression,
        returnByValue: true,
        awaitPromise,
        userGesture: true,
      },
      timeoutMs,
    );
    if (resp.result && resp.result.exceptionDetails) {
      throw new Error("JS exception in page");
    }
    return resp.result && resp.result.result ? resp.result.result.value : undefined;
  }

  async pressKey(key, code, vk, mods = {}) {
    let modifiers = 0;
    if (mods.alt) modifiers |= 1;
    if (mods.ctrl) modifiers |= 2;
    if (mods.meta) modifiers |= 4;
    if (mods.shift) modifiers |= 8;
    const base = {
      modifiers,
      key,
      code,
      windowsVirtualKeyCode: vk,
      nativeVirtualKeyCode: vk,
    };
    // Match automation/cdp.py: rawKeyDown for chords so Cursor treats them as trusted.
    if (mods.ctrl) {
      await this.call("Input.dispatchKeyEvent", {
        type: "rawKeyDown",
        key: "Control",
        code: "ControlLeft",
        windowsVirtualKeyCode: 17,
        nativeVirtualKeyCode: 17,
        modifiers: 2,
      });
    }
    const downType = mods.ctrl || mods.alt || mods.meta ? "rawKeyDown" : "keyDown";
    const down = Object.assign({ type: downType }, base);
    if (key === "Enter") {
      down.text = "\r";
      down.unmodifiedText = "\r";
    }
    await this.call("Input.dispatchKeyEvent", down);
    await this.call("Input.dispatchKeyEvent", Object.assign({ type: "keyUp" }, base));
    if (mods.ctrl) {
      await this.call("Input.dispatchKeyEvent", {
        type: "keyUp",
        key: "Control",
        code: "ControlLeft",
        windowsVirtualKeyCode: 17,
        nativeVirtualKeyCode: 17,
        modifiers: 0,
      });
    }
  }

  async close() {
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
        /* ignore */
      }
    }
    this.ws = null;
    this.pending.clear();
  }
}

/* ------------------------------------------------------------------ */
/* CDP HTTP helpers                                                    */
/* ------------------------------------------------------------------ */

function httpJson(host, port, path) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host, port, path, timeout: 4000 }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (body += c));
      res.on("end", () => {
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          reject(e);
        }
      });
    });
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("CDP HTTP timeout"));
    });
  });
}

async function pageHasComposer(t) {
  const s = new CdpSession();
  try {
    await s.connect(t.webSocketDebuggerUrl, t.title);
    const has = await s.evaluate(
      "!!document.querySelector('.tiptap.ProseMirror.ui-prompt-input-editor__input,.tiptap.ProseMirror')",
      false,
    );
    await s.close();
    return !!has;
  } catch {
    try {
      await s.close();
    } catch {
      /* ignore */
    }
    return false;
  }
}

async function findAgentsPage(host, port) {
  const list = await httpJson(host, port, "/json/list");
  const pages = (list || []).filter((t) => t && t.type === "page" && t.webSocketDebuggerUrl);

  // Prefer the dedicated "Cursor Agents" window first (fast path — no probe needed if titled).
  const byTitle = pages.find((t) => /^cursor agents$/i.test(String(t.title || "").trim()));
  if (byTitle && (await pageHasComposer(byTitle))) return byTitle;

  const scored = [];
  for (const t of pages) {
    const title = (t.title || "").toLowerCase();
    let score = 0;
    if (/agent/.test(title)) score += 5;
    if (/cursor/.test(title)) score += 1;
    if (/glass/.test(title)) score += 2;
    scored.push({ t, score });
  }
  scored.sort((a, b) => b.score - a.score);

  for (const { t } of scored) {
    if (byTitle && t.id === byTitle.id) continue;
    if (await pageHasComposer(t)) return t;
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* In-page JS snippets                                                 */
/* ------------------------------------------------------------------ */

const JS_TILE_STATUS = `
(function() {
  function tileRoots() {
    const tiled = [...document.querySelectorAll('.glass-agent-conversation-tiling__tile')];
    if (tiled.length > 0) return tiled;
    const shell = document.querySelector('.agent-panel-conversation-shell');
    return shell ? [shell] : [];
  }
  function agentIdOf(node) {
    const k = Object.keys(node).find(x =>
      x.startsWith('__reactFiber$') || x.startsWith('__reactInternalInstance$')
    );
    let f = k ? node[k] : null, steps = 0;
    while (f && steps++ < 40) {
      const p = f.memoizedProps;
      if (p && typeof p === 'object' && typeof p.agentId === 'string') return p.agentId;
      f = f.return;
    }
    return null;
  }
  function editorsIn(t) {
    return [...t.querySelectorAll('.tiptap.ProseMirror.ui-prompt-input-editor__input')]
      .filter(e => !e.closest('.prompt-edit-input'));
  }
  function modelOf(t) {
    const eds = editorsIn(t);
    const ed = eds[eds.length - 1];
    const root = ed
      ? (ed.closest('.ui-prompt-input') || ed.closest('.agent-prompt-input-root') || t)
      : t;
    const fromComposer = root?.querySelector('.ui-model-picker__trigger-text')?.textContent?.trim();
    if (fromComposer) return fromComposer;
    const any = t.querySelector('.ui-model-picker__trigger-text');
    return (any && any.textContent.trim()) || '';
  }
  function generatingOf(t) {
    const submits = [...t.querySelectorAll('.ui-prompt-input-submit-button')]
      .filter(b => !b.closest('.prompt-edit-input'));
    return submits.some(b => b.getAttribute('data-state') === 'stop')
      || submits.some(b => /stop generation/i.test(b.getAttribute('aria-label') || ''));
  }
  function planningOf(t) {
    return /planning next moves/i.test(t.innerText || '');
  }
  function parsePercent(s) {
    const m = String(s || '').match(/(\\d{1,3})\\s*%/);
    return m ? Number(m[1]) : null;
  }
  function parseTokenAmount(raw, unit) {
    const n = Number(raw);
    if (!Number.isFinite(n)) return null;
    const u = String(unit || '').toUpperCase();
    if (u === 'K') return Math.round(n * 1e3);
    if (u === 'M') return Math.round(n * 1e6);
    if (u === 'B') return Math.round(n * 1e9);
    return Math.round(n);
  }
  function parseTokensLabel(s) {
    const m = String(s || '').match(/~?\\s*([\\d.]+)\\s*([KMBkmb])?\\s*\\/\\s*([\\d.]+)\\s*([KMBkmb])?/);
    if (!m) return null;
    const used = parseTokenAmount(m[1], m[2]);
    const limit = parseTokenAmount(m[3], m[4]);
    if (used == null || limit == null) return null;
    return { used, limit, label: String(s || '').trim() };
  }
  function readTray(tray) {
    if (!tray) return null;
    const summary = (tray.querySelector('.ui-context-usage-tray__summary')?.innerText || tray.innerText || '').trim();
    const tokensEl = tray.querySelector('.ui-context-usage-tray__token-count');
    const tokensText = (tokensEl?.innerText || '').trim();
    const parsed = parseTokensLabel(tokensText) || parseTokensLabel(summary);
    const percent = parsePercent(summary) || (parsed && parsed.limit ? Math.round((parsed.used / parsed.limit) * 100) : null);
    const categories = [...tray.querySelectorAll('.ui-context-usage-tray__category')].map(el => ({
      label: (el.querySelector('.ui-context-usage-tray__category-label')?.textContent || '').trim(),
      value: (el.querySelector('.ui-context-usage-tray__category-value')?.textContent || '').trim(),
    })).filter(c => c.label);
    return {
      percent,
      tokensLabel: tokensText || (parsed && parsed.label) || '',
      used: parsed ? parsed.used : null,
      limit: parsed ? parsed.limit : null,
      categories,
      summary: summary.slice(0, 240),
    };
  }
  function contextOf(t) {
    const btn = t.querySelector('.glass-chat-status-bar__button--context')
      || t.querySelector('.glass-chat-status-bar__metric-label')
      || null;
    const aria = btn ? (btn.getAttribute('aria-label') || '') : '';
    const text = btn ? (btn.innerText || btn.textContent || '').trim() : '';
    const percent = parsePercent(aria) ?? parsePercent(text);
    const openTray = t.querySelector('.ui-context-usage-tray')
      || document.querySelector('.ui-context-usage-tray');
    const detail = openTray ? readTray(openTray) : null;
    return {
      percent: detail && detail.percent != null ? detail.percent : percent,
      label: aria || (percent != null ? ('Context ' + percent + '%') : ''),
      tokensLabel: detail ? detail.tokensLabel : '',
      used: detail ? detail.used : null,
      limit: detail ? detail.limit : null,
      categories: detail ? detail.categories : [],
      trayOpen: !!openTray,
    };
  }
  const roots = tileRoots();
  const ae = document.activeElement;
  let focusIdx = roots.findIndex(t => t.contains(ae));
  if (focusIdx < 0) focusIdx = roots.length ? roots.length - 1 : -1;
  const tiles = roots.map((t, i) => ({
    index: i,
    agentId: agentIdOf(t),
    model: modelOf(t),
    generating: generatingOf(t),
    planning: planningOf(t),
    focused: i === focusIdx,
    context: contextOf(t),
  }));
  const focused = focusIdx >= 0 ? tiles[focusIdx] : null;
  return {
    pageTitle: document.title || '',
    tileCount: tiles.length,
    focused,
    tiles,
    hasComposer: !!document.querySelector('.tiptap.ProseMirror.ui-prompt-input-editor__input,.tiptap.ProseMirror'),
  };
})()
`;

/**
 * Conversation meta from the focused agent header (React fiber on chat title).
 * Workdir / branch / source — scraped once when the conversation is built.
 */
const JS_AGENT_META = `
(function() {
  function unwrap(v, depth) {
    depth = depth || 0;
    if (depth > 6 || v == null) return v;
    if (typeof v !== 'object') return v;
    if (Object.prototype.hasOwnProperty.call(v, '_value')) return unwrap(v._value, depth + 1);
    return v;
  }
  function uriPath(u) {
    u = unwrap(u);
    if (!u) return null;
    if (typeof u === 'string') return u;
    return u._fsPath || u.fsPath || u.path || null;
  }
  function repoLabelFromUrl(raw) {
    const s = String(raw || '').trim();
    if (!s) return null;
    let m = s.match(/github\\.com[/:]([^/]+)[/]([^/.\\s]+)/i);
    if (m) return m[1] + '/' + m[2].replace(/\\.git$/i, '');
    m = s.match(/[:/]([^/]+)[/]([^/.\\s]+?)(?:\\.git)?$/);
    if (m && m[1] !== 'c' && m[1].length > 1) return m[1] + '/' + m[2];
    return null;
  }
  const title =
    document.querySelector('.chat-title-tab-trigger') ||
    document.querySelector('.chat-title-tab-title');
  if (!title) return { ok: false, error: 'no title' };
  const fk = Object.keys(title).find(k =>
    k.startsWith('__reactFiber$') || k.startsWith('__reactInternalInstance$')
  );
  let fiber = fk ? title[fk] : null;
  for (let d = 0; d < 40 && fiber; d++, fiber = fiber.return) {
    const p = fiber.memoizedProps || {};
    const header = p.agentHeader || p.header;
    if (!header || typeof header !== 'object') continue;
    const env =
      unwrap(header.environment) ||
      (header.targetEnvironment && header.targetEnvironment.environment);
    const teEnv = header.targetEnvironment && header.targetEnvironment.environment;
    const workdir =
      uriPath(env && env.uri) ||
      uriPath(teEnv && teEnv.uri) ||
      null;
    const repos = unwrap(header.trackedGitRepos) || [];
    const r0 = Array.isArray(repos) && repos.length ? repos[0] : null;
    let repoUrl = r0 ? unwrap(r0.repoUrl) : null;
    if (repoUrl && typeof repoUrl === 'object') {
      repoUrl = repoUrl.url || repoUrl.href || repoUrl.remoteUrl || repoUrl.webUrl || null;
    }
    if (typeof repoUrl !== 'string') repoUrl = null;
    const branchBtn = document.querySelector('.glass-chat-status-bar__button[data-shows="branch"]');
    const branchFromBar = branchBtn
      ? String(branchBtn.getAttribute('aria-label') || branchBtn.textContent || '')
          .replace(/^Branch\\s+/i, '')
          .replace(/,.*/, '')
          .trim()
      : '';
    const envSeg = document.querySelector('.glass-chat-status-bar__segment--env');
    const envAria = envSeg ? String(envSeg.getAttribute('aria-label') || '').trim() : '';
    const envText = envSeg ? String(envSeg.textContent || '').trim() : '';
    const envLabel = envAria || envText || '';
    let envShort = null;
    if (/\\bssh\\b/i.test(envLabel) || /^ssh\\b/i.test(envText)) envShort = 'SSH';
    else if (/\\bremote\\b/i.test(envLabel)) envShort = 'Remote';
    else if (/\\blocal\\b/i.test(envLabel) || /^local$/i.test(envText)) envShort = 'Local';
    else if (envText) envShort = envText.slice(0, 24);
    else if (envAria) envShort = envAria.replace(/\\s*environment\\s*$/i, '').trim().slice(0, 24) || null;
    const branch =
      (r0 && unwrap(r0.activeBranchName)) ||
      branchFromBar ||
      null;
    const source = header.source || null;
    const createdVia =
      source === 'local' ? 'Created via Desktop' :
      source === 'cloud' ? 'Created via Cloud' :
      source ? ('Created via ' + source) : null;
    return {
      ok: true,
      agentId: header.id || null,
      name: unwrap(header.name) || null,
      workdir,
      repoPath: (r0 && r0.repoPath) || workdir || null,
      repoUrl,
      repo: repoLabelFromUrl(repoUrl) || null,
      branch: branch ? String(branch) : null,
      source,
      createdVia,
      envLabel: envLabel || null,
      envShort,
    };
  }
  return { ok: false, error: 'no agentHeader' };
})()
`;

/** Open the focused tile's context tray, read tokens, close if we opened it. */
const JS_CONTEXT_DETAIL = `
(async function() {
  function tileRoots() {
    const tiled = [...document.querySelectorAll('.glass-agent-conversation-tiling__tile')];
    if (tiled.length > 0) return tiled;
    const shell = document.querySelector('.agent-panel-conversation-shell');
    return shell ? [shell] : [];
  }
  function parsePercent(s) {
    const m = String(s || '').match(/(\\d{1,3})\\s*%/);
    return m ? Number(m[1]) : null;
  }
  function parseTokenAmount(raw, unit) {
    const n = Number(raw);
    if (!Number.isFinite(n)) return null;
    const u = String(unit || '').toUpperCase();
    if (u === 'K') return Math.round(n * 1e3);
    if (u === 'M') return Math.round(n * 1e6);
    if (u === 'B') return Math.round(n * 1e9);
    return Math.round(n);
  }
  function parseTokensLabel(s) {
    const m = String(s || '').match(/~?\\s*([\\d.]+)\\s*([KMBkmb])?\\s*\\/\\s*([\\d.]+)\\s*([KMBkmb])?/);
    if (!m) return null;
    const used = parseTokenAmount(m[1], m[2]);
    const limit = parseTokenAmount(m[3], m[4]);
    if (used == null || limit == null) return null;
    return { used, limit, label: String(s || '').trim() };
  }
  function readTray(tray) {
    if (!tray) return null;
    const summary = (tray.querySelector('.ui-context-usage-tray__summary')?.innerText || tray.innerText || '').trim();
    const tokensEl = tray.querySelector('.ui-context-usage-tray__token-count');
    const tokensText = (tokensEl?.innerText || '').trim();
    const parsed = parseTokensLabel(tokensText) || parseTokensLabel(summary);
    const percent = parsePercent(summary) || (parsed && parsed.limit ? Math.round((parsed.used / parsed.limit) * 100) : null);
    const categories = [...tray.querySelectorAll('.ui-context-usage-tray__category')].map(el => ({
      label: (el.querySelector('.ui-context-usage-tray__category-label')?.textContent || '').trim(),
      value: (el.querySelector('.ui-context-usage-tray__category-value')?.textContent || '').trim(),
    })).filter(c => c.label);
    return {
      percent,
      tokensLabel: tokensText || (parsed && parsed.label) || '',
      used: parsed ? parsed.used : null,
      limit: parsed ? parsed.limit : null,
      categories,
      summary: summary.slice(0, 240),
    };
  }
  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
  const roots = tileRoots();
  const ae = document.activeElement;
  const tile = roots.find(t => t.contains(ae)) || roots[roots.length - 1] || document.body;
  const btn = tile.querySelector('.glass-chat-status-bar__button--context')
    || document.querySelector('.glass-chat-status-bar__button--context');
  if (!btn) {
    return { ok: false, error: 'no context button' };
  }
  const aria = btn.getAttribute('aria-label') || '';
  const text = (btn.innerText || '').trim();
  const percentQuick = parsePercent(aria) ?? parsePercent(text);
  let tray = document.querySelector('.ui-context-usage-tray');
  let opened = false;
  if (!tray) {
    const prev = document.activeElement;
    btn.click();
    opened = true;
    for (let i = 0; i < 12 && !tray; i++) {
      await sleep(50);
      tray = document.querySelector('.ui-context-usage-tray');
    }
    if (prev && typeof prev.focus === 'function') {
      try { prev.focus(); } catch (e) {}
    }
  }
  const detail = readTray(tray);
  if (opened) {
    document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
    await sleep(40);
    // Fallback: toggle closed if Escape didn't dismiss.
    if (document.querySelector('.ui-context-usage-tray')) {
      try { btn.click(); } catch (e) {}
      await sleep(40);
    }
  }
  return {
    ok: true,
    percent: (detail && detail.percent != null) ? detail.percent : percentQuick,
    label: aria || (percentQuick != null ? ('Context ' + percentQuick + '%') : ''),
    tokensLabel: detail ? detail.tokensLabel : '',
    used: detail ? detail.used : null,
    limit: detail ? detail.limit : null,
    categories: detail ? detail.categories : [],
    summary: detail ? detail.summary : '',
    opened,
  };
})()
`;

function jsFocusAndInsert(text) {
  // Insert into the focused tile's follow-up / last composer.
  return `
(function() {
  const TEXT = ${JSON.stringify(text)};
  function tileRoots() {
    const tiled = [...document.querySelectorAll('.glass-agent-conversation-tiling__tile')];
    if (tiled.length > 0) return tiled;
    const shell = document.querySelector('.agent-panel-conversation-shell');
    return shell ? [shell] : [];
  }
  function editorsIn(t) {
    return [...t.querySelectorAll('.tiptap.ProseMirror.ui-prompt-input-editor__input')]
      .filter(e => !e.closest('.prompt-edit-input'));
  }
  function pickEditor(t) {
    const eds = editorsIn(t);
    if (!eds.length) return null;
    const isFu = e => e.closest('.agent-panel-followup-input') ||
      /send follow-?up/i.test((e.querySelector('[data-placeholder]')?.getAttribute('data-placeholder')) ||
        e.getAttribute('data-placeholder') || '');
    return eds.find(isFu) || eds[eds.length - 1];
  }
  const roots = tileRoots();
  const ae = document.activeElement;
  let tile = roots.find(t => t.contains(ae)) || roots[roots.length - 1] || null;
  let ed = tile ? pickEditor(tile) : null;
  if (!ed) {
    ed = document.querySelector('.tiptap.ProseMirror.ui-prompt-input-editor__input')
      || document.querySelector('.tiptap.ProseMirror');
  }
  if (!ed) return { ok: false, error: 'no composer' };
  ed.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
  ed.focus();
  ed.click();
  // Prefer execCommand so tip-tap / ProseMirror pick up the edit.
  let inserted = false;
  try {
    inserted = document.execCommand('insertText', false, TEXT);
  } catch (e) {
    inserted = false;
  }
  if (!inserted) {
    ed.textContent = (ed.textContent || '') + TEXT;
    ed.dispatchEvent(new InputEvent('input', { bubbles: true, data: TEXT, inputType: 'insertText' }));
  }
  return {
    ok: true,
    inserted: !!inserted,
    preview: TEXT.slice(0, 80),
    len: TEXT.length,
  };
})()
`;
}

const JS_FOCUS_COMPOSER = `
(function() {
  function tileRoots() {
    const tiled = [...document.querySelectorAll('.glass-agent-conversation-tiling__tile')];
    if (tiled.length > 0) return tiled;
    const shell = document.querySelector('.agent-panel-conversation-shell');
    return shell ? [shell] : [];
  }
  function pickEditor(t) {
    const eds = [...t.querySelectorAll('.tiptap.ProseMirror.ui-prompt-input-editor__input')]
      .filter(e => !e.closest('.prompt-edit-input'));
    if (!eds.length) return null;
    const isFu = e => e.closest('.agent-panel-followup-input') ||
      /send follow-?up/i.test((e.querySelector('[data-placeholder]')?.getAttribute('data-placeholder')) ||
        e.getAttribute('data-placeholder') || '');
    return eds.find(isFu) || eds[eds.length - 1];
  }
  const roots = tileRoots();
  const ae = document.activeElement;
  const tile = roots.find(t => t.contains(ae)) || roots[roots.length - 1] || null;
  const ed = (tile && pickEditor(tile))
    || document.querySelector('.tiptap.ProseMirror.ui-prompt-input-editor__input')
    || document.querySelector('.tiptap.ProseMirror');
  if (!ed) return false;
  ed.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
  ed.focus();
  ed.click();
  return true;
})()
`;

/* ------------------------------------------------------------------ */
/* Plugin                                                              */
/* ------------------------------------------------------------------ */

class JefrCdpPlugin extends Plugin {
  async onload() {
    const loaded = (await this.loadData()) || {};
    this.settings = Object.assign({}, DEFAULT_SETTINGS, loaded);
    if (!this.settings.injectTemplate) this.settings.injectTemplate = PROMPT_NO_MCP_LOG;
    // Context tokens: opt-in only. Older saves had contextDetailMs: 8000 from a prior default
    // and that opened the Agents tray every few seconds (visible flicker).
    if (typeof loaded.showContextTokens !== "boolean") {
      this.settings.showContextTokens = false;
      if (Number(this.settings.contextDetailMs) > 0) this.settings.contextDetailMs = 0;
    }
    const beforeIds = new Set(
      Array.isArray(loaded.promptBookmarks) ? loaded.promptBookmarks.map((b) => b && b.id) : [],
    );
    const needsMigrate = !Array.isArray(loaded.promptBookmarks) || !loaded.promptBookmarks.length;
    normalizePromptSettings(this.settings);
    const addedBuiltIn = this.settings.promptBookmarks.some((b) => b && !beforeIds.has(b.id));
    const migratedTokens = typeof loaded.showContextTokens !== "boolean";
    if (needsMigrate || addedBuiltIn || migratedTokens) await this.saveData(this.settings);

    this.cdp = new CdpSession();
    this.cdp.onDead = () => this.scheduleReconnect();
    this._reconnectTimer = null;
    this._connecting = false;
    /** After new-agent: Inject stays on until the next successful send, then auto-off. */
    this._injectOncePending = false;
    /** agentId → conversation meta (workdir/branch/…), saved once when built. */
    this.agentMetaById = new Map();
    this._agentMetaBusy = false;

    this.registerView(VIEW_TYPE, (leaf) => new JefrCdpView(leaf, this));

    this.addRibbonIcon("radio", "Open JEFR CDP", () => {
      this.activateView();
    });

    this.addCommand({
      id: "open-jefr-cdp",
      name: "Open JEFR CDP",
      callback: () => this.activateView(),
    });

    this.addCommand({
      id: "send-composer",
      name: "Send current composer text to Cursor agent",
      callback: async () => {
        const view = await this.ensureView();
        if (view) await view.sendCurrent();
      },
    });

    this.addCommand({
      id: "new-agent",
      name: "New agent in Cursor (Ctrl+N)",
      callback: async () => {
        const view = await this.ensureView();
        if (view) await view.onNewAgent();
      },
    });

    this.addCommand({
      id: "attach-clipboard-image",
      name: "Attach image from clipboard",
      callback: async () => {
        const view = await this.ensureView();
        if (!view) return;
        const ok = await view.tryClipboardImage();
        new Notice(ok ? "JEFR CDP: image attached" : "JEFR CDP: no image in clipboard");
      },
    });

    this.addCommand({
      id: "toggle-compact-mode",
      name: "Toggle full / compact mode",
      callback: async () => {
        const view = await this.ensureView();
        if (view) await view.toggleMinimized();
      },
    });

    this.addCommand({
      id: "switch-to-full-mode",
      name: "Switch to full mode",
      callback: async () => {
        const view = await this.ensureView();
        if (view) await view.setMinimized(false);
      },
    });

    this.addCommand({
      id: "switch-to-compact-mode",
      name: "Switch to compact mode",
      callback: async () => {
        const view = await this.ensureView();
        if (view) await view.setMinimized(true);
      },
    });

    this.addSettingTab(new JefrCdpSettingTab(this.app, this));

    // Kick CDP in background so the view opens warm.
    void this.ensureCdp().catch(() => {});
  }

  onunload() {
    if (this._reconnectTimer) clearTimeout(this._reconnectTimer);
    void this.cdp.close();
  }

  async saveSettings() {
    await this.saveData(this.settings);
    this.app.workspace.getLeavesOfType(VIEW_TYPE).forEach((leaf) => {
      if (leaf.view instanceof JefrCdpView) leaf.view.onSettingsChanged();
    });
  }

  async activateView() {
    const { workspace } = this.app;
    let leaf = workspace.getLeavesOfType(VIEW_TYPE)[0];
    if (!leaf) {
      leaf = workspace.getLeaf("tab");
      await leaf.setViewState({ type: VIEW_TYPE, active: true });
    }
    workspace.revealLeaf(leaf);
    return leaf;
  }

  async ensureView() {
    const leaf = await this.activateView();
    return leaf && leaf.view instanceof JefrCdpView ? leaf.view : null;
  }

  scheduleReconnect() {
    if (!this.settings.autoReconnect) return;
    if (this._reconnectTimer) clearTimeout(this._reconnectTimer);
    this._reconnectTimer = setTimeout(() => {
      void this.ensureCdp().catch(() => {});
    }, 2000);
  }

  async ensureCdp() {
    if (this.cdp.connected) return this.cdp;
    if (this._connecting) {
      // Wait briefly for in-flight connect.
      for (let i = 0; i < 40 && this._connecting; i++) {
        await sleep(50);
      }
      if (this.cdp.connected) return this.cdp;
    }
    this._connecting = true;
    try {
      const host = (this.settings.cdpHost || "127.0.0.1").trim() || "127.0.0.1";
      const port = Number(this.settings.cdpPort) || 9222;
      const page = await findAgentsPage(host, port);
      if (!page) throw new Error("No Agents/composer page on :" + port + " — is Cursor running with --remote-debugging-port?");
      await this.cdp.connect(page.webSocketDebuggerUrl, page.title);
      this.notifyViews();
      return this.cdp;
    } catch (e) {
      this.scheduleReconnect();
      throw e;
    } finally {
      this._connecting = false;
    }
  }

  notifyViews() {
    this.app.workspace.getLeavesOfType(VIEW_TYPE).forEach((leaf) => {
      if (leaf.view instanceof JefrCdpView) leaf.view.refreshStatus();
    });
  }

  async tileStatus() {
    const cdp = await this.ensureCdp();
    return cdp.evaluate(JS_TILE_STATUS, false);
  }

  /** Scrape focused agent header meta (workdir / branch / source) via CDP. */
  async scrapeAgentMeta() {
    const cdp = await this.ensureCdp();
    return cdp.evaluate(JS_AGENT_META, false);
  }

  getCachedAgentMeta(agentId) {
    if (!agentId) return null;
    return this.agentMetaById.get(String(agentId)) || null;
  }

  /**
   * Save conversation meta once per agentId when workdir is available.
   * Retries on later polls until the conversation is built.
   */
  async ensureAgentMeta(agentId) {
    if (!agentId) return null;
    const id = String(agentId);
    const cached = this.agentMetaById.get(id);
    // Refresh once if an older cache entry lacks envShort (local/SSH tag).
    if (cached && cached.workdir && cached.envShort) return cached;
    if (this._agentMetaBusy) return cached || null;
    this._agentMetaBusy = true;
    try {
      const raw = await this.scrapeAgentMeta();
      if (!raw || !raw.ok || !raw.agentId) return cached || null;
      const meta = {
        agentId: String(raw.agentId),
        name: raw.name || null,
        workdir: raw.workdir || null,
        repoPath: raw.repoPath || raw.workdir || null,
        repo: raw.repo || null,
        repoUrl: raw.repoUrl || null,
        branch: raw.branch || null,
        source: raw.source || null,
        createdVia: raw.createdVia || null,
        envLabel: raw.envLabel || null,
        envShort: raw.envShort || null,
        savedAt: Date.now(),
      };
      // Only lock in when workdir is present (conversation built).
      if (meta.workdir) {
        this.agentMetaById.set(meta.agentId, meta);
      }
      return this.agentMetaById.get(id) || (meta.agentId === id && meta.workdir ? meta : cached) || null;
    } catch {
      return cached || null;
    } finally {
      this._agentMetaBusy = false;
    }
  }

  /** Briefly open the focused tile's context tray and read token breakdown. */
  async contextDetail() {
    const cdp = await this.ensureCdp();
    return cdp.evaluate(JS_CONTEXT_DETAIL, true);
  }

  getPromptBookmarks() {
    normalizePromptSettings(this.settings);
    return this.settings.promptBookmarks;
  }

  getActivePrompt() {
    const bookmarks = this.getPromptBookmarks();
    return bookmarks.find((b) => b.id === this.settings.activePromptId) || bookmarks[0];
  }

  async setActivePrompt(id) {
    normalizePromptSettings(this.settings);
    const hit = this.settings.promptBookmarks.find((b) => b.id === id);
    if (!hit) return null;
    this.settings.activePromptId = hit.id;
    this.settings.injectTemplate = hit.template;
    await this.saveSettings();
    return hit;
  }

  async upsertPromptBookmark(bookmark) {
    normalizePromptSettings(this.settings);
    const next = normalizeBookmark(bookmark);
    const list = this.settings.promptBookmarks;
    const idx = list.findIndex((b) => b.id === next.id);
    if (idx >= 0) list[idx] = next;
    else list.push(next);
    if (!this.settings.activePromptId) this.settings.activePromptId = next.id;
    if (this.settings.activePromptId === next.id) {
      this.settings.injectTemplate = next.template;
    }
    await this.saveSettings();
    return next;
  }

  async deletePromptBookmark(id) {
    normalizePromptSettings(this.settings);
    const list = this.settings.promptBookmarks;
    if (list.length <= 1) throw new Error("Keep at least one prompt bookmark");
    const next = list.filter((b) => b.id !== id);
    if (next.length === list.length) return;
    this.settings.promptBookmarks = next;
    if (this.settings.activePromptId === id) {
      this.settings.activePromptId = next[0].id;
      this.settings.injectTemplate = next[0].template;
    }
    await this.saveSettings();
  }

  buildPayload(userText) {
    const text = String(userText || "").trim();
    if (!text) return "";
    if (!this.settings.injectEnabled) return text;
    const active = this.getActivePrompt();
    const tmpl = (active && active.template) || this.settings.injectTemplate || DEFAULT_INJECT;
    if (tmpl.includes("{{message}}")) return tmpl.replace(/\{\{message\}\}/g, text);
    return tmpl + "\n\n" + text;
  }

  /** Paste staged images into the focused composer via clipboard + Ctrl+V. */
  async pasteImagesToAgent(attachments) {
    const list = Array.isArray(attachments) ? attachments.filter((a) => a && a.dataUrl) : [];
    if (!list.length) return 0;
    const cdp = await this.ensureCdp();
    let n = 0;
    for (const att of list) {
      writeClipboardImage(att.dataUrl);
      const focused = await cdp.evaluate(JS_FOCUS_COMPOSER, false);
      if (!focused) throw new Error("Could not focus composer for image paste");
      await sleep(50);
      await cdp.pressKey("v", "KeyV", 86, { ctrl: true });
      await sleep(220);
      n++;
    }
    return n;
  }

  /** Paste large text via clipboard + Ctrl+V (avoids CDP evaluate hangs). */
  async pasteTextToAgent(text) {
    const payload = String(text || "");
    if (!payload) return { ok: false, error: "empty", via: "clipboard" };
    const cdp = await this.ensureCdp();
    writeClipboardText(payload);
    const focused = await cdp.evaluate(JS_FOCUS_COMPOSER, false);
    if (!focused) throw new Error("Could not focus composer for text paste");
    await sleep(50);
    await cdp.pressKey("v", "KeyV", 86, { ctrl: true });
    // TipTap needs a beat to ingest a large paste before Enter.
    await sleep(Math.min(1200, 120 + Math.floor(payload.length / 80)));
    return { ok: true, inserted: true, via: "clipboard", len: payload.length, preview: payload.slice(0, 80) };
  }

  async sendToAgent(userText, attachments) {
    const payload = this.buildPayload(userText);
    const images = Array.isArray(attachments) ? attachments.filter((a) => a && a.dataUrl) : [];
    if (!payload && !images.length) throw new Error("Empty message");

    const cdp = await this.ensureCdp();

    if (images.length) {
      await this.pasteImagesToAgent(images);
      await sleep(80);
    }

    let inserted = null;
    if (payload) {
      // Large payloads inside Runtime.evaluate + execCommand('insertText') routinely
      // exceed the CDP timeout and leave a zombie "online" socket. Paste instead.
      if (payload.length >= PASTE_TEXT_THRESHOLD) {
        inserted = await this.pasteTextToAgent(payload);
      } else {
        inserted = await cdp.evaluate(jsFocusAndInsert(payload), false, 15000);
        if (!inserted || !inserted.ok) {
          throw new Error((inserted && inserted.error) || "Could not focus composer");
        }
        await sleep(40);
      }
    } else {
      // Images only — still focus before Enter.
      const focused = await cdp.evaluate(JS_FOCUS_COMPOSER, false);
      if (!focused) throw new Error("Could not focus composer");
      await sleep(40);
    }

    await cdp.pressKey("Enter", "Enter", 13);
    return { payload, inserted, imageCount: images.length };
  }

  async newAgent() {
    const cdp = await this.ensureCdp();
    await cdp.evaluate(JS_FOCUS_COMPOSER, false);
    await sleep(60);
    await cdp.pressKey("n", "KeyN", 78, { ctrl: true });
    // Inject once: tick Inject for the fresh agent; first send will untick (see consumeInjectOnce).
    if (this.settings.injectOnNewAgent !== false) {
      this._injectOncePending = true;
      if (!this.settings.injectEnabled) {
        this.settings.injectEnabled = true;
        await this.saveSettings();
      } else {
        this.notifyViews();
      }
    }
  }

  /**
   * After a successful send on a post-new-agent session: turn Inject off once.
   * Returns true if Inject was unticked.
   */
  async consumeInjectOnce() {
    if (!this._injectOncePending) return false;
    if (this.settings.injectOnNewAgent === false) {
      this._injectOncePending = false;
      return false;
    }
    this._injectOncePending = false;
    if (!this.settings.injectEnabled) return false;
    this.settings.injectEnabled = false;
    await this.saveSettings();
    return true;
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/* ------------------------------------------------------------------ */
/* View                                                                */
/* ------------------------------------------------------------------ */

class JefrCdpView extends ItemView {
  constructor(leaf, plugin) {
    super(leaf);
    this.plugin = plugin;
    this.history = [];
    /** Sent composer texts for ↑ / ↓ recall (session-only). */
    this.inputHistory = [];
    /** -1 = live draft; 0..n-1 = browsing inputHistory. */
    this.inputHistoryIndex = -1;
    this.inputHistoryDraft = "";
    this.pollTimer = null;
    this.sending = false;
    this.lastStatus = null;
    this.attachments = [];
    this._docPasteHandler = null;
    this.lastContext = null;
    this._lastContextDetailAt = 0;
    this._contextDetailBusy = false;
    this._newAgentBusy = false;

    // Obsidian pushes this.scope while the leaf is active — consumes core Mod+N
    // (new note / new window). Capture-phase keydown alone cannot stop that keymap.
    this.scope = new Scope(this.app.scope);
    this.scope.register(["Mod"], "n", (evt) => {
      if (!this.isCompact()) return;
      if (evt) evt.preventDefault();
      void this.onNewAgent();
      return false;
    });
    this.scope.register(["Mod"], "PageUp", (evt) => {
      if (evt) evt.preventDefault();
      this.app.commands.executeCommandById("workspace:previous-tab");
      return false;
    });
    this.scope.register(["Mod"], "PageDown", (evt) => {
      if (evt) evt.preventDefault();
      this.app.commands.executeCommandById("workspace:next-tab");
      return false;
    });
  }

  getViewType() {
    return VIEW_TYPE;
  }

  getDisplayText() {
    return "JEFR CDP";
  }

  getIcon() {
    return "radio";
  }

  /** Pane ⋮ / tab menu — full-mode extras live here (compact chrome stays minimal). */
  onPaneMenu(menu, source) {
    super.onPaneMenu(menu, source);
    const compact = this.isCompact();
    const route = this.getRouteSummary();

    menu.addSeparator();
    menu.addItem((item) => {
      item
        .setTitle(compact ? "Switch to full mode" : "Switch to compact mode")
        .setIcon(compact ? "maximize-2" : "minimize-2")
        .onClick(() => {
          void this.toggleMinimized();
        });
    });
    menu.addItem((item) => {
      item
        .setTitle("Attach image")
        .setIcon("image")
        .onClick(async () => {
          const ok = await this.tryClipboardImage();
          if (!ok && this.fileInput) this.fileInput.click();
          else if (!ok) new Notice("JEFR CDP: no image in clipboard");
        });
    });
    menu.addItem((item) => {
      item
        .setTitle("Reconnect CDP")
        .setIcon("refresh-cw")
        .onClick(async () => {
          await this.plugin.cdp.close();
          try {
            await this.plugin.ensureCdp();
            new Notice("JEFR CDP: connected");
          } catch (e) {
            new Notice("JEFR CDP: " + (e.message || e));
          }
          void this.refreshStatus();
        });
    });
    const bookmarks = this.plugin.getPromptBookmarks();
    const activeId = this.plugin.settings.activePromptId;
    menu.addItem((item) => {
      item.setTitle("Prompt bookmark").setIcon("bookmark");
      const sub = item.setSubmenu();
      for (const b of bookmarks) {
        sub.addItem((si) => {
          si.setTitle(b.name);
          if (b.id === activeId) si.setChecked(true);
          si.onClick(() => {
            void this.plugin.setActivePrompt(b.id).then(() => {
              this.refreshPromptSelect();
              this.updateHint();
            });
          });
        });
      }
    });

    menu.addSeparator();
    // Status (Agents id + model + workdir) — under actions; workdir also on compact bar.
    menu.addItem((item) => {
      item
        .setTitle(route.agentLine)
        .setIcon("bot")
        .setDisabled(true);
    });
    if (route.modelLine) {
      menu.addItem((item) => {
        item
          .setTitle(route.modelLine)
          .setIcon("cpu")
          .setDisabled(true);
      });
    }
    if (route.workdirLine) {
      menu.addItem((item) => {
        item
          .setTitle(route.workdirLine)
          .setIcon("folder")
          .setDisabled(true);
      });
    }
    if (route.repoLine) {
      menu.addItem((item) => {
        item
          .setTitle(route.repoLine)
          .setIcon("git-branch")
          .setDisabled(true);
      });
    }
    if (route.envLine) {
      menu.addItem((item) => {
        item
          .setTitle(route.envLine)
          .setIcon("monitor")
          .setDisabled(true);
      });
    }
    if (route.createdVia) {
      menu.addItem((item) => {
        item
          .setTitle(route.createdVia)
          .setIcon("laptop")
          .setDisabled(true);
      });
    }
    if (route.detail) {
      menu.addItem((item) => {
        item
          .setTitle("Copy route info")
          .setIcon("copy")
          .onClick(async () => {
            try {
              await navigator.clipboard.writeText(route.detail);
              new Notice("JEFR CDP: route info copied");
            } catch {
              new Notice(route.detail);
            }
          });
      });
    }
  }

  /** Snapshot of Agents tile / model for the ⋮ menu (and full-mode route bar). */
  getRouteSummary() {
    const online = this.plugin.cdp && this.plugin.cdp.connected;
    const st = this.lastStatus;
    if (!online) {
      return {
        agentLine: "CDP offline",
        modelLine: "",
        workdirLine: "",
        repoLine: "",
        envLine: "",
        createdVia: "",
        detail: "Waiting for Cursor CDP on " + this.plugin.settings.cdpHost + ":" + this.plugin.settings.cdpPort,
      };
    }
    const f = st && st.focused;
    const busy = !!(f && (f.generating || f.planning));
    const state = !f
      ? st && st.hasComposer
        ? "composer"
        : "no tile"
      : busy
        ? f.planning
          ? "planning"
          : "busy"
        : "idle";
    const model = (f && f.model) || "";
    const aid = f && f.agentId ? String(f.agentId).slice(0, 8) : "";
    const meta = f && f.agentId ? this.plugin.getCachedAgentMeta(f.agentId) : null;
    const workdir = (meta && meta.workdir) || "";
    const branch = (meta && meta.branch) || "";
    const repo = (meta && meta.repo) || "";
    const envShort = (meta && meta.envShort) || "";
    const envLabel = (meta && meta.envLabel) || "";
    const createdVia = (meta && meta.createdVia) || "";
    const agentLine = aid ? "Agents · " + aid : "Agents · " + state;
    const modelLine = model || state;
    const workdirLine = workdir ? workdir : "";
    const repoLine = repo || branch ? (repo || "repo") + (branch ? " · " + branch : "") : "";
    const envLine = envLabel || envShort || "";
    const detailBits = [
      (st && st.pageTitle) || "Cursor Agents",
      state,
      model || null,
      aid || null,
      repo || null,
      branch ? "branch " + branch : null,
      envShort || envLabel || null,
      workdir || null,
      createdVia || null,
    ].filter(Boolean);
    return {
      agentLine,
      modelLine,
      workdirLine,
      repoLine,
      envLine,
      createdVia,
      detail: detailBits.join(" · "),
      state,
      model,
      aid,
      busy,
      workdir,
      branch,
      repo,
      envShort,
    };
  }

  async onOpen() {
    this.buildUI();
    this.startPoll();
    this.registerEvent(
      this.app.workspace.on("active-leaf-change", (leaf) => {
        if (leaf === this.leaf) this.focusComposer();
      }),
    );
    this.registerDomEvent(this.containerEl, "pointerdown", (e) => this.onPanePointer(e));
    this.focusComposer();
    void this.plugin.ensureCdp().then(() => this.refreshStatus()).catch(() => this.refreshStatus());
  }

  async onClose() {
    this.stopPoll();
    if (this._docPasteHandler) {
      document.removeEventListener("paste", this._docPasteHandler, true);
      this._docPasteHandler = null;
    }
  }

  focusComposer() {
    const el = this.input;
    if (!el || document.activeElement === el) return;
    const go = () => {
      if (!el.isConnected || document.activeElement === el) return;
      if (this.app.workspace.activeLeaf !== this.leaf) return;
      el.focus({ preventScroll: true });
    };
    requestAnimationFrame(() => window.setTimeout(go, 0));
  }

  onPanePointer(e) {
    const t = e.target;
    if (!(t instanceof Element)) return;
    if (t.closest("textarea, input, select, button, a, .clickable-icon, .menu, label")) return;
    this.focusComposer();
  }

  isCompact() {
    return this.plugin.settings.minimized !== false;
  }

  onSettingsChanged() {
    if (this.injectToggle) this.injectToggle.checked = !!this.plugin.settings.injectEnabled;
    this.refreshPromptSelect();
    this.updateHint();
    this.applyMinimized();
    this.stopPoll();
    this.startPoll();
    void this.refreshStatus();
  }

  startPoll() {
    const ms = Math.max(400, Number(this.plugin.settings.pollMs) || 800);
    this.pollTimer = window.setInterval(() => {
      void this.refreshStatus();
    }, ms);
  }

  stopPoll() {
    if (this.pollTimer) {
      window.clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  buildUI() {
    const root = this.contentEl;
    root.empty();
    root.addClass("jefr-cdp-root");

    // Expanded-mode history (hidden in compact — same as jefr-chat minimized).
    const scroll = root.createDiv({ cls: "jefr-cdp-scroll" });
    this.scrollEl = scroll;

    const header = scroll.createDiv({ cls: "jefr-cdp-header" });
    this.headerEl = header;
    const brand = header.createDiv({ cls: "jefr-cdp-brand" });
    brand.createSpan({ cls: "jefr-cdp-logo", text: "JEFR CDP" });
    this.statusPill = brand.createSpan({ cls: "jefr-cdp-pill jefr-cdp-pill-off", text: "CDP offline" });
    this.tilePill = brand.createSpan({ cls: "jefr-cdp-pill jefr-cdp-pill-idle", text: "No tile" });

    const headerRight = header.createDiv({ cls: "jefr-cdp-header-right" });
    this.reconnectBtn = headerRight.createEl("button", {
      cls: "jefr-cdp-icon-btn",
      attr: { "aria-label": "Reconnect CDP", title: "Reconnect CDP" },
    });
    setIcon(this.reconnectBtn, "refresh-cw");
    this.reconnectBtn.onclick = async () => {
      await this.plugin.cdp.close();
      try {
        await this.plugin.ensureCdp();
        new Notice("JEFR CDP: connected");
      } catch (e) {
        new Notice("JEFR CDP: " + (e.message || e));
      }
      this.refreshStatus();
    };

    this.metaLine = scroll.createDiv({ cls: "jefr-cdp-meta" });
    this.metaLine.setText("Connect Cursor with --remote-debugging-port=9222");

    this.messagesEl = scroll.createDiv({ cls: "jefr-cdp-messages" });
    this.renderEmpty();

    // Dock = thin route chrome + full-height composer (fills panel in compact).
    const dock = root.createDiv({ cls: "jefr-cdp-dock" });
    this.dockEl = dock;

    const routeBar = dock.createDiv({ cls: "jefr-cdp-routebar" });
    this.routeBar = routeBar;

    this.routeStatus = routeBar.createSpan({
      cls: "jefr-cdp-route jefr-cdp-route-off jefr-cdp-full-only",
      attr: { title: "CDP / focused tile" },
    });
    this.routeNameEl = this.routeStatus.createSpan({ cls: "jefr-cdp-route-name", text: "CDP offline" });
    this.routeModelEl = this.routeStatus.createSpan({ cls: "jefr-cdp-route-model", text: "" });

    this.routeContextEl = routeBar.createSpan({
      cls: "jefr-cdp-context jefr-cdp-context-empty",
      attr: {
        title: "Context usage",
        "aria-label": "Context usage",
      },
    });
    this.routeContextPctEl = this.routeContextEl.createSpan({ cls: "jefr-cdp-context-pct", text: "—" });
    this.routeContextTokensEl = this.routeContextEl.createSpan({ cls: "jefr-cdp-context-tokens", text: "" });

    const routeRight = routeBar.createDiv({ cls: "jefr-cdp-route-right" });

    // Prompt select: full mode only — compact picks bookmark via pane ⋮.
    this.promptSelect = routeRight.createEl("select", {
      cls: "jefr-cdp-prompt-select jefr-cdp-full-only",
      attr: { title: "Prompt bookmark (inject template)", "aria-label": "Prompt bookmark" },
    });
    this.promptSelect.onchange = async () => {
      const id = this.promptSelect.value;
      await this.plugin.setActivePrompt(id);
      this.updateHint();
    };
    this.refreshPromptSelect();

    const injectLabel = routeRight.createEl("label", {
      cls: "jefr-cdp-toggle",
      attr: { title: "Prepend selected prompt bookmark when sending" },
    });
    this.injectToggle = injectLabel.createEl("input", {
      attr: { type: "checkbox", "aria-label": "Inject" },
    });
    this.injectToggle.checked = !!this.plugin.settings.injectEnabled;
    this.injectToggle.onchange = async () => {
      this.plugin.settings.injectEnabled = !!this.injectToggle.checked;
      // Manual off cancels the pending one-shot; manual on does not re-arm it.
      if (!this.injectToggle.checked) this.plugin._injectOncePending = false;
      await this.plugin.saveSettings();
      this.refreshPromptSelect();
      this.updateHint();
    };
    injectLabel.createSpan({ cls: "jefr-cdp-toggle-label", text: "Inject" });

    this.attachBtn = routeRight.createEl("button", {
      cls: "jefr-cdp-icon-btn jefr-cdp-full-only",
      attr: { "aria-label": "Attach image", title: "Attach image (clipboard or file)" },
    });
    setIcon(this.attachBtn, "image");
    this.attachBtn.onclick = async () => {
      const ok = await this.tryClipboardImage();
      if (!ok) this.fileInput.click();
    };

    this.newAgentBtn = routeRight.createEl("button", {
      cls: "jefr-cdp-icon-btn",
      attr: { "aria-label": "New agent", title: "New agent (Ctrl+N)" },
    });
    setIcon(this.newAgentBtn, "square-pen");
    this.newAgentBtn.onclick = () => this.onNewAgent();

    this.reconnectMiniBtn = routeRight.createEl("button", {
      cls: "jefr-cdp-icon-btn jefr-cdp-reconnect-mini jefr-cdp-full-only",
      attr: { "aria-label": "Reconnect CDP", title: "Reconnect CDP" },
    });
    setIcon(this.reconnectMiniBtn, "refresh-cw");
    this.reconnectMiniBtn.onclick = () => this.reconnectBtn.click();

    this.minimizeBtn = routeRight.createEl("button", {
      cls: "jefr-cdp-icon-btn jefr-cdp-minimize-btn jefr-cdp-full-only",
      attr: { "aria-label": "Toggle compact mode" },
    });
    this.minimizeBtn.onclick = () => this.toggleMinimized();

    // After controls so compact CSS can place workdir mid-bar (Inject/New · path · %).
    this.routeWorkdirEl = routeBar.createSpan({
      cls: "jefr-cdp-workdir jefr-cdp-workdir-empty",
      attr: { "aria-label": "Working directory" },
      text: "",
    });

    const composer = dock.createDiv({ cls: "jefr-cdp-composer" });
    this.composerEl = composer;
    this.attachBar = composer.createDiv({ cls: "jefr-cdp-attachbar" });

    this.input = composer.createEl("textarea", {
      cls: "jefr-cdp-input",
      attr: {
        rows: "3",
        placeholder:
          "Message agent…  Enter send · Ctrl+N new agent · Shift+Enter newline · ↑↓ history · paste image",
      },
    });
    this.input.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && (e.key === "PageUp" || e.key === "PageDown")) {
        e.preventDefault();
        this.app.commands.executeCommandById(
          e.key === "PageUp" ? "workspace:previous-tab" : "workspace:next-tab",
        );
        return;
      }
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        void this.sendCurrent();
        return;
      }
      // Shell-style: ↑ at caret start → last message; ↓ → next / restore draft.
      if (e.key === "ArrowUp" && !e.altKey && !e.ctrlKey && !e.metaKey) {
        if (this.input.selectionStart === 0 && this.input.selectionEnd === 0) {
          if (this.recallInputHistory(-1)) e.preventDefault();
        }
        return;
      }
      if (e.key === "ArrowDown" && !e.altKey && !e.ctrlKey && !e.metaKey) {
        if (this.inputHistoryIndex >= 0) {
          if (this.recallInputHistory(1)) e.preventDefault();
        }
      }
    });

    // Capture-phase: stop Obsidian Mod+N (new note / new window) before the core keymap.
    this.registerDomEvent(
      window,
      "keydown",
      (e) => {
        if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey) return;
        if (e.key !== "n" && e.key !== "N") return;
        if (!this.isCompact()) return;
        const within = this.contentEl && this.contentEl.contains(/** @type {Node} */ (e.target));
        const leafActive = this.app.workspace.activeLeaf === this.leaf;
        if (!within && !leafActive) return;
        e.preventDefault();
        e.stopImmediatePropagation();
        void this.onNewAgent();
      },
      true
    );
    this.input.addEventListener("paste", (e) => this.onPaste(e), true);

    composer.addEventListener("dragover", (e) => {
      e.preventDefault();
      composer.addClass("jefr-cdp-dragover");
    });
    composer.addEventListener("dragleave", () => composer.removeClass("jefr-cdp-dragover"));
    composer.addEventListener("drop", (e) => {
      e.preventDefault();
      composer.removeClass("jefr-cdp-dragover");
      void this.ingestFiles(e.dataTransfer && e.dataTransfer.files);
    });

    this._docPasteHandler = (e) => {
      if (!this.input || document.activeElement !== this.input) return;
      this.onPaste(e);
    };
    document.addEventListener("paste", this._docPasteHandler, true);

    this.fileInput = composer.createEl("input", {
      cls: "jefr-cdp-fileinput",
      attr: { type: "file", accept: "image/*", multiple: "true" },
    });
    this.fileInput.onchange = () => {
      void this.ingestFiles(this.fileInput.files);
      this.fileInput.value = "";
    };

    // Expanded-mode toolbar only (hidden in compact, like original jefr-chat).
    const toolbar = composer.createDiv({ cls: "jefr-cdp-toolbar" });
    this.toolbarEl = toolbar;
    this.hint = toolbar.createSpan({ cls: "jefr-cdp-hint", text: "" });
    this.sendBtn = toolbar.createEl("button", { cls: "jefr-cdp-send", text: "Send" });
    this.sendBtn.onclick = () => void this.sendCurrent();
    this.updateHint();

    this.applyMinimized();
  }

  refreshPromptSelect() {
    if (!this.promptSelect) return;
    const bookmarks = this.plugin.getPromptBookmarks();
    const activeId = this.plugin.settings.activePromptId;
    this.promptSelect.empty();
    for (const b of bookmarks) {
      const opt = this.promptSelect.createEl("option", { text: b.name, attr: { value: b.id } });
      if (b.id === activeId) opt.selected = true;
    }
    this.promptSelect.value = activeId;
    this.promptSelect.disabled = !this.plugin.settings.injectEnabled;
  }

  updateHint() {
    if (!this.hint) return;
    if (this.injectToggle && this.injectToggle.checked) {
      const active = this.plugin.getActivePrompt();
      const name = (active && active.name) || "inject";
      this.hint.setText("Enter sends (+ " + name + ")");
    } else {
      this.hint.setText("Enter sends (raw)");
    }
    if (this.promptSelect) this.promptSelect.disabled = !(this.injectToggle && this.injectToggle.checked);
  }

  applyMinimized() {
    const on = this.isCompact();
    if (this.contentEl) this.contentEl.toggleClass("jefr-cdp-minimized", on);
    this.applyAttachThumbSize();
    if (this.minimizeBtn) {
      this.minimizeBtn.empty();
      setIcon(this.minimizeBtn, on ? "maximize-2" : "minimize-2");
      this.minimizeBtn.setAttr("aria-label", on ? "Switch to full mode" : "Switch to compact mode");
      this.minimizeBtn.setAttr("title", on ? "Switch to full mode" : "Switch to compact mode");
    }
  }

  applyAttachThumbSize() {
    if (!this.contentEl) return;
    const n = Number(this.plugin.settings && this.plugin.settings.attachThumbSize);
    const px = Number.isFinite(n) ? Math.min(240, Math.max(16, Math.round(n))) : 26;
    this.contentEl.style.setProperty("--jefr-cdp-attach-thumb-size", px + "px");
  }

  async setMinimized(on) {
    this.plugin.settings.minimized = !!on;
    await this.plugin.saveSettings();
    this.applyMinimized();
  }

  async toggleMinimized() {
    await this.setMinimized(!this.isCompact());
  }

  stageImage(dataUrl, name) {
    if (!dataUrl || dataUrl.indexOf("data:image") !== 0) return;
    // De-dupe rapid double-fires from paste + capture handlers.
    const last = this.attachments[this.attachments.length - 1];
    if (last && last.dataUrl === dataUrl && Date.now() - (last.ts || 0) < 800) return;
    this.attachments.push({ id: makeId(), name: name || "pasted-image", dataUrl, ts: Date.now() });
    this.renderAttachments();
  }

  removeAttachment(id) {
    this.attachments = this.attachments.filter((a) => a.id !== id);
    this.renderAttachments();
  }

  renderAttachments() {
    if (!this.attachBar) return;
    this.attachBar.empty();
    if (!this.attachments.length) return;
    for (const att of this.attachments) {
      const chip = this.attachBar.createDiv({ cls: "jefr-cdp-attach-chip" });
      const img = chip.createEl("img", {
        cls: "jefr-cdp-attach-thumb",
        attr: { src: att.dataUrl, alt: att.name },
      });
      img.draggable = false;
      const x = chip.createEl("button", {
        cls: "jefr-cdp-attach-remove",
        text: "×",
        attr: { title: "Remove" },
      });
      x.onclick = () => this.removeAttachment(att.id);
    }
  }

  onPaste(e) {
    const dt = e.clipboardData;
    if (!dt) return;
    const files = [];
    if (dt.files && dt.files.length) {
      for (let i = 0; i < dt.files.length; i++) {
        if (/^image\//i.test(dt.files[i].type || "")) files.push(dt.files[i]);
      }
    }
    if (!files.length && dt.items) {
      for (let i = 0; i < dt.items.length; i++) {
        const it = dt.items[i];
        if (it.kind === "file" && /^image\//i.test(it.type || "")) {
          const f = it.getAsFile();
          if (f) files.push(f);
        }
      }
    }
    if (files.length) {
      e.preventDefault();
      e.stopPropagation();
      void this.ingestFiles(files);
      return;
    }
    // Bitmap-only clipboard (screenshots): prevent Obsidian note insert, stage via Electron.
    void this.tryClipboardImage().then((ok) => {
      if (ok) {
        try {
          e.preventDefault();
          e.stopPropagation();
        } catch {
          /* ignore */
        }
      }
    });
  }

  async ingestFiles(fileList) {
    if (!fileList || !fileList.length) return;
    for (let i = 0; i < fileList.length; i++) {
      const f = fileList[i];
      if (!f || !/^image\//i.test(f.type || "")) continue;
      try {
        const dataUrl = await fileToDataUrl(f);
        this.stageImage(dataUrl, f.name || "pasted-image");
      } catch {
        /* ignore */
      }
    }
  }

  async tryClipboardImage() {
    // 1) Async Clipboard API
    try {
      if (navigator.clipboard && navigator.clipboard.read) {
        const items = await navigator.clipboard.read();
        for (const item of items) {
          const type = (item.types || []).find((t) => /^image\//i.test(t));
          if (!type) continue;
          const blob = await item.getType(type);
          const dataUrl = await fileToDataUrl(new File([blob], "pasted-image.png", { type }));
          this.stageImage(dataUrl, "pasted-image.png");
          return true;
        }
      }
    } catch {
      /* ignore */
    }
    // 2) Electron bitmap
    const du = readClipboardImage();
    if (du) {
      this.stageImage(du, "pasted-image.png");
      return true;
    }
    // 3) Copied image files
    const files = readClipboardFileImages();
    if (files.length) {
      for (const f of files) this.stageImage(f.dataUrl, f.name);
      return true;
    }
    return false;
  }

  renderEmpty() {
    this.messagesEl.empty();
    const empty = this.messagesEl.createDiv({ cls: "jefr-cdp-empty" });
    empty.createDiv({ cls: "jefr-cdp-empty-title", text: "Direct to Agents" });
    empty.createDiv({
      cls: "jefr-cdp-empty-body",
      text: "Messages go into the focused Cursor Agents tile over CDP. No MCP queue.",
    });
  }

  updateRouteLabel(online, st) {
    if (!this.routeNameEl) return;
    // Keep jefr-cdp-full-only so compact mode never re-shows Agents/model text.
    const fullOnly = " jefr-cdp-full-only";
    if (!online) {
      this.routeNameEl.setText("CDP offline");
      this.routeModelEl.setText("");
      this.routeStatus.className = "jefr-cdp-route jefr-cdp-route-off" + fullOnly;
      this.routeStatus.setAttr("title", "Waiting for Cursor CDP");
      this.updateContextUI(null);
      this.updateWorkdirUI(null);
      return;
    }
    const f = st && st.focused;
    const busy = !!(f && (f.generating || f.planning));
    const state = !f ? (st && st.hasComposer ? "composer" : "no tile") : busy ? (f.planning ? "planning" : "busy") : "idle";
    const model = (f && f.model) || "";
    const aid = f && f.agentId ? String(f.agentId).slice(0, 8) : "";
    this.routeNameEl.setText(aid ? "Agents · " + aid : "Agents · " + state);
    this.routeModelEl.setText(model || state);
    this.routeStatus.className =
      "jefr-cdp-route " + (busy ? "jefr-cdp-route-busy" : "jefr-cdp-route-on") + fullOnly;
    this.routeStatus.setAttr(
      "title",
      ((st && st.pageTitle) || "Cursor Agents") +
        " · " +
        state +
        (model ? " · " + model : "") +
        (aid ? " · " + aid : ""),
    );
    const ctx = this.mergeContext(f && f.context, this.lastContext);
    this.updateContextUI(ctx);
    const meta = f && f.agentId ? this.plugin.getCachedAgentMeta(f.agentId) : null;
    this.updateWorkdirUI(meta);
    if (f && f.agentId && !(meta && meta.workdir && meta.envShort)) {
      void this.plugin.ensureAgentMeta(f.agentId).then((saved) => {
        if (saved) this.updateWorkdirUI(saved);
      });
    }
  }

  updateWorkdirUI(meta) {
    if (!this.routeWorkdirEl) return;
    const workdir = meta && meta.workdir ? String(meta.workdir) : "";
    if (!workdir) {
      this.routeWorkdirEl.setText("");
      this.routeWorkdirEl.className = "jefr-cdp-workdir jefr-cdp-workdir-empty";
      // aria-label only — Obsidian renders its tooltip from that; a title= attr
      // would also fire the native browser tooltip (double popups).
      this.routeWorkdirEl.removeAttribute("title");
      this.routeWorkdirEl.setAttr("aria-label", "Working directory unavailable");
      return;
    }
    const branch = meta && meta.branch ? String(meta.branch) : "";
    const repo = meta && meta.repo ? String(meta.repo) : "";
    const envShort = meta && meta.envShort ? String(meta.envShort) : "";
    const envLabel = meta && meta.envLabel ? String(meta.envLabel) : "";
    const base = workdir.replace(/[\\/]+$/, "").split(/[\\/]/).pop() || workdir;
    const label = [base, branch || null, envShort || null].filter(Boolean).join(" · ");
    const tipBits = [
      workdir,
      repo || null,
      branch ? "branch " + branch : null,
      envLabel || envShort || null,
      meta.createdVia || null,
    ].filter(Boolean);
    this.routeWorkdirEl.setText(label);
    this.routeWorkdirEl.className = "jefr-cdp-workdir";
    this.routeWorkdirEl.removeAttribute("title");
    this.routeWorkdirEl.setAttr("aria-label", tipBits.join(" · "));
  }

  mergeContext(quick, detail) {
    const q = quick && typeof quick === "object" ? quick : null;
    const d = detail && typeof detail === "object" ? detail : null;
    if (!q && !d) return null;
    const percent =
      q && q.percent != null ? q.percent : d && d.percent != null ? d.percent : null;
    return {
      percent,
      label: (q && q.label) || (d && d.label) || (percent != null ? "Context " + percent + "%" : ""),
      tokensLabel: (d && d.tokensLabel) || (q && q.tokensLabel) || "",
      used: d && d.used != null ? d.used : q && q.used != null ? q.used : null,
      limit: d && d.limit != null ? d.limit : q && q.limit != null ? q.limit : null,
      categories: (d && d.categories) || (q && q.categories) || [],
      summary: (d && d.summary) || "",
    };
  }

  formatTokenShort(n) {
    if (n == null || !Number.isFinite(n)) return "";
    if (n >= 1e6) return (Math.round((n / 1e6) * 10) / 10) + "M";
    if (n >= 1e3) return (Math.round((n / 1e3) * 10) / 10) + "K";
    return String(Math.round(n));
  }

  /** True only when user opted into tray peeks (Settings → Full context tokens). */
  contextTokensEnabled() {
    if (this.plugin.settings.showContextTokens !== true) return false;
    const n = Number(this.plugin.settings.contextDetailMs);
    return Number.isFinite(n) && n > 0;
  }

  updateContextUI(ctx) {
    if (!this.routeContextEl) return;
    if (this.plugin.settings.showContextUsage === false) {
      this.routeContextEl.addClass("jefr-cdp-context-hidden");
      return;
    }
    this.routeContextEl.removeClass("jefr-cdp-context-hidden");
    const showTokens = this.contextTokensEnabled();
    this.routeContextEl.toggleClass("jefr-cdp-context-pct-only", !showTokens);
    if (!ctx || ctx.percent == null) {
      this.routeContextPctEl.setText("—");
      this.routeContextTokensEl.setText("");
      this.routeContextEl.className =
        "jefr-cdp-context jefr-cdp-context-empty" + (showTokens ? "" : " jefr-cdp-context-pct-only");
      this.routeContextEl.setAttr("title", "Context usage unavailable");
      this.routeContextEl.setAttr("aria-label", "Context usage unavailable");
      return;
    }
    const pct = Math.max(0, Math.min(100, Math.round(Number(ctx.percent))));
    this.routeContextPctEl.setText(pct + "%");
    let tokens = "";
    if (showTokens) {
      if (ctx.used != null && ctx.limit != null) {
        tokens = this.formatTokenShort(ctx.used) + "/" + this.formatTokenShort(ctx.limit);
      } else if (ctx.tokensLabel) {
        tokens = String(ctx.tokensLabel).replace(/\s*Tokens\s*$/i, "").replace(/^~/, "").trim();
      }
    }
    this.routeContextTokensEl.setText(tokens);
    let level = "ok";
    if (pct >= 90) level = "danger";
    else if (pct >= 70) level = "warn";
    this.routeContextEl.className =
      "jefr-cdp-context jefr-cdp-context-" + level + (showTokens ? "" : " jefr-cdp-context-pct-only");
    const bits = [ctx.label || ("Context " + pct + "%")];
    if (showTokens) {
      if (ctx.tokensLabel) bits.push(ctx.tokensLabel);
      else if (tokens) bits.push(tokens);
      if (Array.isArray(ctx.categories) && ctx.categories.length) {
        bits.push(
          ctx.categories
            .slice(0, 8)
            .map((c) => c.label + " " + c.value)
            .join(" · "),
        );
      }
    }
    this.routeContextEl.setAttr("title", bits.join("\n"));
    this.routeContextEl.setAttr("aria-label", "Context " + pct + "%");
  }

  async refreshContextDetail(force) {
    if (this.plugin.settings.showContextUsage === false) return;
    if (!this.contextTokensEnabled()) return;
    if (this._contextDetailBusy) return;
    const detailMs = Math.max(0, Number(this.plugin.settings.contextDetailMs) || 0);
    const now = Date.now();
    if (!force && now - (this._lastContextDetailAt || 0) < detailMs) return;
    if (!this.plugin.cdp.connected) return;
    this._contextDetailBusy = true;
    try {
      const detail = await this.plugin.contextDetail();
      this._lastContextDetailAt = Date.now();
      if (detail && detail.ok) {
        this.lastContext = {
          percent: detail.percent,
          label: detail.label,
          tokensLabel: detail.tokensLabel,
          used: detail.used,
          limit: detail.limit,
          categories: detail.categories || [],
          summary: detail.summary || "",
        };
        const quick = this.lastStatus && this.lastStatus.focused && this.lastStatus.focused.context;
        this.updateContextUI(this.mergeContext(quick, this.lastContext));
      }
    } catch {
      /* ignore — percent from status poll still works */
    } finally {
      this._contextDetailBusy = false;
    }
  }

  async refreshStatus() {
    const online = this.plugin.cdp.connected;
    if (this.statusPill) {
      this.statusPill.setText(online ? "CDP online" : "CDP offline");
      this.statusPill.className = "jefr-cdp-pill " + (online ? "jefr-cdp-pill-on" : "jefr-cdp-pill-off");
    }

    if (!online) {
      if (this.tilePill) {
        this.tilePill.setText("No tile");
        this.tilePill.className = "jefr-cdp-pill jefr-cdp-pill-idle";
      }
      if (this.metaLine) {
        this.metaLine.setText(
          "Waiting for Cursor CDP on " + this.plugin.settings.cdpHost + ":" + this.plugin.settings.cdpPort,
        );
      }
      this.updateRouteLabel(false, null);
      return;
    }

    try {
      const st = await this.plugin.tileStatus();
      this.lastStatus = st;
      const f = st && st.focused;
      if (this.tilePill) {
        if (!f) {
          this.tilePill.setText(st && st.hasComposer ? "Composer" : "No tile");
          this.tilePill.className = "jefr-cdp-pill jefr-cdp-pill-idle";
        } else {
          const busy = f.generating || f.planning;
          this.tilePill.setText(busy ? (f.planning ? "Planning" : "Busy") : "Idle");
          this.tilePill.className = "jefr-cdp-pill " + (busy ? "jefr-cdp-pill-busy" : "jefr-cdp-pill-ready");
        }
      }
      const title = (st && st.pageTitle) || this.plugin.cdp.pageTitle || "Agents";
      const model = (f && f.model) || "—";
      const aid = f && f.agentId ? String(f.agentId).slice(0, 8) : "—";
      const ctx = this.mergeContext(f && f.context, this.lastContext);
      const ctxBit =
        ctx && ctx.percent != null
          ? " · ctx " +
            Math.round(ctx.percent) +
            "%" +
            (this.contextTokensEnabled() && ctx.used != null && ctx.limit != null
              ? " (" + this.formatTokenShort(ctx.used) + "/" + this.formatTokenShort(ctx.limit) + ")"
              : "")
          : "";
      if (this.metaLine) {
        this.metaLine.setText(
          title.slice(0, 48) +
            " · tiles " +
            (st.tileCount || 0) +
            " · model " +
            model +
            " · id " +
            aid +
            ctxBit,
        );
      }
      this.updateRouteLabel(true, st);
      void this.refreshContextDetail(false);
    } catch (e) {
      if (this.tilePill) {
        this.tilePill.setText("Error");
        this.tilePill.className = "jefr-cdp-pill jefr-cdp-pill-off";
      }
      if (this.metaLine) this.metaLine.setText(String(e.message || e));
      this.updateRouteLabel(false, null);
      await this.plugin.cdp.close();
      this.plugin.scheduleReconnect();
    }
  }

  /**
   * Step through previously sent input. delta -1 = older, +1 = newer.
   * @returns {boolean} true if the input value was changed
   */
  recallInputHistory(delta) {
    if (!this.inputHistory.length) return false;

    if (this.inputHistoryIndex < 0) {
      if (delta >= 0) return false;
      this.inputHistoryDraft = this.input.value;
      this.inputHistoryIndex = this.inputHistory.length - 1;
    } else {
      this.inputHistoryIndex += delta;
    }

    if (this.inputHistoryIndex < 0) {
      this.inputHistoryIndex = 0;
      this.input.value = this.inputHistory[0];
    } else if (this.inputHistoryIndex >= this.inputHistory.length) {
      this.inputHistoryIndex = -1;
      this.input.value = this.inputHistoryDraft;
    } else {
      this.input.value = this.inputHistory[this.inputHistoryIndex];
    }

    const n = this.input.value.length;
    this.input.setSelectionRange(n, n);
    return true;
  }

  pushInputHistory(text) {
    const t = String(text || "").trim();
    if (!t) return;
    const last = this.inputHistory[this.inputHistory.length - 1];
    if (last === t) return;
    this.inputHistory.push(t);
    const max = Math.max(20, this.plugin.settings.maxHistory || 200);
    while (this.inputHistory.length > max) this.inputHistory.shift();
    this.inputHistoryIndex = -1;
    this.inputHistoryDraft = "";
  }

  appendHistory(item) {
    if (this.history.length === 0) this.messagesEl.empty();
    this.history.push(item);
    while (this.history.length > (this.plugin.settings.maxHistory || 200)) {
      this.history.shift();
      const first = this.messagesEl.firstElementChild;
      if (first) first.remove();
    }
    const row = this.messagesEl.createDiv({ cls: "jefr-cdp-msg jefr-cdp-msg-" + item.kind });
    const head = row.createDiv({ cls: "jefr-cdp-msg-head" });
    head.createSpan({ cls: "jefr-cdp-msg-role", text: item.kind === "out" ? "You → agent" : "System" });
    head.createSpan({
      cls: "jefr-cdp-msg-time",
      text: new Date(item.ts).toLocaleTimeString(),
    });
    const body = row.createDiv({ cls: "jefr-cdp-msg-body" });
    body.setText(item.text);
    this.scrollEl.scrollTop = this.scrollEl.scrollHeight;
  }

  async sendCurrent() {
    if (this.sending) return;
    const text = (this.input.value || "").trim();
    const images = this.attachments.slice();
    if (!text && !images.length) return;
    this.sending = true;
    this.sendBtn.setAttr("disabled", "true");
    try {
      const injected = !!this.plugin.settings.injectEnabled && !!text;
      const { payload, imageCount } = await this.plugin.sendToAgent(text, images);
      if (text) this.pushInputHistory(text);
      this.input.value = "";
      this.inputHistoryIndex = -1;
      this.inputHistoryDraft = "";
      this.focusComposer();
      this.attachments = [];
      this.renderAttachments();
      const bits = [];
      if (text) bits.push(injected ? text + "\n\n— inject (" + (payload || "").length + " chars) —" : text);
      if (imageCount) bits.push("[" + imageCount + " image" + (imageCount === 1 ? "" : "s") + " via CDP paste]");
      this.appendHistory({ kind: "out", ts: Date.now(), text: bits.join("\n") });
      // Context updates after the agent digests the turn — refresh tokens shortly (if enabled).
      if (this.contextTokensEnabled()) {
        this._lastContextDetailAt = 0;
        window.setTimeout(() => {
          void this.refreshContextDetail(true);
        }, 1600);
      }
      // Inject-once: new agent armed Inject; first successful send turns it off.
      const unticked = await this.plugin.consumeInjectOnce();
      if (unticked) {
        this.appendHistory({
          kind: "sys",
          ts: Date.now(),
          text: "Inject off (one-shot after new agent)",
        });
      }
    } catch (e) {
      new Notice("JEFR CDP: " + (e.message || e));
      this.appendHistory({ kind: "sys", ts: Date.now(), text: String(e.message || e) });
    } finally {
      this.sending = false;
      this.sendBtn.removeAttribute("disabled");
      void this.refreshStatus();
    }
  }

  async onNewAgent() {
    if (this._newAgentBusy) return;
    this._newAgentBusy = true;
    try {
      await this.plugin.newAgent();
      new Notice("JEFR CDP: Ctrl+N sent");
      this.appendHistory({ kind: "sys", ts: Date.now(), text: "Sent Ctrl+N (new agent)" });
      await sleep(300);
      void this.refreshStatus();
    } catch (e) {
      new Notice("JEFR CDP: " + (e.message || e));
    } finally {
      this._newAgentBusy = false;
    }
  }
}

/* ------------------------------------------------------------------ */
/* Settings                                                            */
/* ------------------------------------------------------------------ */

class JefrCdpSettingTab extends PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  display() {
    const { containerEl } = this;
    containerEl.empty();
    containerEl.createEl("h2", { text: "JEFR CDP" });
    containerEl.createEl("p", {
      text: "Direct CDP bridge to Cursor Agents. Launch Cursor with --remote-debugging-port=9222.",
    });

    new Setting(containerEl)
      .setName("CDP host")
      .setDesc("Usually 127.0.0.1")
      .addText((t) =>
        t.setValue(this.plugin.settings.cdpHost).onChange(async (v) => {
          this.plugin.settings.cdpHost = (v || "127.0.0.1").trim() || "127.0.0.1";
          await this.plugin.saveSettings();
        }),
      );

    new Setting(containerEl)
      .setName("CDP port")
      .setDesc("Cursor --remote-debugging-port")
      .addText((t) =>
        t.setValue(String(this.plugin.settings.cdpPort)).onChange(async (v) => {
          const n = parseInt(v, 10);
          this.plugin.settings.cdpPort = Number.isFinite(n) && n > 0 ? n : 9222;
          await this.plugin.saveSettings();
        }),
      );

    new Setting(containerEl)
      .setName("Inject prompt by default")
      .setDesc("Prepend the selected prompt bookmark when sending")
      .addToggle((t) =>
        t.setValue(!!this.plugin.settings.injectEnabled).onChange(async (v) => {
          this.plugin.settings.injectEnabled = !!v;
          if (!v) this.plugin._injectOncePending = false;
          await this.plugin.saveSettings();
        }),
      );

    new Setting(containerEl)
      .setName("Inject once on new agent")
      .setDesc(
        "When creating a new agent (button or command), turn Inject on. After the first message sent to that agent, turn Inject off automatically.",
      )
      .addToggle((t) =>
        t.setValue(this.plugin.settings.injectOnNewAgent !== false).onChange(async (v) => {
          this.plugin.settings.injectOnNewAgent = !!v;
          if (!v) this.plugin._injectOncePending = false;
          await this.plugin.saveSettings();
        }),
      );

    containerEl.createEl("h3", { text: "Prompt bookmarks" });

    normalizePromptSettings(this.plugin.settings);
    const bookmarks = this.plugin.settings.promptBookmarks;
    const active = this.plugin.getActivePrompt();

    new Setting(containerEl)
      .setName("Bookmark")
      .setDesc("Switch from here or the route bar. {{message}} = your typed text.")
      .addDropdown((d) => {
        for (const b of bookmarks) d.addOption(b.id, b.name);
        d.setValue(active.id);
        d.onChange(async (v) => {
          await this.plugin.setActivePrompt(v);
          this.display();
        });
      })
      .addButton((btn) =>
        btn.setButtonText("Add").onClick(async () => {
          const cur = this.plugin.getActivePrompt();
          const created = await this.plugin.upsertPromptBookmark({
            id: makeId(),
            name: "Custom",
            template: (cur && cur.template) || DEFAULT_INJECT,
          });
          await this.plugin.setActivePrompt(created.id);
          this.display();
        }),
      )
      .addButton((btn) =>
        btn.setButtonText("Delete").setWarning().onClick(async () => {
          try {
            await this.plugin.deletePromptBookmark(active.id);
            this.display();
          } catch (e) {
            new Notice("JEFR CDP: " + (e.message || e));
          }
        }),
      )
      .addButton((btn) =>
        btn.setButtonText("Reset built-ins").onClick(async () => {
          this.plugin.settings.promptBookmarks = defaultPromptBookmarks();
          this.plugin.settings.activePromptId = "bm-no-mcp-log";
          normalizePromptSettings(this.plugin.settings);
          await this.plugin.saveSettings();
          this.display();
        }),
      );

    new Setting(containerEl)
      .setName("Name")
      .addText((t) => {
        t.setValue(active.name);
        t.onChange(async (v) => {
          active.name = String(v || "").trim() || "Prompt";
          await this.plugin.upsertPromptBookmark(active);
        });
      });

    new Setting(containerEl)
      .setName("Template")
      .addTextArea((t) => {
        t.setValue(active.template);
        t.inputEl.rows = 8;
        t.inputEl.style.width = "100%";
        t.inputEl.style.fontFamily = "var(--font-monospace)";
        t.onChange(async (v) => {
          active.template = v;
          await this.plugin.upsertPromptBookmark(active);
        });
      });

    new Setting(containerEl)
      .setName("Compact mode by default")
      .setDesc(
        "Default view: workdir + context % + Inject + New agent. Prompt bookmark, attach, reconnect, and full/compact switch live under the pane ⋮ menu.",
      )
      .addToggle((t) =>
        t.setValue(this.plugin.settings.minimized !== false).onChange(async (v) => {
          this.plugin.settings.minimized = !!v;
          await this.plugin.saveSettings();
          this.plugin.app.workspace.getLeavesOfType(VIEW_TYPE).forEach((leaf) => {
            if (leaf.view instanceof JefrCdpView) leaf.view.applyMinimized();
          });
        }),
      );

    new Setting(containerEl)
      .setName("Compact paste thumbnail size")
      .setDesc("Width/height (px) of pasted image thumbnails in compact mode. Default 26.")
      .addText((t) =>
        t.setValue(String(this.plugin.settings.attachThumbSize || 26)).onChange(async (v) => {
          const n = parseInt(v, 10);
          this.plugin.settings.attachThumbSize = Number.isFinite(n)
            ? Math.min(240, Math.max(16, n))
            : 26;
          await this.plugin.saveSettings();
          this.plugin.app.workspace.getLeavesOfType(VIEW_TYPE).forEach((leaf) => {
            if (leaf.view instanceof JefrCdpView) leaf.view.applyAttachThumbSize();
          });
        }),
      );

    new Setting(containerEl)
      .setName("Auto-reconnect")
      .addToggle((t) =>
        t.setValue(!!this.plugin.settings.autoReconnect).onChange(async (v) => {
          this.plugin.settings.autoReconnect = !!v;
          await this.plugin.saveSettings();
        }),
      );

    new Setting(containerEl)
      .setName("Show context usage")
      .setDesc("Read the Agents status-bar context % over CDP and show a compact chip on the route bar")
      .addToggle((t) =>
        t.setValue(this.plugin.settings.showContextUsage !== false).onChange(async (v) => {
          this.plugin.settings.showContextUsage = !!v;
          await this.plugin.saveSettings();
        }),
      );

    new Setting(containerEl)
      .setName("Full context tokens")
      .setDesc(
        "Off by default. When on, briefly opens the Agents context tray to read used/limit tokens (can flicker that window). Percent-only needs no tray.",
      )
      .addToggle((t) =>
        t.setValue(this.plugin.settings.showContextTokens === true).onChange(async (v) => {
          this.plugin.settings.showContextTokens = !!v;
          if (v && !(Number(this.plugin.settings.contextDetailMs) > 0)) {
            this.plugin.settings.contextDetailMs = 8000;
          }
          await this.plugin.saveSettings();
          this.plugin.app.workspace.getLeavesOfType(VIEW_TYPE).forEach((leaf) => {
            if (leaf.view instanceof JefrCdpView) {
              leaf.view.lastContext = null;
              void leaf.view.refreshStatus();
            }
          });
        }),
      );

    if (this.plugin.settings.showContextTokens === true) {
      new Setting(containerEl)
        .setName("Context token refresh (ms)")
        .setDesc("How often to peek the Agents context tray while Full context tokens is on. Minimum useful value ~3000.")
        .addText((t) =>
          t.setValue(String(this.plugin.settings.contextDetailMs || 8000)).onChange(async (v) => {
            const n = parseInt(v, 10);
            this.plugin.settings.contextDetailMs = Number.isFinite(n) && n >= 0 ? n : 8000;
            await this.plugin.saveSettings();
          }),
        );
    }
  }
}

module.exports = JefrCdpPlugin;
