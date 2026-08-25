'use strict';

const fs = require('fs');
const path = require('path');
const { Plugin, ItemView, Notice, PluginSettingTab, Setting, Scope } = require('obsidian');

const VIEW_TYPE = 'jefr-gemini';
const DEFAULT_PORT = 17381;
const HELLO_STALE_MS = 20000;
const IDLE_HOLD_MS = 2500;
const MAX_IMAGES = 6;
const MAX_IMAGE_CHARS = 8 * 1024 * 1024;
const RANK = { streaming: 2, finished: 1, idle: 0 };

const DEFAULT_SETTINGS = {
  port: DEFAULT_PORT,
};

function makeId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function fmtElapsed(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const m = Math.floor(s / 60);
  const r = s % 60;
  if (m >= 60) {
    const h = Math.floor(m / 60);
    return h + ':' + String(m % 60).padStart(2, '0') + ':' + String(r).padStart(2, '0');
  }
  return m + ':' + String(r).padStart(2, '0');
}

function getElectron() {
  try {
    return require('electron');
  } catch (_) {
    return null;
  }
}

function writeClipboardImage(dataUrl) {
  const electron = getElectron();
  if (!electron) throw new Error('electron unavailable');
  const nativeImage = electron.nativeImage || (electron.remote && electron.remote.nativeImage);
  const clipboard = electron.clipboard || (electron.remote && electron.remote.clipboard);
  if (!nativeImage || !clipboard) throw new Error('electron clipboard/nativeImage missing');
  const img = nativeImage.createFromDataURL(dataUrl);
  if (!img || (typeof img.isEmpty === 'function' && img.isEmpty())) {
    throw new Error('invalid image data');
  }
  clipboard.writeImage(img);
}

function readClipboardImage() {
  try {
    const electron = getElectron();
    if (!electron) return '';
    const clipboard = electron.clipboard || (electron.remote && electron.remote.clipboard);
    if (!clipboard || typeof clipboard.readImage !== 'function') return '';
    const img = clipboard.readImage();
    if (!img || (typeof img.isEmpty === 'function' && img.isEmpty())) return '';
    return img.toDataURL() || '';
  } catch (_) {
    return '';
  }
}

function readClipboardFileImages() {
  const out = [];
  try {
    const electron = getElectron();
    const clip = electron && electron.clipboard;
    if (!clip) return out;
    let txt = '';
    try {
      if (typeof clip.read === 'function') txt = clip.read('text/uri-list') || '';
    } catch (_) {}
    if (!txt && typeof clip.readText === 'function') txt = clip.readText() || '';
    if (!txt) return out;
    const imageExts = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'];
    const uris = txt.split(/\r?\n/).map((s) => s.trim()).filter((s) => s && s[0] !== '#');
    for (const uri of uris) {
      let p = uri;
      if (/^file:\/\//i.test(p)) {
        p = decodeURIComponent(p.replace(/^file:\/\//i, ''));
        if (/^\/[A-Za-z]:/.test(p)) p = p.slice(1);
      }
      const ext = (path.extname(p).slice(1) || '').toLowerCase();
      if (imageExts.indexOf(ext) === -1) continue;
      try {
        const buf = fs.readFileSync(p);
        const mime = ext === 'jpg' || ext === 'jpeg' ? 'image/jpeg' : 'image/' + ext;
        out.push({ dataUrl: 'data:' + mime + ';base64,' + buf.toString('base64'), name: path.basename(p) });
      } catch (_) {}
    }
  } catch (_) {}
  return out;
}

function fileToDataUrl(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result || ''));
    r.onerror = () => reject(new Error('read failed'));
    r.readAsDataURL(file);
  });
}

function nodeHttp() {
  try {
    return require('http');
  } catch (_) {
    return null;
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

function json(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

class BridgeServer {
  constructor(plugin) {
    this.plugin = plugin;
    this.server = null;
    this.queue = [];
    this.lastHello = 0;
    this.lastAck = null;
    this.lastBusy = false;
    this.expectAnswer = false;
    this.expectAt = 0;
    this.answeringSince = 0;
    this.answer = { state: 'idle', finished: true };
    this.questions = 0;
    this.model = '';
    this.thinking = '';
    this.lastActiveAt = 0;
    this.tabs = new Map();
    this.lastSendTabId = '';
    this.waiters = [];
  }

  pruneTabs(now) {
    const parked = new Set(this.waiters.map((w) => String(w.tabId || '')));
    for (const [id, row] of this.tabs) {
      if (parked.has(id)) continue;
      if (now - row.at > HELLO_STALE_MS) this.tabs.delete(id);
    }
  }

  aggregateAnswer(now) {
    this.pruneTabs(now);
    let best = 'idle';
    for (const row of this.tabs.values()) {
      if ((RANK[row.state] || 0) > (RANK[best] || 0)) best = row.state;
    }
    if (best !== 'idle') {
      this.lastActiveAt = now;
      return { state: best, finished: best === 'finished' };
    }
    if (this.answer.state !== 'idle' && now - this.lastActiveAt < IDLE_HOLD_MS) {
      return this.answer;
    }
    return { state: 'idle', finished: true };
  }

  latestQuestions() {
    let best = null;
    for (const row of this.tabs.values()) {
      if (!best || row.at > best.at) best = row;
    }
    return best && Number.isFinite(best.questions) ? best.questions : 0;
  }

  latestModel() {
    let best = null;
    for (const row of this.tabs.values()) {
      if (!best || row.at > best.at) best = row;
    }
    return (best && best.model) || '';
  }

  latestThinking() {
    let best = null;
    for (const row of this.tabs.values()) {
      if (!best || row.at > best.at) best = row;
    }
    return (best && best.thinking) || '';
  }

  noteHello(body) {
    const now = Date.now();
    this.lastHello = now;
    const id = String((body && (body.tabId || body.tab || body.chromeTabId)) || '');
    if (body && body.heartbeat) {
      this.touchTab(id);
      return;
    }
    const raw = String((body && body.answer) || '').toLowerCase();
    const state =
      raw === 'streaming' || raw === 'finished' || raw === 'idle' ? raw : 'idle';
    const q = Number(body && body.questions);
    const questions = Number.isFinite(q) && q >= 0 ? Math.floor(q) : 0;
    const model = String((body && body.model) || '')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 48);
    const thinking = String((body && body.thinking) || '')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 80);
    this.tabs.set(id || 'default', { state, at: now, questions, model, thinking });
    this.answer = this.aggregateAnswer(now);
    this.questions = this.latestQuestions();
    this.model = this.latestModel();
    this.thinking = this.latestThinking();
    if (this.expectAnswer) {
      if (state === 'streaming' || state === 'finished') this.expectAnswer = false;
      else if (this.expectAt && now - this.expectAt > 120000) this.expectAnswer = false;
    }
  }

  listening() {
    return !!(this.server && this.server.listening);
  }

  geminiLive() {
    if (this.waiters.some((w) => w && !w.settled)) return true;
    return this.lastHello > 0 && Date.now() - this.lastHello < HELLO_STALE_MS;
  }

  enqueue(text, action, images) {
    const pics = Array.isArray(images)
      ? images
          .filter((a) => a && a.dataUrl && String(a.dataUrl).indexOf('data:image') === 0)
          .slice(0, MAX_IMAGES)
          .map((a) => ({
            name: String(a.name || 'image'),
            dataUrl: String(a.dataUrl).slice(0, MAX_IMAGE_CHARS),
          }))
      : [];
    const job = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
      action: action === 'newchat' ? 'newchat' : action === 'copy' ? 'copy' : 'send',
      text: String(text || ''),
      images: pics,
      ts: Date.now(),
      leased: 0,
      warned: false,
    };
    this.queue.push(job);
    this.flushWaiters();
    return job;
  }

  touchTab(id) {
    const key = String(id || '');
    if (!key) return;
    const prev = this.tabs.get(key);
    if (prev) {
      prev.at = Date.now();
      return;
    }
    this.tabs.set(key, {
      state: 'idle',
      at: Date.now(),
      questions: this.questions,
      model: this.model,
      thinking: '',
    });
  }

  flushWaiters() {
    for (const w of [...this.waiters]) {
      if (!w.ready || typeof w.done !== 'function') continue;
      const jobs = this.dueJobs(w.tabId);
      if (jobs.length) w.done(jobs);
    }
  }

  ownerTabId() {
    this.pruneTabs(Date.now());
    if (this.lastSendTabId && this.tabs.has(this.lastSendTabId)) return this.lastSendTabId;
    let best = null;
    for (const [id, row] of this.tabs) {
      if (!best || row.at > best.at) best = { id, at: row.at };
    }
    return best ? best.id : '';
  }

  dueJobs(callerId) {
    const now = Date.now();
    const LEASE_MS = 45000;
    for (const job of this.queue) {
      if (job.leased && now - job.leased > LEASE_MS) {
        if (!job.warned) {
          new Notice('JEFR Gemini: job timed out waiting for ack');
          job.warned = true;
        }
        job.leased = 0;
      }
    }
    const owner = this.ownerTabId();
    const caller = String(callerId || '');
    if (!owner || !caller || caller !== owner) return [];
    const due = this.queue.filter((job) => !job.leased);
    for (const job of due) job.leased = now;
    const out = due.map((job) => ({
      id: job.id,
      action: job.action || 'send',
      text: job.text,
      images: job.images || [],
      ts: job.ts,
    }));
    const hasSend = out.some((job) => {
      const a = job.action || 'send';
      return a !== 'newchat' && a !== 'copy';
    });
    if (hasSend) {
      this.expectAnswer = true;
      this.expectAt = Date.now();
      if (!this.answeringSince) this.answeringSince = this.expectAt;
    } else if (out.some((job) => job.action === 'newchat')) {
      this.expectAnswer = false;
      this.thinking = '';
      this.answeringSince = 0;
    }
    return out;
  }

  ackJob(body) {
    const id = body && body.id;
    const action = String((body && body.action) || '');
    this.lastAck = {
      id,
      ok: !!body.ok,
      error: String((body && body.error) || ''),
      action,
      ts: Date.now(),
    };
    if (id) this.queue = this.queue.filter((j) => j.id !== id);
    if (body && body.ok === false && (action === 'send' || !action)) {
      this.expectAnswer = false;
    }
    if (body && body.ok && (action === 'send' || !action)) {
      const n = Number(body && body.chromeTabId);
      if (Number.isFinite(n) && n > 0) this.lastSendTabId = String(n);
    }
    if (body && body.ok && action === 'copy') {
      this.plugin.notifyCopyToast();
    } else if (body && body.ok === false && this.lastAck.error) {
      new Notice('JEFR Gemini: ' + this.lastAck.error);
    }
  }

  start(port) {
    const http = nodeHttp();
    if (!http) throw new Error('http module unavailable (desktop only)');
    this.stop();
    this.server = http.createServer((req, res) => {
      void this.handle(req, res);
    });
    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(port, '127.0.0.1', () => resolve());
    });
  }

  stop() {
    if (!this.server) return;
    try {
      this.server.close();
    } catch (_) {}
    this.server = null;
    for (const w of this.waiters) {
      try {
        w.done([]);
      } catch (_) {}
    }
    this.waiters = [];
  }

  async handle(req, res) {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      });
      res.end();
      return;
    }

    const url = String(req.url || '/').split('?')[0];
    try {
      if (req.method === 'POST' && url === '/hello') {
        const body = await readBody(req);
        const before = this.answer.state;
        const beforeModel = this.model;
        const beforeThink = this.thinking;
        this.noteHello(body);
        if (body && body.heartbeat) {
          json(res, 200, { ok: true, jobs: [] });
          return;
        }
        this.lastBusy = !!(body && body.busy);
        if (
          this.answer.state !== before ||
          this.model !== beforeModel ||
          this.thinking !== beforeThink
        ) {
          this.plugin.notifyViews();
        }
        const caller = String((body && (body.tabId || body.chromeTabId)) || '');
        const jobs = body.ready ? this.dueJobs(caller) : [];
        if (jobs.length) this.plugin.notifyViews();
        json(res, 200, { ok: true, jobs });
        return;
      }
      if (req.method === 'POST' && url === '/wait') {
        const body = await readBody(req);
        const caller = String((body && (body.tabId || body.chromeTabId)) || '');
        this.touchTab(caller);
        this.lastHello = Date.now();
        const ready = !!(body && body.ready);
        const timeout = Math.min(30000, Math.max(1000, Number(body && body.timeout) || 25000));
        const jobs = await new Promise((resolve) => {
          const w = { tabId: caller, ready, settled: false };
          const done = (list) => {
            if (w.settled) return;
            w.settled = true;
            clearTimeout(w.timer);
            this.waiters = this.waiters.filter((x) => x !== w);
            this.lastHello = Date.now();
            resolve(Array.isArray(list) ? list : []);
          };
          w.done = done;
          w.timer = setTimeout(() => done([]), timeout);
          // req 'close' fires when the POST body is finished — that would
          // end the long-poll immediately. Watch the response instead.
          res.on('close', () => done([]));
          this.waiters.push(w);
          if (ready) {
            const due = this.dueJobs(caller);
            if (due.length) done(due);
          }
        });
        json(res, 200, { ok: true, jobs });
        return;
      }
      if (req.method === 'POST' && url === '/ack') {
        const body = await readBody(req);
        this.ackJob(body);
        this.plugin.notifyViews();
        json(res, 200, { ok: true });
        return;
      }
      if (req.method === 'POST' && url === '/clip-image') {
        const body = await readBody(req);
        const dataUrl = String((body && body.dataUrl) || '');
        if (!dataUrl || dataUrl.indexOf('data:image') !== 0) {
          json(res, 400, { ok: false, error: 'no image' });
          return;
        }
        try {
          writeClipboardImage(dataUrl);
          json(res, 200, { ok: true });
        } catch (e) {
          json(res, 500, { ok: false, error: String(e.message || e) });
        }
        return;
      }
      if (req.method === 'GET' && url === '/status') {
        json(res, 200, {
          ok: true,
          pending: this.queue.length,
          gemini: this.geminiLive(),
          answer: this.answer,
          model: this.model,
          lastAck: this.lastAck,
          lastSendTabId: this.lastSendTabId,
        });
        return;
      }
      json(res, 404, { ok: false, error: 'not found' });
    } catch (e) {
      json(res, 500, { ok: false, error: String(e.message || e) });
    }
  }
}

class JefrGeminiView extends ItemView {
  constructor(leaf, plugin) {
    super(leaf);
    this.plugin = plugin;
    this.input = null;
    this.pillEl = null;
    this.timerEl = null;
    this.thinkEl = null;
    this.modelEl = null;
    this.metaEl = null;
    this.contextEl = null;
    this.routeEl = null;
    this.sending = false;
    this._copyBusy = false;
    this.inputHistory = [];
    this.inputHistoryIndex = -1;
    this.inputHistoryDraft = '';
    this.pollTimer = null;
    this.attachments = [];
    this.attachBar = null;
    this._docPasteHandler = null;
    // Same as jefr CDP: ItemView.scope, parented so other hotkeys fall through.
    this.scope = new Scope(this.app.scope);
    this.scope.register(['Mod'], 'N', (e) => {
      if (e) e.preventDefault();
      void this.newChat();
      return false;
    });
    this.scope.register(['Mod'], 'C', (e) => {
      if (this.hasCopyableSelection()) return true;
      if (e) e.preventDefault();
      void this.copyLast();
      return false;
    });
  }

  getViewType() {
    return VIEW_TYPE;
  }

  getDisplayText() {
    return 'JEFR Gemini';
  }

  getIcon() {
    return 'sparkles';
  }

  async onOpen() {
    this.buildUI();
    this.refreshStatus();
    this.pollTimer = window.setInterval(() => this.refreshStatus(), 250);
    this.registerEvent(
      this.app.workspace.on('active-leaf-change', (leaf) => {
        if (leaf === this.leaf && this._activeLeaf !== this.leaf) this.focusComposer();
        this._activeLeaf = leaf;
      }),
    );
    this.registerDomEvent(this.containerEl, 'pointerdown', (e) => this.onPanePointer(e));
    this.registerDomEvent(
      window,
      'keydown',
      (e) => {
        if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey) return;
        const within = this.contentEl && this.contentEl.contains(/** @type {Node} */ (e.target));
        const leafActive = this.app.workspace.activeLeaf === this.leaf;
        if (!within && !leafActive) return;
        if (e.key === 'n' || e.key === 'N') {
          e.preventDefault();
          e.stopImmediatePropagation();
          void this.newChat();
          return;
        }
        if (e.key !== 'c' && e.key !== 'C') return;
        if (this.hasCopyableSelection()) return;
        e.preventDefault();
        e.stopImmediatePropagation();
        void this.copyLast();
      },
      true,
    );
    this.focusComposer();
  }

  async onClose() {
    if (this.pollTimer) window.clearInterval(this.pollTimer);
    this.pollTimer = null;
    if (this._docPasteHandler) {
      document.removeEventListener('paste', this._docPasteHandler, true);
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
    if (t.closest('textarea, input, select, button, a, .clickable-icon, .menu, label')) return;
    this.focusComposer();
  }

  buildUI() {
    const root = this.contentEl;
    root.empty();
    root.addClass('jefr-gem-root');

    const dock = root.createDiv({ cls: 'jefr-gem-dock' });
    const bar = dock.createDiv({ cls: 'jefr-gem-routebar' });
    this.pillEl = bar.createSpan({ cls: 'jefr-gem-pill jefr-gem-pill-off', text: 'Gemini offline' });
    this.timerEl = bar.createSpan({
      cls: 'jefr-gem-timer',
      text: '',
      attr: { title: 'Time answering', 'aria-label': 'Time answering' },
    });
    this.routeEl = bar.createSpan({ cls: 'jefr-gem-route', text: ':' + this.plugin.settings.port });
    this.contextEl = bar.createSpan({
      cls: 'jefr-gem-context jefr-gem-context-empty',
      text: '—',
      attr: { title: 'Questions in this chat', 'aria-label': 'Questions in this chat' },
    });

    const composer = dock.createDiv({ cls: 'jefr-gem-composer' });
    this.attachBar = composer.createDiv({ cls: 'jefr-gem-attachbar' });
    this.input = composer.createEl('textarea', {
      cls: 'jefr-gem-input',
      attr: {
        rows: '3',
        placeholder: 'Message Gemini…  Enter send · ↑↓ history · Ctrl+N new chat · Ctrl+C last reply · Shift+Enter newline · paste photo',
        spellcheck: 'false',
        autocomplete: 'off',
        autocorrect: 'off',
        autocapitalize: 'off',
      },
    });
    this.input.addEventListener('keydown', (e) => {
      if (e.isComposing || e.key === 'Process') return;
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        void this.sendCurrent();
        return;
      }
      if (e.key === 'ArrowUp' && !e.altKey && !e.ctrlKey && !e.metaKey) {
        const atStart = this.input.selectionStart === 0 && this.input.selectionEnd === 0;
        if (atStart || !this.input.value) {
          if (this.recallInputHistory(1)) e.preventDefault();
        }
        return;
      }
      if (e.key === 'ArrowDown' && !e.altKey && !e.ctrlKey && !e.metaKey) {
        if (this.inputHistoryIndex >= 0) {
          if (this.recallInputHistory(-1)) e.preventDefault();
        }
      }
    });
    this.input.addEventListener('paste', (e) => this.onPaste(e), true);
    composer.addEventListener('dragover', (e) => {
      e.preventDefault();
      composer.addClass('jefr-gem-dragover');
    });
    composer.addEventListener('dragleave', () => composer.removeClass('jefr-gem-dragover'));
    composer.addEventListener('drop', (e) => {
      e.preventDefault();
      composer.removeClass('jefr-gem-dragover');
      void this.ingestFiles(e.dataTransfer && e.dataTransfer.files);
    });
    this._docPasteHandler = (e) => {
      if (!this.input || document.activeElement !== this.input) return;
      this.onPaste(e);
    };
    document.addEventListener('paste', this._docPasteHandler, true);

    const meta = dock.createDiv({ cls: 'jefr-gem-meta jefr-gem-meta-empty' });
    this.modelEl = meta.createSpan({
      cls: 'jefr-gem-model jefr-gem-model-empty',
      text: '',
    });
    this.thinkEl = meta.createSpan({
      cls: 'jefr-gem-thinking',
      text: '',
      attr: { title: 'Gemini thinking', 'aria-label': 'Gemini thinking' },
    });
    this.metaEl = meta;
  }

  stageImage(dataUrl, name) {
    if (!dataUrl || dataUrl.indexOf('data:image') !== 0) return;
    if (this.attachments.length >= MAX_IMAGES) {
      new Notice('JEFR Gemini: max ' + MAX_IMAGES + ' photos');
      return;
    }
    const last = this.attachments[this.attachments.length - 1];
    if (last && last.dataUrl === dataUrl && Date.now() - (last.ts || 0) < 800) return;
    this.attachments.push({ id: makeId(), name: name || 'photo', dataUrl, ts: Date.now() });
    this.renderAttachments();
  }

  removeAttachment(id) {
    this.attachments = this.attachments.filter((a) => a.id !== id);
    this.renderAttachments();
  }

  renderAttachments() {
    if (!this.attachBar) return;
    this.attachBar.empty();
    for (const att of this.attachments) {
      const chip = this.attachBar.createDiv({ cls: 'jefr-gem-attach-chip' });
      const img = chip.createEl('img', {
        cls: 'jefr-gem-attach-thumb',
        attr: { src: att.dataUrl, alt: att.name },
      });
      img.draggable = false;
      const x = chip.createEl('button', {
        cls: 'jefr-gem-attach-remove',
        text: '×',
        attr: { title: 'Remove' },
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
        if (/^image\//i.test(dt.files[i].type || '')) files.push(dt.files[i]);
      }
    }
    if (!files.length && dt.items) {
      for (let i = 0; i < dt.items.length; i++) {
        const it = dt.items[i];
        if (it.kind === 'file' && /^image\//i.test(it.type || '')) {
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
    void this.tryClipboardImage().then((ok) => {
      if (ok) {
        try {
          e.preventDefault();
          e.stopPropagation();
        } catch (_) {}
      }
    });
  }

  async ingestFiles(fileList) {
    if (!fileList || !fileList.length) return;
    for (let i = 0; i < fileList.length; i++) {
      const f = fileList[i];
      if (!f || !/^image\//i.test(f.type || '')) continue;
      try {
        this.stageImage(await fileToDataUrl(f), f.name || 'photo');
      } catch (_) {}
    }
  }

  async tryClipboardImage() {
    try {
      if (navigator.clipboard && navigator.clipboard.read) {
        const items = await navigator.clipboard.read();
        for (const item of items) {
          const type = (item.types || []).find((t) => /^image\//i.test(t));
          if (!type) continue;
          const blob = await item.getType(type);
          const dataUrl = await fileToDataUrl(new File([blob], 'photo.png', { type }));
          this.stageImage(dataUrl, 'photo.png');
          return true;
        }
      }
    } catch (_) {}
    const du = readClipboardImage();
    if (du) {
      this.stageImage(du, 'photo.png');
      return true;
    }
    const files = readClipboardFileImages();
    if (files.length) {
      for (const f of files) this.stageImage(f.dataUrl, f.name);
      return true;
    }
    return false;
  }

  recallInputHistory(dir) {
    if (!this.inputHistory.length) return false;
    if (this.inputHistoryIndex < 0) this.inputHistoryDraft = this.input.value;
    const next = this.inputHistoryIndex + dir;
    if (next < -1 || next >= this.inputHistory.length) return false;
    this.inputHistoryIndex = next;
    this.input.value =
      next < 0 ? this.inputHistoryDraft : this.inputHistory[this.inputHistory.length - 1 - next];
    this.input.selectionStart = this.input.selectionEnd = 0;
    return true;
  }

  refreshStatus() {
    if (!this.pillEl) return;
    const srv = this.plugin.bridge;
    const live = srv.geminiLive();
    const queued = srv.queue.filter((j) => j.action !== 'copy').length;
    const n = live ? srv.questions || 0 : 0;
    const model = live ? srv.model || '' : '';
    let pill = 'Gemini offline';
    let pillCls = 'off';
    let answering = false;
    if (!srv.listening()) pill = 'Bridge down';
    else if (!live) pill = 'Gemini offline';
    else if (this.sending || queued) {
      pill = queued ? 'Queued' : 'Sending';
      pillCls = 'busy';
    } else if (srv.lastBusy || srv.expectAnswer || srv.answer.state === 'streaming' || srv.thinking) {
      answering = true;
      pill = 'Answering';
      pillCls = 'busy';
    } else if (srv.answer.state === 'finished') {
      pill = 'Finished';
      pillCls = 'on';
    } else {
      pill = 'Ready';
      pillCls = 'on';
    }
    const thinking = answering ? srv.thinking || '' : '';
    if (answering) {
      if (!srv.answeringSince) srv.answeringSince = Date.now();
    } else if (!this.sending && !queued) {
      srv.answeringSince = 0;
    }
    const elapsed =
      answering && srv.answeringSince ? fmtElapsed(Date.now() - srv.answeringSince) : '';
    const snap = [pill, elapsed, thinking, n, live, model].join('|');
    if (snap !== this._statusSnap) {
      this._statusSnap = snap;
      this.pillEl.removeClass('jefr-gem-pill-on');
      this.pillEl.removeClass('jefr-gem-pill-off');
      this.pillEl.removeClass('jefr-gem-pill-busy');
      this.pillEl.addClass('jefr-gem-pill-' + pillCls);
      this.pillEl.setText(pill);
      this.pillEl.setAttr('title', '127.0.0.1:' + this.plugin.settings.port);
      if (this.timerEl) {
        this.timerEl.setText(elapsed);
        this.timerEl.setAttr('title', elapsed ? 'Answering ' + elapsed : 'Time answering');
      }
      if (this.thinkEl) {
        this.thinkEl.setText(thinking);
        this.thinkEl.setAttr('title', thinking || 'Gemini thinking');
      }
      if (this.modelEl) {
        this.modelEl.removeClass('jefr-gem-model-empty');
        this.modelEl.removeClass('jefr-gem-model-ok');
        this.modelEl.addClass(model ? 'jefr-gem-model-ok' : 'jefr-gem-model-empty');
        this.modelEl.setText(model);
      }
      if (this.metaEl) {
        this.metaEl.toggleClass('jefr-gem-meta-empty', !model && !thinking);
      }
      if (this.contextEl) {
        this.contextEl.removeClass('jefr-gem-context-ok');
        this.contextEl.removeClass('jefr-gem-context-empty');
        this.contextEl.addClass(live ? 'jefr-gem-context-ok' : 'jefr-gem-context-empty');
        this.contextEl.setText(live ? String(n) : '—');
        this.contextEl.setAttr(
          'title',
          live ? n + ' question' + (n === 1 ? '' : 's') + ' in this chat' : 'Questions in this chat',
        );
      }
    }
    const now = Date.now();
    for (const job of srv.queue) {
      if (job.warned || now - job.ts < 15000) continue;
      if (srv.lastBusy && srv.geminiLive()) continue;
      job.warned = true;
      const what =
        job.action === 'newchat' ? 'New Chat click' : job.action === 'copy' ? 'Copy click' : 'text';
      new Notice(
        live
          ? 'JEFR Gemini: Gemini tab did not take the ' + what + '. Reload the JEFR Gemini extension.'
          : 'JEFR Gemini: no Gemini tab. Load the unpacked extension and open gemini.google.com.',
      );
    }
  }

  async sendCurrent() {
    if (this.sending) return;
    const text = (this.input.value || '').trim();
    const images = this.attachments.slice();
    if (!text && !images.length) return;
    if (!this.plugin.bridge.listening()) {
      new Notice('JEFR Gemini: bridge not listening');
      return;
    }
    if (!this.plugin.bridge.geminiLive()) {
      new Notice('JEFR Gemini: Gemini tab offline — load the extension and open Gemini');
    }
    this.sending = true;
    this.refreshStatus();
    try {
      this.plugin.bridge.enqueue(text, 'send', images);
      if (text) this.inputHistory.push(text);
      if (this.inputHistory.length > 80) this.inputHistory.shift();
      this.inputHistoryIndex = -1;
      this.inputHistoryDraft = '';
      this.input.value = '';
      this.attachments = [];
      this.renderAttachments();
      this.focusComposer();
    } finally {
      this.sending = false;
      this.refreshStatus();
    }
  }

  async newChat() {
    if (!this.plugin.bridge.listening()) {
      new Notice('JEFR Gemini: bridge not listening');
      return;
    }
    if (!this.plugin.bridge.geminiLive()) {
      new Notice('JEFR Gemini: Gemini tab offline — load the extension and open Gemini');
    }
    this.plugin.bridge.enqueue('', 'newchat');
    this.refreshStatus();
  }

  hasCopyableSelection() {
    const el = this.input;
    if (el && document.activeElement === el) {
      const start = el.selectionStart;
      const end = el.selectionEnd;
      if (typeof start === 'number' && typeof end === 'number' && start !== end) return true;
    }
    const sel = window.getSelection();
    if (!sel || sel.isCollapsed) return false;
    return String(sel.toString() || '').length > 0;
  }

  async copyLast() {
    if (this._copyBusy) return;
    if (!this.plugin.bridge.listening()) {
      new Notice('JEFR Gemini: bridge not listening');
      return;
    }
    if (!this.plugin.bridge.geminiLive()) {
      new Notice('JEFR Gemini: Gemini tab offline — load the extension and open Gemini');
    }
    this._copyBusy = true;
    this.plugin.bridge.enqueue('', 'copy');
    this.refreshStatus();
    window.setTimeout(() => {
      this._copyBusy = false;
    }, 400);
  }

  showCopyToast() {
    const root = this.contentEl;
    if (!root) return;
    const old = root.querySelector('#jefr-gemini-finish-toast');
    if (old) old.remove();
    const el = root.createDiv({
      cls: 'jefr-gem-copy-toast',
      attr: { id: 'jefr-gemini-finish-toast', role: 'status' },
    });
    const mark = el.createSpan({ cls: 'mark' });
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M3 8.3 6.2 11.4 13 4.5');
    path.setAttribute('fill', 'none');
    path.setAttribute('stroke', 'currentColor');
    path.setAttribute('stroke-width', '1.5');
    path.setAttribute('stroke-linecap', 'round');
    path.setAttribute('stroke-linejoin', 'round');
    svg.appendChild(path);
    mark.appendChild(svg);
    el.createSpan({ text: 'Copied' });
    requestAnimationFrame(() => {
      requestAnimationFrame(() => el.addClass('on'));
    });
    window.setTimeout(() => {
      el.removeClass('on');
      window.setTimeout(() => el.remove(), 420);
    }, 2400);
  }
}

class JefrGeminiSettingTab extends PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  display() {
    const { containerEl } = this;
    containerEl.empty();
    containerEl.createEl('h2', { text: 'JEFR Gemini' });
    containerEl.createEl('p', {
      text: 'Compact composer queues text and photos on 127.0.0.1. Paste or drop an image, Enter sends.',
    });
    new Setting(containerEl)
      .setName('Listen port')
      .setDesc('Must match extension/content.js PORT (default 17381).')
      .addText((t) =>
        t.setValue(String(this.plugin.settings.port)).onChange(async (v) => {
          const n = parseInt(v, 10);
          if (!Number.isFinite(n) || n < 1 || n > 65535) return;
          this.plugin.settings.port = n;
          await this.plugin.saveSettings();
          await this.plugin.restartBridge();
        }),
      );
  }
}

module.exports = class JefrGeminiPlugin extends Plugin {
  async onload() {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
    this.bridge = new BridgeServer(this);

    this.registerView(VIEW_TYPE, (leaf) => new JefrGeminiView(leaf, this));
    this.addRibbonIcon('sparkles', 'Open JEFR Gemini', () => {
      void this.activateView();
    });
    this.addCommand({
      id: 'open-jefr-gemini',
      name: 'Open JEFR Gemini',
      callback: () => this.activateView(),
    });
    this.addCommand({
      id: 'open-jefr-gemini-left',
      name: 'Open JEFR Gemini (split left)',
      callback: () => this.activateView('left'),
    });
    this.addCommand({
      id: 'open-jefr-gemini-right',
      name: 'Open JEFR Gemini (split right)',
      callback: () => this.activateView('right'),
    });
    this.addCommand({
      id: 'send-composer',
      name: 'Send current composer text to Gemini',
      callback: async () => {
        const view = await this.ensureView();
        if (view) await view.sendCurrent();
      },
    });
    this.addCommand({
      id: 'new-chat',
      name: 'New Gemini chat',
      callback: async () => {
        const view = await this.ensureView();
        if (view) await view.newChat();
      },
    });
    this.addSettingTab(new JefrGeminiSettingTab(this.app, this));

    try {
      await this.bridge.start(Number(this.settings.port) || DEFAULT_PORT);
    } catch (e) {
      new Notice('JEFR Gemini: ' + (e.message || e));
    }
  }

  onunload() {
    this.bridge.stop();
  }

  async saveSettings() {
    await this.saveData(this.settings);
  }

  async restartBridge() {
    try {
      await this.bridge.start(Number(this.settings.port) || DEFAULT_PORT);
      this.notifyViews();
    } catch (e) {
      new Notice('JEFR Gemini: ' + (e.message || e));
    }
  }

  notifyViews() {
    this.app.workspace.getLeavesOfType(VIEW_TYPE).forEach((leaf) => {
      if (leaf.view instanceof JefrGeminiView) leaf.view.refreshStatus();
    });
  }

  notifyCopyToast() {
    this.app.workspace.getLeavesOfType(VIEW_TYPE).forEach((leaf) => {
      if (leaf.view instanceof JefrGeminiView) leaf.view.showCopyToast();
    });
  }

  inSidebar(leaf) {
    if (!leaf) return false;
    const root = leaf.getRoot();
    return root === this.app.workspace.leftSplit || root === this.app.workspace.rightSplit;
  }

  splitSource(existing) {
    const { workspace } = this.app;
    const recent = workspace.getMostRecentLeaf();
    if (recent && recent !== existing && !this.inSidebar(recent)) return recent;
    const leaves = [];
    workspace.iterateRootLeaves((leaf) => {
      if (leaf !== existing && !this.inSidebar(leaf)) leaves.push(leaf);
    });
    return leaves[0] || workspace.getLeaf(false);
  }

  async activateView(side) {
    const { workspace } = this.app;
    const existing = workspace.getLeavesOfType(VIEW_TYPE)[0];
    if (existing && !side && !this.inSidebar(existing)) {
      workspace.revealLeaf(existing);
      return existing;
    }

    let dest;
    if (side === 'left' || side === 'right') {
      const from = this.splitSource(existing);
      dest = workspace.createLeafBySplit(from, 'vertical', side === 'left');
    } else {
      dest = workspace.getLeaf('tab');
    }
    await dest.setViewState({ type: VIEW_TYPE, active: true });
    if (existing && existing !== dest) existing.detach();
    workspace.revealLeaf(dest);
    return dest;
  }

  async ensureView() {
    const leaf = await this.activateView();
    return leaf && leaf.view instanceof JefrGeminiView ? leaf.view : null;
  }
};
