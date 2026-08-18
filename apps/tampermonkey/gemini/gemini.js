// ==UserScript==
// @name         Gemini
// @namespace    http://tampermonkey.net/
// @version      3.0.11
// @description  One script: auto-copy + Ctrl+C, finish toast, sidenav/mode/upsell, fixed input + autofocus.
// @author       You
// @match        https://gemini.google.com/*
// @grant        GM_setClipboard
// @grant        GM_addStyle
// @run-at       document-idle
// ==/UserScript==

/*
 * v3.0.11 — copy toast a bit larger.
 * v3.0.10 — hide Gemini "Copied to clipboard" snackbar (our toast stays).
 * v3.0.9 — auto-copy clicks Copy, intercepts Gemini's markdown, GM-writes it (no gesture needed).
 * v3.0.8 — HTML→Markdown matches Gemini Copy: tight lists, fence lang, cell markup, hr.
 * v3.0.7 — auto-copy uses GM markdown again (click has no gesture). Ctrl+C still clicks Copy.
 * v3.0.6 — no extra 1.5s after Copy appears; click as soon as complete + stable + button.
 * v3.0.5 — auto-copy is the Copy button click (same payload as Ctrl+C). No GM overwrite.
 * v3.0.4 — wait for Copy button + extra settle; clipboard is HTML→markdown, not innerText.
 * v3.0.3 — toast uses inverse snackbar contrast (notification, not chrome).
 * v3.0.2 — quieter lr26 toast (glass chip, check, above input).
 * v3.0.1 — toast sits above the input dock (lr26 mweb header ate top:20px).
 * v3.0.0 — single IIFE. Split sources: archive/2026-08-14/*.bak
 *
 * One finish bus (footer.complete + aria-busy + stable text + copy control) drives copy + toast.
 * zoom-per-tab-ext stays a Chrome extension, not this file.
 */

(function (global) {
  "use strict";

  const VERSION = "3.0.11";
  const LOG = "[Gemini]";

  const SETTLE_MS = 900;
  const POLL_MS = 800;
  const STABLE_MS = 700;
  const TOAST_MS = 2400;
  const TOAST_FADE_MS = 420;
  const TOAST_ID = "jefr-gemini-finish-toast";
  const INPUT_HEIGHT = "33px";

  const util = {
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),

    log: (...args) => console.log(LOG, ...args),

    addStyle(css, id) {
      if (id && document.getElementById(id)) return;
      if (!id && typeof GM_addStyle === "function") {
        GM_addStyle(css);
        return;
      }
      const s = document.createElement("style");
      if (id) s.id = id;
      s.textContent = css;
      (document.head || document.documentElement).appendChild(s);
    },

    whenReady(fn) {
      if (document.body) fn();
      else document.addEventListener("DOMContentLoaded", fn, { once: true });
    },

    whenLoad(fn) {
      if (document.readyState === "complete") fn();
      else global.addEventListener("load", fn, { once: true });
    },

    getContentEl(modelResponse) {
      return (
        modelResponse?.querySelector?.('[id^="model-response-message-content"]') ||
        null
      );
    },

    extractText(modelResponse) {
      const content = util.getContentEl(modelResponse);
      if (!content) return "";
      return (content.innerText || content.textContent || "")
        .replace(/\u00a0/g, " ")
        .trim();
    },

    // Match Gemini's Copy button: tight lists, ```lang fences, inline markup in tables, ---.
    htmlToMarkdown(root) {
      if (!root) return "";

      const skip = new Set([
        "script",
        "style",
        "button",
        "copy-button",
        "mat-icon",
        "svg",
        "noscript",
        "message-actions",
      ]);

      const isSkip = (el) => skip.has(el.tagName.toLowerCase());

      const isSep = (el) => {
        const tag = el.tagName.toLowerCase();
        if (tag === "hr" || tag === "mat-divider") return true;
        if (el.getAttribute("role") === "separator") return true;
        const cls = String(el.className || "");
        return /\b(divider|separator|thematic-break)\b/i.test(cls);
      };

      const inline = (el) => {
        let s = "";
        const walk = (n) => {
          if (!n) return;
          if (n.nodeType === 3) {
            s += n.textContent.replace(/\u00a0/g, " ");
            return;
          }
          if (n.nodeType !== 1) return;
          if (isSkip(n) || isSep(n)) return;
          const t = n.tagName.toLowerCase();
          if (t === "br") {
            s += "\n";
            return;
          }
          if (t === "strong" || t === "b") {
            s += "**" + inline(n) + "**";
            return;
          }
          if (t === "em" || t === "i") {
            s += "*" + inline(n) + "*";
            return;
          }
          if (t === "code") {
            s += "`" + (n.textContent || "").replace(/`/g, "\\`") + "`";
            return;
          }
          if (t === "del" || t === "s") {
            s += "~~" + inline(n) + "~~";
            return;
          }
          if (t === "p") {
            const inner = inline(n);
            s += s && inner ? "\n" + inner : inner;
            return;
          }
          n.childNodes.forEach(walk);
        };
        el.childNodes.forEach(walk);
        return s.replace(/[ \t]+\n/g, "\n").replace(/[ \t]{2,}/g, " ").trim();
      };

      const fenceLang = (el) => {
        const attr =
          el.getAttribute?.("data-language") ||
          el.getAttribute?.("data-lang") ||
          el.querySelector?.("[data-language]")?.getAttribute("data-language") ||
          el.querySelector?.("[data-lang]")?.getAttribute("data-lang") ||
          "";
        if (attr.trim()) return attr.trim();
        const code = el.querySelector?.("code");
        const cls = `${el.className || ""} ${code?.className || ""}`;
        const m = String(cls).match(/language-([a-zA-Z0-9_+-]+)/);
        if (m) return m[1];
        const header = el.querySelector?.(
          ".code-block-header .lang, .code-block-header .language, [class$='-language'], .language-label, .header-row .lang"
        );
        if (header) {
          const t = (header.textContent || "").replace(/\s+/g, " ").trim().toLowerCase();
          if (t && t.length < 24 && !/copy|copied/.test(t)) return t;
        }
        const headerRow = el.querySelector?.(".header, .header-row, .code-block-header, .toolbar");
        if (headerRow) {
          const t = (headerRow.textContent || "")
            .replace(/copy(ed)?/gi, "")
            .replace(/\s+/g, "")
            .trim()
            .toLowerCase();
          if (/^[a-z0-9_+-]{1,20}$/.test(t)) return t;
        }
        return "";
      };

      const fenceFrom = (el) => {
        const codeEl =
          el.querySelector("pre code") ||
          el.querySelector("pre") ||
          (el.tagName.toLowerCase() === "pre" ? el : el.querySelector("code"));
        const raw = ((codeEl && codeEl !== el ? codeEl.textContent : el.querySelector("code")?.textContent) || "")
          .replace(/\u00a0/g, " ")
          .replace(/\n$/, "");
        const lang = fenceLang(el);
        const open = lang ? "```" + lang : "```";
        return open + "\n" + raw + "\n\n```";
      };

      const tableToMd = (table) => {
        const rows = [...table.querySelectorAll("tr")].map((tr) =>
          [...tr.querySelectorAll("th,td")].map((c) =>
            inline(c).replace(/\|/g, "\\|").replace(/\n/g, " ")
          )
        );
        if (!rows.length) return "";
        const width = Math.max(...rows.map((r) => r.length), 1);
        const pad = (r) => {
          const x = r.slice();
          while (x.length < width) x.push("");
          return x;
        };
        const fmt = (r) => "| " + pad(r).join(" | ") + " |";
        const sep = "| " + Array(width).fill("---").join(" | ") + " |";
        const body = rows.map(pad);
        return [fmt(body[0]), sep, ...body.slice(1).map(fmt)].join("\n");
      };

      const listBlock = (listEl, indent) => {
        const ordered = listEl.tagName.toLowerCase() === "ol";
        const start = ordered ? Number(listEl.getAttribute("start")) || 1 : 1;
        const lines = [];
        let n = 0;
        for (const li of listEl.children) {
          if (li.tagName.toLowerCase() !== "li") continue;
          const nested = [];
          const rest = [];
          li.childNodes.forEach((child) => {
            if (child.nodeType === 1 && /^(ul|ol)$/i.test(child.tagName)) nested.push(child);
            else rest.push(child);
          });
          const wrap = document.createElement("span");
          rest.forEach((c) => wrap.appendChild(c.cloneNode(true)));
          const pad = "  ".repeat(indent);
          const bullet = ordered ? `${start + n}. ` : "- ";
          n++;
          const text = inline(wrap);
          if (text) lines.push(pad + bullet + text);
          nested.forEach((sub) => {
            const inner = listBlock(sub, indent + 1);
            if (inner) lines.push(inner);
          });
        }
        return lines.join("\n");
      };

      const blocks = [];
      const render = (el) => {
        if (!el) return;
        if (el.nodeType === 3) {
          const t = el.textContent.replace(/\u00a0/g, " ").replace(/\s+/g, " ").trim();
          if (t) blocks.push(t);
          return;
        }
        if (el.nodeType !== 1) return;
        const tag = el.tagName.toLowerCase();
        if (isSkip(el)) return;
        if (isSep(el)) {
          blocks.push("---");
          return;
        }
        if (/^h[1-6]$/.test(tag)) {
          const t = inline(el);
          if (t) blocks.push("#".repeat(+tag[1]) + " " + t);
          return;
        }
        if (el.getAttribute("role") === "heading") {
          const level = Math.min(6, Math.max(1, Number(el.getAttribute("aria-level")) || 2));
          const t = inline(el);
          if (t) blocks.push("#".repeat(level) + " " + t);
          return;
        }
        if (tag === "p") {
          const t = inline(el);
          if (t) blocks.push(t);
          return;
        }
        if (tag === "blockquote") {
          const t = inline(el);
          if (t) blocks.push(t.split("\n").map((l) => "> " + l).join("\n"));
          return;
        }
        if (tag === "ul" || tag === "ol") {
          const t = listBlock(el, 0);
          if (t) blocks.push(t);
          return;
        }
        if (tag === "table") {
          const t = tableToMd(el);
          if (t) blocks.push(t);
          return;
        }
        if (tag === "pre" || tag === "code-block") {
          blocks.push(fenceFrom(el));
          if (el.querySelector("hr, mat-divider, [role='separator']")) blocks.push("---");
          return;
        }
        if (tag === "hr") {
          blocks.push("---");
          return;
        }
        el.childNodes.forEach(render);
      };

      root.childNodes.forEach(render);
      return blocks
        .filter(Boolean)
        .join("\n\n")
        .replace(/\n{3,}/g, "\n\n")
        .trim();
    },

    extractMarkdown(modelResponse) {
      const content = util.getContentEl(modelResponse);
      if (!content) return "";
      const md = util.htmlToMarkdown(content);
      if (md) return md;
      return util.extractText(modelResponse);
    },

    getLatest() {
      const responses = document.querySelectorAll("model-response");
      if (!responses.length) return null;
      return responses[responses.length - 1];
    },

    responseId(modelResponse) {
      const content = util.getContentEl(modelResponse);
      if (content?.id) return content.id;
      const conv = modelResponse.closest(".conversation-container");
      if (conv?.id) return `conv:${conv.id}`;
      return null;
    },

    findCopyControl(root) {
      if (!root) return null;
      const host = root.querySelector?.("copy-button");
      const from = host || root;
      return (
        from.querySelector(
          'gem-icon-button[gemtooltip="Copy response"] button[aria-label="Copy"]'
        ) ||
        from.querySelector("copy-button button[aria-label='Copy']") ||
        from.querySelector('gem-icon-button[arialabel="Copy"] button') ||
        from.querySelector("copy-button button") ||
        from.querySelector('gem-icon-button[gemtooltip="Copy response"]') ||
        null
      );
    },

    isComplete(modelResponse) {
      const content = util.getContentEl(modelResponse);
      if (!content) return false;
      if (content.getAttribute("aria-busy") === "true") return false;
      const footer = modelResponse.querySelector(".response-footer");
      if (footer && !footer.classList.contains("complete")) return false;
      if (footer?.classList.contains("complete")) return true;
      return (
        content.getAttribute("aria-busy") === "false" &&
        !!util.findCopyControl(modelResponse)
      );
    },

    isInPrompt(el) {
      if (!el) return false;
      if (
        el.closest?.(
          "input-area-v2, rich-textarea, .ql-editor, [data-node-type='input-area']"
        )
      ) {
        return true;
      }
      return el.getAttribute?.("aria-label") === "Enter a prompt for Gemini";
    },

    getPromptInput() {
      return (
        document.querySelector('[aria-label="Enter a prompt for Gemini"]') ||
        document.querySelector('[data-placeholder="Ask Gemini"]') ||
        document.querySelector("input-area-v2 .ql-editor.textarea") ||
        document.querySelector("input-area-v2 .ql-editor") ||
        document.querySelector('.ql-editor[contenteditable="true"]')
      );
    },

    focusAtEnd(el) {
      if (!el) return;
      el.focus();
      if (el.isContentEditable) {
        const sel = global.getSelection();
        const range = document.createRange();
        range.selectNodeContents(el);
        range.collapse(false);
        sel.removeAllRanges();
        sel.addRange(range);
      } else if (el.setSelectionRange) {
        const len = el.value.length;
        el.setSelectionRange(len, len);
      }
    },
  };

  // ── one finish bus (copy + toast subscribe) ──

  const createFinishBus = () => {
    const seen = new Set();
    const stableMap = new Map();
    const listeners = new Set();
    let pending = null;
    let booted = false;

    const onComplete = (fn) => {
      listeners.add(fn);
      return () => listeners.delete(fn);
    };

    const textIsStable = (id, text) => {
      const now = Date.now();
      const prev = stableMap.get(id);
      if (!prev || prev.len !== text.length) {
        stableMap.set(id, { len: text.length, since: now });
        return false;
      }
      return now - prev.since >= STABLE_MS && text.length > 0;
    };

    const seed = () => {
      let n = 0;
      document.querySelectorAll("model-response").forEach((mr) => {
        const id = util.responseId(mr);
        if (!id || seen.has(id)) return;
        if (util.isComplete(mr) && util.extractText(mr)) {
          seen.add(id);
          n++;
        }
      });
      util.log(`finish: seeded ${n} finished response(s)`);
    };

    const emit = (mr, id) => {
      if (seen.has(id)) return;
      seen.add(id);
      for (const fn of listeners) {
        try {
          fn(mr, id);
        } catch (e) {
          util.log("finish listener error", e);
        }
      }
    };

    const scan = () => {
      const latest = util.getLatest();
      if (!latest) return;
      const id = util.responseId(latest);
      if (!id || seen.has(id)) return;
      if (!util.isComplete(latest)) return;
      const text = util.extractText(latest);
      if (!textIsStable(id, text)) {
        schedule();
        return;
      }
      if (!util.findCopyControl(latest)) {
        schedule();
        return;
      }
      emit(latest, id);
    };

    const schedule = () => {
      if (pending) clearTimeout(pending);
      pending = setTimeout(() => {
        pending = null;
        scan();
      }, SETTLE_MS);
    };

    const start = () => {
      if (booted) return;
      booted = true;
      seed();
      new MutationObserver(schedule).observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["aria-busy", "class"],
        characterData: true,
      });
      setInterval(scan, POLL_MS);
      util.log("finish: watching");
    };

    let lastHref = location.href;
    setInterval(() => {
      if (location.href === lastHref) return;
      lastHref = location.href;
      util.log("finish: route change — re-seed finished only");
      seen.clear();
      stableMap.clear();
      seed();
    }, 1000);

    util.whenReady(start);
    return { onComplete };
  };

  // ── copy (auto + Ctrl+C) ──

  const createCopy = (finish) => {
    const clickEl = (el) => {
      if (!el) return false;
      const target = el.matches?.("button") ? el : el.querySelector?.("button") || el;
      const r = target.getBoundingClientRect?.() || { left: 0, top: 0, width: 0, height: 0 };
      const cx = r.left + Math.max(r.width / 2, 1);
      const cy = r.top + Math.max(r.height / 2, 1);
      const common = {
        bubbles: true,
        cancelable: true,
        composed: true,
        view: global,
        clientX: cx,
        clientY: cy,
        button: 0,
        buttons: 1,
      };
      for (const [type, Ctor, extra] of [
        ["pointerdown", PointerEvent, { pointerId: 1, pointerType: "mouse", isPrimary: true }],
        ["mousedown", MouseEvent, null],
        ["pointerup", PointerEvent, { pointerId: 1, pointerType: "mouse", isPrimary: true }],
        ["mouseup", MouseEvent, null],
        ["click", MouseEvent, null],
      ]) {
        try {
          target.dispatchEvent(new Ctor(type, extra ? { ...common, ...extra } : common));
        } catch (_) {}
      }
      try {
        target.click();
      } catch (_) {}
      return true;
    };

    const forceClickCopy = async (modelResponse) => {
      const actions = modelResponse.querySelector("message-actions");
      const hadHide = !!actions?.classList.contains("hide-action-bar");
      if (hadHide) {
        actions.classList.remove("hide-action-bar");
        await new Promise((r) => requestAnimationFrame(r));
      }
      const btn = util.findCopyControl(modelResponse);
      let clicked = false;
      if (btn) {
        clickEl(btn);
        try {
          btn.dataset.geminiAutoCopied = "1";
        } catch (_) {}
        clicked = true;
      }
      if (hadHide) {
        requestAnimationFrame(() => actions.classList.add("hide-action-bar"));
      }
      return clicked;
    };

    // Gemini still *calls* clipboard.writeText on a synthetic click; the browser
    // rejects the write (no gesture). Capture that string and GM-write it.
    const clickCopyAndCapture = async (modelResponse) => {
      const page = typeof unsafeWindow !== "undefined" ? unsafeWindow : global;
      const clips = [];
      if (page.navigator?.clipboard) clips.push(page.navigator.clipboard);
      if (global.navigator?.clipboard && global.navigator.clipboard !== page.navigator?.clipboard) {
        clips.push(global.navigator.clipboard);
      }

      let captured = "";
      const restore = [];

      const hookClip = (clip) => {
        if (!clip) return;
        const origWriteText = clip.writeText ? clip.writeText.bind(clip) : null;
        const origWrite = clip.write ? clip.write.bind(clip) : null;
        if (origWriteText) {
          try {
            clip.writeText = async (text) => {
              captured = String(text ?? "");
              try {
                return await origWriteText(text);
              } catch (_) {
                return undefined;
              }
            };
            restore.push(() => {
              try {
                clip.writeText = origWriteText;
              } catch (_) {}
            });
          } catch (_) {}
        }
        if (origWrite) {
          try {
            clip.write = async (items) => {
              try {
                const arr = items && typeof items[Symbol.iterator] === "function" ? [...items] : [];
                for (const item of arr) {
                  if (item?.types && [...item.types].includes("text/plain")) {
                    const blob = await item.getType("text/plain");
                    captured = await blob.text();
                  }
                }
              } catch (_) {}
              try {
                return await origWrite(items);
              } catch (_) {
                return undefined;
              }
            };
            restore.push(() => {
              try {
                clip.write = origWrite;
              } catch (_) {}
            });
          } catch (_) {}
        }
      };
      clips.forEach(hookClip);

      const onCopy = (e) => {
        try {
          const t = e.clipboardData?.getData("text/plain");
          if (t) captured = t;
        } catch (_) {}
      };
      document.addEventListener("copy", onCopy, true);

      try {
        const clicked = await forceClickCopy(modelResponse);
        if (!clicked) return "";
        const until = Date.now() + 500;
        while (!captured && Date.now() < until) {
          await util.sleep(40);
        }
        return captured.trim();
      } finally {
        document.removeEventListener("copy", onCopy, true);
        restore.forEach((fn) => fn());
      }
    };

    const writeClipboard = async (text, opts = {}) => {
      if (!text) return false;
      const preferGestureApi = !!opts.preferGestureApi;

      const tryGm = () => {
        try {
          if (typeof GM_setClipboard === "function") {
            GM_setClipboard(text, "text");
            return true;
          }
        } catch (e) {
          util.log("GM_setClipboard failed", e);
        }
        try {
          if (typeof GM !== "undefined" && typeof GM.setClipboard === "function") {
            GM.setClipboard(text, "text");
            return true;
          }
        } catch (e) {
          util.log("GM.setClipboard failed", e);
        }
        return false;
      };

      const tryNav = async () => {
        try {
          if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(text);
            return true;
          }
        } catch (e) {
          util.log("clipboard.writeText failed", e);
        }
        return false;
      };

      const tryExec = () => {
        try {
          const ta = document.createElement("textarea");
          ta.value = text;
          ta.setAttribute("readonly", "");
          ta.style.cssText = "position:fixed;left:-9999px;top:0";
          document.body.appendChild(ta);
          ta.select();
          const ok = document.execCommand("copy");
          ta.remove();
          return ok;
        } catch (e) {
          util.log("execCommand copy failed", e);
          return false;
        }
      };

      if (preferGestureApi) {
        if (await tryNav()) return true;
        if (tryGm()) return true;
        return tryExec();
      }
      if (tryGm()) return true;
      if (await tryNav()) return true;
      return tryExec();
    };

    const copyModelResponse = async (modelResponse, reason) => {
      if (!modelResponse) {
        util.log(reason, "no model-response");
        return false;
      }

      // Ctrl+C is a real gesture — Gemini's Copy button writes native Markdown.
      if (reason === "Ctrl+C") {
        const clicked = await forceClickCopy(modelResponse);
        if (clicked) {
          util.log(reason, "clicked Copy");
          return true;
        }
      }

      // Auto: click Copy, steal the markdown Gemini tried to write, GM it.
      if (reason === "auto" || reason === "manual") {
        const captured = await clickCopyAndCapture(modelResponse);
        if (captured) {
          const ok = await writeClipboard(captured);
          util.log(
            reason,
            ok ? "copied via Copy button" : "FAILED",
            `${captured.length} chars`
          );
          return ok;
        }
        util.log(reason, "Copy click gave no payload — HTML→md fallback");
      }

      const text = util.extractMarkdown(modelResponse);
      if (!text) {
        util.log(reason, "empty response text");
        return false;
      }
      const ok = await writeClipboard(text, { preferGestureApi: reason === "Ctrl+C" });
      util.log(
        reason,
        ok ? "copied md" : "FAILED",
        `${text.length} chars`,
        typeof GM_setClipboard === "function" ? "GM_ok" : "GM_missing"
      );
      return ok;
    };

    const hasTextSelection = () => {
      const el = document.activeElement;
      if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA")) {
        const start = el.selectionStart;
        const end = el.selectionEnd;
        if (typeof start === "number" && typeof end === "number" && start !== end) {
          return true;
        }
      }
      const sel = global.getSelection();
      if (!sel || sel.isCollapsed) return false;
      return sel.toString().length > 0;
    };

    let busy = false;
    document.addEventListener(
      "keydown",
      (e) => {
        if (!(e.key === "c" || e.key === "C")) return;
        if (!e.ctrlKey || e.altKey || e.metaKey || e.shiftKey) return;
        if (hasTextSelection()) return;
        if (util.isInPrompt(document.activeElement)) return;
        e.preventDefault();
        e.stopPropagation();
        if (busy) return;
        busy = true;
        copyModelResponse(util.getLatest(), "Ctrl+C").finally(() => {
          setTimeout(() => {
            busy = false;
          }, 300);
        });
      },
      true
    );

    finish.onComplete((mr) => {
      copyModelResponse(mr, "auto");
    });

    util.log(
      "copy: Ctrl+C + auto",
      typeof GM_setClipboard === "function"
        ? "(GM_setClipboard available)"
        : "(GM_setClipboard MISSING — reinstall to apply @grant)"
    );

    return { copyLatest: () => copyModelResponse(util.getLatest(), "manual") };
  };

  // ── finish toast ──

  const createNotify = (finish) => {
    const cssId = TOAST_ID + "-css";
    const ensureCss = () => {
      let s = document.getElementById(cssId);
      if (!s) {
        s = document.createElement("style");
        s.id = cssId;
        (document.head || document.documentElement).appendChild(s);
      }
      s.textContent = `
      #${TOAST_ID}{
        position:fixed !important;left:50% !important;right:auto !important;
        top:auto !important;bottom:96px;z-index:2147483647 !important;
        pointer-events:none;display:flex;align-items:center;gap:12px;
        padding:10px 20px 10px 10px;border-radius:999px;
        font:500 15px/1.25 "Google Sans Text","Google Sans","Segoe UI",system-ui,sans-serif;
        letter-spacing:.02em;
        color:#fff;
        background:#1b1b1b;
        border:1px solid rgba(255,255,255,.08);
        box-shadow:0 8px 28px rgba(0,0,0,.32), 0 0 0 1px rgba(0,0,0,.12);
        transform:translate(-50%,10px) scale(.97);opacity:0;
        transform-origin:50% 100%;
        transition:opacity ${TOAST_FADE_MS}ms cubic-bezier(.2,.8,.2,1),
                   transform ${TOAST_FADE_MS}ms cubic-bezier(.2,.8,.2,1);
      }
      #${TOAST_ID}.on{opacity:1;transform:translate(-50%,0) scale(1)}
      #${TOAST_ID} .mark{
        width:26px;height:26px;border-radius:50%;flex:none;
        display:flex;align-items:center;justify-content:center;
        background:#0f9d58;
        box-shadow:0 0 0 3px rgba(15,157,88,.22);
      }
      #${TOAST_ID} svg{width:14px;height:14px;color:#fff}
      @media (prefers-reduced-motion:reduce){
        #${TOAST_ID}{transition:opacity 160ms linear;transform:translate(-50%,0) scale(1)}
      }
      `;
    };

    const toastBottomPx = () => {
      const dock =
        document.querySelector("input-container") ||
        document.querySelector("input-area-v2");
      if (!dock) return 96;
      const top = dock.getBoundingClientRect().top;
      return Math.max(24, Math.round(window.innerHeight - top + 18));
    };

    const checkIcon = () => {
      const ns = "http://www.w3.org/2000/svg";
      const svg = document.createElementNS(ns, "svg");
      svg.setAttribute("viewBox", "0 0 16 16");
      svg.setAttribute("aria-hidden", "true");
      const path = document.createElementNS(ns, "path");
      path.setAttribute("d", "M3 8.3 6.2 11.4 13 4.5");
      path.setAttribute("fill", "none");
      path.setAttribute("stroke", "currentColor");
      path.setAttribute("stroke-width", "1.5");
      path.setAttribute("stroke-linecap", "round");
      path.setAttribute("stroke-linejoin", "round");
      svg.appendChild(path);
      return svg;
    };

    const showToast = () => {
      ensureCss();
      document.getElementById(TOAST_ID)?.remove();
      const el = document.createElement("div");
      el.id = TOAST_ID;
      el.setAttribute("role", "status");
      const mark = document.createElement("span");
      mark.className = "mark";
      mark.appendChild(checkIcon());
      const label = document.createElement("span");
      label.textContent = "Copied";
      el.append(mark, label);
      el.style.bottom = toastBottomPx() + "px";
      (document.body || document.documentElement).appendChild(el);
      requestAnimationFrame(() => {
        requestAnimationFrame(() => el.classList.add("on"));
      });
      setTimeout(() => {
        el.classList.remove("on");
        setTimeout(() => el.remove(), TOAST_FADE_MS);
      }, TOAST_MS);
    };

    finish.onComplete(() => {
      showToast();
      util.log("toast shown");
    });

    return { showToast };
  };

  // ── sidenav + upsell + Pro/Flash ──

  const createUi = () => {
    const TOGGLE_ID = "tm-sidenav-toggle";
    const quotes = [
      "The only limit is your imagination.",
      "Dream big, start small, act now.",
      "Every moment is a fresh beginning.",
      "Be the energy you want to attract.",
      "Stars can't shine without darkness.",
      "Your potential is endless.",
      "Create the life you can't wait to wake up to.",
      "The best time to start is now.",
      "Believe you can and you're halfway there.",
      "Make today ridiculously amazing.",
      "You are capable of extraordinary things.",
      "Let your light shine so bright it inspires others.",
      "The universe is conspiring in your favor.",
      "You were born to do remarkable things.",
      "Your story is still being written.",
      "What feels impossible today will be your warm-up tomorrow.",
      "You are exactly where you need to be.",
      "Trust the magic of new beginnings.",
      "You carry galaxies within you.",
      "Today is full of endless possibilities.",
      "Your presence makes the world more beautiful.",
      "The best is yet to come.",
      "You are a work of art in progress.",
      "Let curiosity lead the way.",
      "You have survived 100% of your worst days.",
      "Embrace the glorious mess that you are.",
      "You are the author of your own story.",
      "Breathe. You've got this.",
      "Small steps still move you forward.",
      "You are braver than you believe.",
      "The sun will rise and we will try again.",
      "You are someone's reason to smile.",
      "Dare to be different. Dare to be you.",
      "Your dreams are valid.",
      "You are made of stardust and infinite potential.",
      "Every day is a chance to begin again.",
      "You light up the world just by being in it.",
      "Wherever you go, go with all your heart.",
      "You are worthy of all the good things coming your way.",
      "The world needs your unique magic.",
    ];

    const initSidenav = () => {
      let isHidden = localStorage.getItem("gemini-sidenav-hidden") === "true";

      util.addStyle(
        `
            mat-sidenav.tm-hidden { display: none !important; }
            body.tm-sidenav-hidden side-nav-menu-button,
            body.tm-sidenav-hidden chat-app-side-nav-menu-button,
            body.tm-sidenav-hidden bard-mode-switcher,
            body.tm-sidenav-hidden [data-test-id="side-nav-menu-button"],
            body.tm-sidenav-hidden [data-test-id="bard-mode-switcher"] {
                display: none !important;
            }
            #${TOGGLE_ID} {
                width: 48px; height: 48px; border-radius: 50%;
                background: transparent; border: none;
                color: var(--gds-sys-color-on-surface, #c4c7c5);
                cursor: pointer; display: flex; align-items: center; justify-content: center;
            }
            #${TOGGLE_ID}:hover { background: rgba(255,255,255,0.08); }
        `,
        "tm-sidenav-styles"
      );

      const replaceDisclaimer = () => {
        const disclaimer =
          document.querySelector('hallucination-disclaimer p[data-test-id="disclaimer"]') ||
          document.querySelector("hallucination-disclaimer p");
        if (disclaimer && !disclaimer.dataset.tmInspired) {
          disclaimer.dataset.tmInspired = "true";
          disclaimer.textContent = quotes[Math.floor(Math.random() * quotes.length)];
        }
      };

      const updateVisibility = () => {
        document.body.classList.toggle("tm-sidenav-hidden", isHidden);
        const sidenav = document.querySelector("mat-sidenav");
        if (sidenav) sidenav.classList.toggle("tm-hidden", isHidden);
        const btn = document.getElementById(TOGGLE_ID);
        if (btn) {
          btn.title = isHidden ? "Show sidebar" : "Hide sidebar";
          const icon = btn.querySelector("mat-icon");
          if (icon) {
            icon.textContent = isHidden ? "menu" : "close";
            icon.setAttribute("fonticon", isHidden ? "menu" : "close");
          }
        }
      };

      const toggle = () => {
        isHidden = !isHidden;
        localStorage.setItem("gemini-sidenav-hidden", isHidden);
        updateVisibility();
      };

      const createToggleButton = () => {
        if (document.getElementById(TOGGLE_ID)) return;
        const container = document.querySelector(".top-bar-actions .buttons-container");
        if (!container) return;
        const btn = document.createElement("button");
        btn.id = TOGGLE_ID;
        btn.className = "mdc-icon-button mat-mdc-icon-button mat-mdc-button-base mat-unthemed";
        btn.title = isHidden ? "Show sidebar" : "Hide sidebar";
        btn.onclick = toggle;
        const icon = document.createElement("mat-icon");
        icon.className =
          "mat-icon notranslate gds-icon-l google-symbols mat-ligature-font mat-icon-no-color";
        icon.setAttribute("aria-hidden", "true");
        icon.setAttribute("fonticon", isHidden ? "menu" : "close");
        icon.textContent = isHidden ? "menu" : "close";
        btn.appendChild(icon);
        container.insertBefore(btn, container.firstChild);
        updateVisibility();
      };

      new MutationObserver(() => {
        const sidenav = document.querySelector("mat-sidenav");
        if (sidenav && !sidenav.dataset.tmProcessed) {
          sidenav.dataset.tmProcessed = "true";
          updateVisibility();
        }
        createToggleButton();
        replaceDisclaimer();
      }).observe(document.body, { childList: true, subtree: true });

      updateVisibility();
      createToggleButton();
      replaceDisclaimer();
      setTimeout(updateVisibility, 500);
      setTimeout(updateVisibility, 1500);
      setTimeout(replaceDisclaimer, 500);
      util.log("ui: sidenav toggle ready");
    };

    const initUpsell = () => {
      const remove = () => {
        document.querySelectorAll(".buttons-container.adv-upsell").forEach((el) => el.remove());
        document.querySelectorAll("g1-dynamic-upsell-button").forEach((el) => el.remove());
        document.querySelectorAll("button").forEach((btn) => {
          const t = btn.textContent || "";
          if (t.includes("Upgrade to Google AI Ultra") || t.includes("Upgrade to Ultra")) {
            const container =
              btn.closest(".buttons-container.adv-upsell") ||
              btn.closest("g1-dynamic-upsell-button");
            if (container) container.remove();
            else btn.remove();
          }
        });
      };
      new MutationObserver(remove).observe(document.body, { childList: true, subtree: true });
      remove();
      setTimeout(remove, 1000);
      setTimeout(remove, 3000);
      util.log("ui: upsell remover ready");
    };

    const initModeToggle = () => {
      const FLASH = {
        labels: ["3.5 Flash", "Flash", "2.5 Flash"],
        pillHints: ["Flash"],
        testId: "bard-mode-option-56fdd199312815e2",
      };
      const PRO = {
        labels: ["3.1 Pro", "Pro", "Gemini Pro"],
        testId: "bard-mode-option-e6fa609c3fa255c0",
      };
      const THINKING = "Extended";
      let isProcessing = false;

      const waitUntil = async (test, timeoutMs = 2000, stepMs = 16) => {
        const start = Date.now();
        while (Date.now() - start < timeoutMs) {
          if (test()) return true;
          await util.sleep(stepMs);
        }
        return test();
      };

      const isVisible = (el) => {
        if (!el) return false;
        const rect = el.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
      };

      const findModeButton = () => {
        const hosts = [
          ...document.querySelectorAll('[data-test-id="bard-mode-menu-button"]'),
          ...document.querySelectorAll("bard-mode-switcher .logo-pill-btn"),
          ...document.querySelectorAll("button.input-area-switch"),
        ];
        for (const host of hosts) {
          const btn = host.matches?.("button")
            ? host
            : host.querySelector("button:not([disabled])");
          if (btn && !btn.disabled && isVisible(btn)) return btn;
        }
        for (const btn of document.querySelectorAll(
          'button[aria-label*="mode picker"], button[aria-label*="Mode picker"]'
        )) {
          if (!btn.disabled && isVisible(btn)) return btn;
        }
        return null;
      };

      const getVisiblePillLabel = () => {
        const containers = [
          ...document.querySelectorAll('[data-test-id="logo-pill-label-container"]'),
        ].filter(isVisible);
        const inModeButton = (container) =>
          container.closest(
            '[data-test-id="bard-mode-menu-button"], button.input-area-switch, [data-test-id="bard-mode-switcher"], bard-mode-switcher'
          );
        const preferred =
          containers.find((c) => c.classList.contains("thinking-level-enabled") && inModeButton(c)) ||
          containers.find((c) => inModeButton(c)) ||
          containers.find((c) => c.classList.contains("thinking-level-enabled")) ||
          containers[0];
        if (!preferred) return null;
        return {
          primary: preferred.querySelector(".picker-primary-text")?.textContent.trim() || "",
          secondary: preferred.querySelector(".picker-secondary-text")?.textContent.trim() || "",
        };
      };

      const getModePickerAria = () =>
        (findModeButton()?.getAttribute("aria-label") || "").toLowerCase();

      const pillText = () => {
        const pill = getVisiblePillLabel();
        if (!pill) return "";
        return `${pill.primary} ${pill.secondary}`.trim();
      };

      const isFlashExtended = () => {
        const pill = getVisiblePillLabel();
        const text = `${pillText()} ${getModePickerAria()}`.toLowerCase();
        if (!text) return false;
        const hasFlash = FLASH.pillHints.some((h) => text.includes(h.toLowerCase()));
        const hasExtended =
          text.includes("extended") ||
          (pill &&
            pill.primary &&
            FLASH.pillHints.some((h) => pill.primary === h) &&
            pill.secondary === THINKING);
        if (hasFlash && (hasExtended || text.includes("thinking"))) return true;
        if (pill?.primary === "Flash" && pill?.secondary === THINKING) return true;
        return false;
      };

      const isProMode = () => {
        const pill = getVisiblePillLabel();
        const text = `${pillText()} ${getModePickerAria()}`.toLowerCase();
        if (pill?.secondary === "Pro") return true;
        if (text.includes("gemini pro") || /\bpro\b/.test(text)) {
          if (text.includes("flash") && !text.includes("gemini pro")) return false;
          return true;
        }
        return PRO.labels.some((label) => pill?.primary === label || pill?.secondary === label);
      };

      const getCurrentState = () => {
        if (isProMode()) return "pro";
        if (isFlashExtended()) return "flash-extended";
        return "other";
      };

      const isMenuOpen = () => {
        const menu = document.querySelector('[data-test-id="gem-mode-menu"]');
        if (menu?.getAttribute("data-visible") === "true") return true;
        const popover = document.querySelector(
          '[data-test-id="bard-mode-desktop-gem-menu"], [data-test-id="bard-mode-mobile-gem-menu"], [data-test-id="bard-mode-gem-menu"], gem-popover[data-visible="true"]'
        );
        if (popover && isVisible(popover)) return true;
        return !!document.querySelector(
          'mat-option, .mat-mdc-option, gem-menu-item[role="menuitem"], [data-test-id^="bard-mode-option-"]'
        );
      };

      const closeMenu = () => {
        document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
      };

      const closeMenuAndWait = async () => {
        if (!isMenuOpen()) return;
        closeMenu();
        await waitUntil(() => !isMenuOpen(), 500, 16);
      };

      const ensureMenuOpen = async (button) => {
        if (isMenuOpen()) return true;
        button.click();
        return waitUntil(isMenuOpen, 2000, 16);
      };

      const getMenuItemLabel = (item) => {
        const label = item?.querySelector(
          ".label-container .label, .label, .title-text, .picker-primary-text, .gds-body-l"
        );
        return (
          label?.textContent.replace(/\s+/g, " ").trim() ||
          item?.textContent.replace(/\s+/g, " ").trim() ||
          ""
        );
      };

      const isMenuItemSelected = (item) =>
        item?.getAttribute("data-active") === "true" ||
        item?.classList.contains("selected") ||
        item?.getAttribute("aria-selected") === "true";

      const findMenuItem = (labels, testId) => {
        if (testId) {
          const byId = document.querySelector(`[data-test-id="${testId}"]`);
          if (byId && isVisible(byId)) return byId;
        }
        const wanted = Array.isArray(labels) ? labels : [labels];
        for (const item of document.querySelectorAll(
          'gem-menu-item[role="menuitem"], mat-option, .mat-mdc-option, [role="option"], [data-test-id^="bard-mode-option-"]'
        )) {
          if (!isVisible(item)) continue;
          if (item.getAttribute("value") === "thinking_level") continue;
          const text = getMenuItemLabel(item) || item.textContent.replace(/\s+/g, " ").trim();
          if (wanted.some((label) => text === label || text.includes(label))) return item;
        }
        return null;
      };

      const getThinkingLevelItem = () =>
        document.querySelector('gem-menu-item[value="thinking_level"]');

      const getCurrentThinkingLevel = () => {
        const pill = getVisiblePillLabel();
        if (
          pill?.secondary &&
          pill.secondary !== "Pro" &&
          (FLASH.pillHints.includes(pill.primary) ||
            pill.primary === "Gemini" ||
            FLASH.pillHints.some((h) => pill.secondary.includes(h)))
        ) {
          if (pill.secondary === THINKING || pill.secondary === "Flash") {
            return pill.secondary === THINKING ? THINKING : pill.secondary;
          }
          return pill.secondary;
        }
        return getThinkingLevelItem()?.querySelector(".sublabel")?.textContent.trim() || "";
      };

      const selectModel = async (button, model) => {
        if (!(await ensureMenuOpen(button))) return false;
        const item = findMenuItem(model.labels || model.label, model.testId);
        if (!item) return false;
        if (isMenuItemSelected(item)) return true;
        item.click();
        return waitUntil(() => isMenuItemSelected(item), 1500, 16);
      };

      const selectThinking = async (button, level) => {
        let thinkingItem = getThinkingLevelItem();
        if (!thinkingItem) {
          if (!(await ensureMenuOpen(button))) return false;
          thinkingItem = getThinkingLevelItem();
        }
        if (!thinkingItem) return true;
        if (getCurrentThinkingLevel() === level) return true;
        if (thinkingItem.getAttribute("aria-expanded") !== "true") {
          thinkingItem.click();
          await waitUntil(
            () => thinkingItem.getAttribute("aria-expanded") === "true" || !!findMenuItem(level),
            1500,
            16
          );
        }
        const levelItem = findMenuItem(level);
        if (!levelItem) return false;
        if (isMenuItemSelected(levelItem)) return true;
        levelItem.click();
        return waitUntil(() => getCurrentThinkingLevel() === level, 1500, 16);
      };

      const applyFlashExtended = async (button) => {
        await selectModel(button, { labels: FLASH.labels, testId: FLASH.testId });
        if (!isMenuOpen()) await ensureMenuOpen(button);
        await selectThinking(button, THINKING);
        await closeMenuAndWait();
      };

      const applyPro = async (button) => {
        await selectModel(button, { labels: PRO.labels, testId: PRO.testId });
        await closeMenuAndWait();
      };

      const toggleMode = async () => {
        if (isProcessing) return;
        const button = findModeButton();
        if (!button) {
          util.log("mode button not found");
          return;
        }
        isProcessing = true;
        try {
          const state = getCurrentState();
          const target = state === "pro" ? "flash-extended" : "pro";
          util.log(`mode ${state} -> ${target}`, pillText());
          if (target === "flash-extended") await applyFlashExtended(button);
          else await applyPro(button);
          util.focusAtEnd(util.getPromptInput());
        } catch (e) {
          util.log("mode error", e);
        } finally {
          await closeMenuAndWait();
          isProcessing = false;
        }
      };

      document.addEventListener(
        "keydown",
        (event) => {
          if (!event.ctrlKey || !event.shiftKey || event.key.toLowerCase() !== "y") return;
          event.preventDefault();
          event.stopPropagation();
          toggleMode();
        },
        true
      );
      util.log("ui: Ctrl+Shift+Y toggles Pro ↔ Flash + Extended");
    };

    const initHideCopySnack = () => {
      // Overlay container stays — it hosts menus. Hide only the copy snackbar.
      util.addStyle(
        `
        .cdk-overlay-pane:has(bard-simple-snack-bar),
        mat-snack-bar-container:has(bard-simple-snack-bar),
        bard-simple-snack-bar {
          display: none !important;
        }
        `,
        "tm-hide-gemini-copy-snack"
      );
      util.log("ui: Gemini copy snackbar hidden");
    };

    util.whenLoad(() => {
      initSidenav();
      initUpsell();
      initHideCopySnack();
      initModeToggle();
    });
  };

  // ── fixed input + type-anywhere focus ──

  const createInput = () => {
    util.addStyle(
      `
        input-area-v2 .text-input-field,
        input-area-v2 .text-input-field.simplified-input-area {
            height: ${INPUT_HEIGHT} !important;
            min-height: ${INPUT_HEIGHT} !important;
            max-height: ${INPUT_HEIGHT} !important;
        }
        input-area-v2 .textarea-wrapper,
        input-area-v2 [data-test-id="textarea-wrapper"],
        .text-input-field_textarea-wrapper {
            height: ${INPUT_HEIGHT} !important;
            min-height: ${INPUT_HEIGHT} !important;
            max-height: ${INPUT_HEIGHT} !important;
        }
        input-area-v2 .text-input-field_textarea-inner,
        input-area-v2 [data-test-id="textarea-inner"] {
            height: 100% !important;
            min-height: 100% !important;
            max-height: 100% !important;
        }
        input-area-v2 rich-textarea.text-input-field_textarea,
        input-area-v2 rich-textarea {
            height: 100% !important;
            min-height: 100% !important;
            max-height: 100% !important;
            --chat-container-height: ${INPUT_HEIGHT} !important;
        }
        input-area-v2 .ql-editor.textarea,
        input-area-v2 .ql-editor.new-input-ui {
            height: 100% !important;
            min-height: 100% !important;
            max-height: 100% !important;
            overflow-y: auto !important;
        }
        input-area-v2 .text-input-field-main-area,
        input-area-v2 .single-line-format {
            height: 100% !important;
            min-height: 100% !important;
            max-height: 100% !important;
        }
        .top-bar-actions {
            display: flex !important;
            justify-content: space-between !important;
            align-items: center !important;
        }
        .top-bar-actions .left-section,
        .top-bar-actions .right-section {
            flex: 1 1 0 !important;
            min-width: 0 !important;
        }
        .top-bar-actions .right-section {
            display: flex !important;
            justify-content: flex-end !important;
        }
        .top-bar-actions .center-section {
            flex: 0 1 auto !important;
            text-align: center !important;
        }
    `,
      "tm-gemini-input-height"
    );

    const isInInput = () => {
      const el = document.activeElement;
      if (!el) return false;
      const tag = el.tagName.toLowerCase();
      return tag === "input" || tag === "textarea" || el.isContentEditable;
    };

    document.addEventListener("keydown", (e) => {
      if (isInInput()) return;
      const input = util.getPromptInput();
      if (!input) return;
      if ((e.ctrlKey || e.metaKey) && e.key === "v") {
        util.focusAtEnd(input);
        return;
      }
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key.length !== 1) return;
      util.focusAtEnd(input);
    });

    util.log("input: fixed height + type-anywhere focus");
  };

  const finish = createFinishBus();
  const copy = createCopy(finish);
  const notify = createNotify(finish);
  createUi();
  createInput();

  global.geminiTm = { version: VERSION, util, copy, notify };
  util.log(`v${VERSION} · copy + toast + ui + input · geminiTm.version`);
})(typeof window !== "undefined" ? window : this);
