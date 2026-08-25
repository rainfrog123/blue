// ==UserScript==
// @name         FT
// @namespace    http://tampermonkey.net/
// @version      1.0.3
// @description  Ctrl+C with no selection copies the full article when it is not paywalled.
// @author       You
// @match        https://www.ft.com/*
// @match        https://www.ft.com/content/*
// @grant        GM_setClipboard
// @grant        GM_addStyle
// @run-at       document-idle
// ==/UserScript==

/*
 * v1.0.3 — Escape bare [editorial] brackets so Obsidian does not treat them as links.
 * v1.0.2 — Drop .article__content-sign-up-topic-description by class + final strip.
 * v1.0.1 — Skip in-article newsletter promos (signup box + Roula/WH Watch blurbs).
 * v1.0.0 — Ctrl+C (no selection) copies title + dek + byline + body.
 *          Same behaviour as apps/tampermonkey/wsj/wsj.js.
 *
 * Selectors from apps/tampermonkey/ft/ele.txt (2026-08-23 dump).
 */

(function (global) {
  "use strict";

  const VERSION = "1.0.3";
  const LOG = "[FT]";
  const TOAST_MS = 2400;
  const TOAST_FADE_MS = 420;
  const TOAST_ID = "jefr-ft-copy-toast";

  const SKIP = new Set([
    "script",
    "style",
    "button",
    "svg",
    "noscript",
    "nav",
    "aside",
    "form",
    "iframe",
  ]);

  const util = {
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

    meta(name) {
      return (
        document.querySelector(`meta[name="${name}"]`)?.content ||
        document.querySelector(`meta[property="${name}"]`)?.content ||
        ""
      );
    },

    jsonLd() {
      for (const s of document.querySelectorAll('script[type="application/ld+json"]')) {
        try {
          const j = JSON.parse(s.textContent);
          const items = Array.isArray(j) ? j : [j];
          const art = items.find((x) => x && (x["@type"] === "NewsArticle" || (Array.isArray(x["@type"]) && x["@type"].includes("NewsArticle"))));
          if (art) return art;
        } catch (_) {}
      }
      return null;
    },

    isVisible(el) {
      if (!el) return false;
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 8;
    },

    isArticlePage() {
      if (/\/content\//.test(location.pathname)) return true;
      return !!(
        document.querySelector("article#site-content") ||
        document.querySelector(".article-content") ||
        document.querySelector("h1.o-topper__headline")
      );
    },

    isPaywalled() {
      const words = util.bodyWordCount();
      const ld = util.jsonLd();
      const expected = Number(ld?.wordCount) || 0;
      if (expected >= 200 && words >= expected * 0.4) return false;
      if (!expected && words >= 120) return false;

      for (const sel of [
        "[data-component='barrier']",
        ".n-ui-barrier",
        "#barrier-page",
        ".subscription-prompt",
      ]) {
        const el = document.querySelector(sel);
        if (!el || !util.isVisible(el)) continue;
        const t = (el.innerText || "").replace(/\s+/g, " ").trim();
        if (
          el.getBoundingClientRect().height > 80 &&
          /subscribe|sign in|already a subscriber|register/i.test(t)
        ) {
          return true;
        }
      }

      if (expected >= 200 && words < expected * 0.4) return true;
      if (!expected && words < 80) return true;
      return false;
    },

    articleRoot() {
      return (
        document.querySelector("article#site-content") ||
        document.querySelector("article.article") ||
        document.querySelector(".article-content") ||
        null
      );
    },

    absUrl(href) {
      const raw = String(href || "").trim();
      if (!raw || /^(javascript:|mailto:|#)/i.test(raw)) return "";
      try {
        return new URL(raw, document.baseURI || location.href).href;
      } catch (_) {
        return raw;
      }
    },

    mdLink(text, href) {
      const label = String(text || "")
        .replace(/\[/g, "\\[")
        .replace(/\]/g, "\\]")
        .replace(/\s+/g, " ")
        .trim();
      if (!label) return "";
      let url = util.absUrl(href);
      if (!url || url === label) return label;
      if (/[\s()]/.test(url)) url = "<" + url.replace(/[<>]/g, "") + ">";
      return `[${label}](${url})`;
    },

    isTickerNode(el) {
      if (!el || el.nodeType !== 1) return false;
      const href = el.getAttribute?.("href") || "";
      if (/markets\.ft\.com|\/data\/equities/i.test(href)) return true;
      if (el.querySelector?.('a[href*="markets.ft.com"], a[href*="/equities/"]')) {
        const t = (el.textContent || "").replace(/\s+/g, " ").trim();
        return t.length < 120;
      }
      return false;
    },

    tickerMarkdown(el) {
      const a =
        el.tagName.toLowerCase() === "a"
          ? el
          : el.querySelector?.('a[href*="markets.ft.com"], a[href*="equities"]');
      const href = a ? a.getAttribute("href") : "";
      const raw = (el.textContent || "").replace(/\s+/g, " ").trim();
      let symbol = "";
      const fromHref = util.absUrl(href).match(/\/equities\/([^/?#]+)/i);
      if (fromHref) {
        try {
          symbol = decodeURIComponent(fromHref[1]).replace(/\+/g, " ");
        } catch (_) {
          symbol = fromHref[1];
        }
      }
      if (!symbol) {
        const m = raw.match(/\b([A-Z]{1,6}(?:\.[A-Z])?)\b/);
        if (m) symbol = m[1];
      }
      let name = "";
      if (symbol && raw.includes(symbol)) {
        name = raw.slice(0, raw.indexOf(symbol)).replace(/[,\s]+$/g, "").trim();
      }
      const label =
        name && symbol && name.toLowerCase() !== symbol.toLowerCase()
          ? `${name} (${symbol})`
          : name || symbol || raw;
      return util.mdLink(label, href) || label;
    },

    skipNode(el) {
      if (!el || el.nodeType !== 1) return false;
      if (SKIP.has(el.tagName.toLowerCase())) return true;
      if (util.isPromoEl(el)) return true;
      if (
        el.closest?.(
          ".o-share, .share-nav, .n-myft-ui, .o-ads, .js-article-ribbon, .comments, .comments-container, .concept-list, .o-header, .o-footer, [data-o-component='o-ads']"
        )
      ) {
        return true;
      }
      return false;
    },

    promoClass(el) {
      const cls = typeof el.className === "string" ? el.className : el.getAttribute?.("class") || "";
      return /article__content-sign-up/i.test(cls);
    },

    isPromoEl(el) {
      if (!el || el.nodeType !== 1) return false;
      if (util.promoClass(el)) return true;
      return !!el.closest?.(".article__content-sign-up, .article__content-sign-up-topic-description, .article__content-sign-up-topic-title");
    },

    isPromoText(s) {
      const t = String(s || "")
        .replace(/\s+/g, " ")
        .replace(/\u00a0/g, " ")
        .replace(/[’‘]/g, "'")
        .trim();
      if (!t || t.length > 320) return false;
      if (/roula khalaf/i.test(t)) return true;
      if (/selects her favourite stories/i.test(t)) return true;
      if (/your guide to what trump/i.test(t)) return true;
      if (/unlock the .+(newsletter|digest)/i.test(t)) return true;
      if (/this weekly newsletter/i.test(t)) return true;
      if (/editor'?s digest/i.test(t) && t.length < 80) return true;
      return false;
    },

    wrapMark(mark, inner) {
      const raw = String(inner ?? "");
      const t = raw.trim();
      if (!t || /^[\s.,;:!?…—–\-]+$/.test(t)) return raw;
      return mark + t + mark;
    },

    escapeBareBrackets(s) {
      return String(s || "").replace(/\[([^\]]+)\](?!\()/g, "\\[$1\\]");
    },

    beautify(s) {
      return util.escapeBareBrackets(
        String(s || "")
          .replace(/\*\*\s*\*\*/g, "")
          .replace(/(\w)\*\*([.,;:!?])\*\*/g, "$1$2")
          .replace(/\*\*([^*]+)\*\*\*\*([^*]+)\*\*/g, "**$1$2**")
          .replace(/[ \t]+\n/g, "\n")
          .replace(/[ \t]{2,}/g, " ")
          .replace(/\n{3,}/g, "\n\n")
          .trim()
      );
    },

    inline(el) {
      let s = "";
      const walk = (n) => {
        if (!n) return;
        if (n.nodeType === 3) {
          s += n.textContent.replace(/\u00a0/g, " ");
          return;
        }
        if (n.nodeType !== 1 || util.skipNode(n)) return;
        const t = n.tagName.toLowerCase();
        if (util.isTickerNode(n)) {
          const md = util.tickerMarkdown(n) || (n.textContent || "").replace(/\s+/g, " ").trim();
          if (md) s += (s && !/\s$/.test(s) ? " " : "") + md;
          return;
        }
        if (t === "br") {
          s += "\n";
          return;
        }
        if (t === "strong" || t === "b") {
          s += util.wrapMark("**", util.inline(n));
          return;
        }
        if (t === "em" || t === "i") {
          s += util.wrapMark("*", util.inline(n));
          return;
        }
        if (t === "a") {
          s += util.mdLink(util.inline(n), n.getAttribute("href") || "") || util.inline(n);
          return;
        }
        n.childNodes.forEach(walk);
      };
      el.childNodes.forEach(walk);
      return s.replace(/[ \t]+\n/g, "\n").replace(/[ \t]{2,}/g, " ").trim();
    },

    htmlToMarkdown(root) {
      if (!root) return "";
      const blocks = [];
      const render = (el) => {
        if (!el) return;
        if (el.nodeType === 3) {
          const t = el.textContent.replace(/\u00a0/g, " ").replace(/\s+/g, " ").trim();
          if (t) blocks.push(t);
          return;
        }
        if (el.nodeType !== 1 || util.skipNode(el)) return;
        const tag = el.tagName.toLowerCase();
        if (/^h[1-6]$/.test(tag)) {
          const t = util.inline(el);
          if (t) blocks.push("#".repeat(+tag[1]) + " " + t);
          return;
        }
        if (tag === "p") {
          const t = util.inline(el);
          if (t && !util.isPromoText(t)) blocks.push(t);
          return;
        }
        if (tag === "blockquote") {
          const t = util.inline(el);
          if (t) blocks.push(t.split("\n").map((l) => "> " + l).join("\n"));
          return;
        }
        if (tag === "ul" || tag === "ol") {
          const ordered = tag === "ol";
          let n = 1;
          const lines = [];
          for (const li of el.children) {
            if (li.tagName.toLowerCase() !== "li") continue;
            const t = util.inline(li);
            if (t) lines.push((ordered ? `${n}. ` : "- ") + t);
            n += 1;
          }
          if (lines.length) blocks.push(lines.join("\n"));
          return;
        }
        if (tag === "figcaption") {
          const t = util.inline(el);
          if (t) blocks.push("_" + t + "_");
          return;
        }
        if (tag === "figure" || tag === "picture" || tag === "img") {
          const cap = el.querySelector?.("figcaption");
          if (cap) render(cap);
          return;
        }
        el.childNodes.forEach(render);
      };
      root.childNodes.forEach(render);
      return blocks.filter(Boolean).join("\n\n").replace(/\n{3,}/g, "\n\n").trim();
    },

    headerMarkdown() {
      const h1 =
        document.querySelector("h1.o-topper__headline .headline__text") ||
        document.querySelector("h1.o-topper__headline") ||
        document.querySelector("article h1") ||
        document.querySelector("h1");
      const dek = document.querySelector(".o-topper__standfirst");
      const by = document.querySelector(".article-info__byline");
      const time = document.querySelector(".article-info__timestamp");
      const ld = util.jsonLd();
      const parts = [];
      const title =
        (h1 && util.inline(h1)) || ld?.headline || util.meta("og:title");
      if (title) parts.push("# " + title);
      const dekText = dek ? util.inline(dek) : ld?.description || util.meta("og:description");
      if (dekText && dekText !== title) {
        parts.push(
          dekText
            .split("\n")
            .map((l) => "> " + l.replace(/^>\s*/, ""))
            .join("\n")
        );
      }
      const who = by
        ? util.inline(by).replace(/\s+/g, " ")
        : ld?.author?.[0]?.name || util.meta("article:author");
      const when = time
        ? (time.getAttribute("datetime")
            ? time.getAttribute("title") || time.textContent
            : util.inline(time)
          ).replace(/\s+/g, " ")
        : "";
      const credit = [who, when].filter(Boolean).join(" · ");
      if (credit) parts.push(credit);
      return parts.join("\n\n");
    },

    bodyRoot() {
      return (
        document.querySelector("#article-body") ||
        document.querySelector("[data-component='article-content-body']") ||
        document.querySelector("[data-attribute='article-content-body']") ||
        document.querySelector("article.n-content-body") ||
        document.querySelector(".n-content-body") ||
        document.querySelector('.article__content[data-trackable="article-body"]') ||
        document.querySelector("[data-component='article-body']") ||
        util.articleRoot()
      );
    },

    bodyParagraphMarkdown() {
      const root =
        document.querySelector(
          "#article-body, [data-component='article-content-body'], [data-attribute='article-content-body']"
        ) || util.bodyRoot();
      if (!root) return "";
      return [...root.querySelectorAll("p")]
        .filter((p) => !util.isPromoEl(p))
        .filter(
          (p) =>
            !p.closest(
              ".comments, .comments-container, .article-info, .concept-list, .o-share, .n-myft-ui"
            )
        )
        .map((p) => util.inline(p))
        .filter((t) => t && !util.isPromoText(t))
        .join("\n\n");
    },

    bodyWordCount() {
      const md = util.bodyParagraphMarkdown() || util.htmlToMarkdown(util.bodyRoot());
      if (!md) return 0;
      return md.split(/\s+/).filter(Boolean).length;
    },

    extractMarkdown() {
      const header = util.headerMarkdown();
      const body =
        util.bodyParagraphMarkdown() || util.htmlToMarkdown(util.bodyRoot());
      const md = util.beautify([header, body].filter(Boolean).join("\n\n"));
      return md
        .split(/\n{2,}/)
        .filter((block) => !util.isPromoText(block.replace(/^[#>*_\s]+/, "")))
        .join("\n\n");
    },

    hasTextSelection() {
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
    },

    isInEditable(el) {
      if (!el) return false;
      if (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable) {
        return true;
      }
      return !!el.closest?.("input, textarea, [contenteditable='true']");
    },

    async writeClipboard(text) {
      if (!text) return false;
      try {
        if (typeof GM_setClipboard === "function") {
          GM_setClipboard(text, "text");
          return true;
        }
      } catch (e) {
        util.log("GM_setClipboard failed", e);
      }
      try {
        if (navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(text);
          return true;
        }
      } catch (e) {
        util.log("clipboard.writeText failed", e);
      }
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
    },
  };

  const showToast = () => {
    util.addStyle(
      `
      #${TOAST_ID}{
        position:fixed !important;left:50% !important;right:auto !important;
        top:auto !important;bottom:36px;z-index:2147483647 !important;
        pointer-events:none;display:flex;align-items:center;gap:12px;
        padding:10px 20px 10px 10px;border-radius:999px;
        font:500 15px/1.25 "Metric 2",Metric,"Segoe UI",system-ui,sans-serif;
        letter-spacing:.02em;color:#fff1e5;background:#33302e;
        border:1px solid rgba(255,241,229,.12);
        box-shadow:0 8px 28px rgba(0,0,0,.32);
        transform:translate(-50%,10px) scale(.97);opacity:0;
        transition:opacity ${TOAST_FADE_MS}ms ease, transform ${TOAST_FADE_MS}ms ease;
      }
      #${TOAST_ID}.on{opacity:1;transform:translate(-50%,0) scale(1)}
      #${TOAST_ID} .mark{
        width:26px;height:26px;border-radius:50%;flex:none;
        display:flex;align-items:center;justify-content:center;background:#0d7680;
      }
      `,
      TOAST_ID + "-css"
    );
    document.getElementById(TOAST_ID)?.remove();
    const el = document.createElement("div");
    el.id = TOAST_ID;
    el.setAttribute("role", "status");
    const mark = document.createElement("span");
    mark.className = "mark";
    mark.textContent = "✓";
    const label = document.createElement("span");
    label.textContent = "Copied";
    el.append(mark, label);
    (document.body || document.documentElement).appendChild(el);
    requestAnimationFrame(() => {
      requestAnimationFrame(() => el.classList.add("on"));
    });
    setTimeout(() => {
      el.classList.remove("on");
      setTimeout(() => el.remove(), TOAST_FADE_MS);
    }, TOAST_MS);
  };

  let busy = false;
  document.addEventListener(
    "keydown",
    (e) => {
      if (!(e.key === "c" || e.key === "C")) return;
      if (!e.ctrlKey || e.altKey || e.metaKey || e.shiftKey) return;
      if (!util.isArticlePage()) return;
      if (util.hasTextSelection()) return;
      if (util.isInEditable(document.activeElement)) return;
      if (util.isPaywalled()) {
        util.log("Ctrl+C skipped — paywalled");
        return;
      }
      e.preventDefault();
      e.stopPropagation();
      if (busy) return;
      busy = true;
      const text = util.extractMarkdown();
      util
        .writeClipboard(text)
        .then((ok) => {
          util.log(
            ok ? "copied" : "FAILED",
            `${text.length} chars`,
            typeof GM_setClipboard === "function" ? "GM_ok" : "GM_missing"
          );
          if (ok) showToast();
        })
        .finally(() => {
          setTimeout(() => {
            busy = false;
          }, 300);
        });
    },
    true
  );

  global.ftTm = { version: VERSION, util };
  util.log(`v${VERSION} · Ctrl+C copies article when unlocked`);
})(typeof window !== "undefined" ? window : this);
