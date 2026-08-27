// ==UserScript==
// @name         Twitter
// @namespace    http://tampermonkey.net/
// @version      1.3.1
// @description  Ctrl+C copies tweet + comments. Hide New posts pill and verified badges.
// @author       You
// @match        https://x.com/*
// @match        https://twitter.com/*
// @grant        GM_setClipboard
// @grant        GM_addStyle
// @run-at       document-start
// ==/UserScript==

/*
 * v1.3.1 — PageUp/Down intercept commented out (likely F7 caret browsing).
 * v1.3.0 — PageUp/PageDown scroll the timeline 80% (X virtualizer snaps
 *          a full page back). overflow-anchor off; pin after layout.
 * v1.2.0 — Merged twitter-ui-cleanup-hide-pill-and-verified.js (CSS at document-start).
 * v1.1.0 — Readable paste: short links, photo credit, no pbs embed.
 *          Status pages include ## Comments (visible replies).
 * v1.0.0 — Ctrl+C (no selection) copies display name, @handle, time, body.
 *
 * Selectors from apps/tampermonkey/twitter/ele.txt
 * (Forbes status dump 2026-08-26, SingleFile of
 *  https://x.com/Forbes/status/2092363895503786486).
 * Pill / verified: same dump + archive/ele.htm, archive/individual.htm.
 */

(function (global) {
  "use strict";

  const VERSION = "1.3.1";
  const PAGE_SCROLL_PCT = 0.8;
  const UI_CSS_ID = "jefr-twitter-ui-css";
  const UI_CSS = `
    /* Page-scroll experiment (v1.3.0) — off for now
    html {
      overflow-anchor: none !important;
    }
    [data-testid="primaryColumn"],
    [data-testid="primaryColumn"] [data-viewportview="true"] {
      overflow-anchor: none !important;
    }
    */
    [role="status"][data-keep-composer-open="true"] {
      display: none !important;
    }
    button[aria-label*="New posts are available"] {
      display: none !important;
    }
    [data-testid="icon-verified"] {
      display: none !important;
    }
    svg[aria-label="Verified account"] {
      display: none !important;
    }
    span:has(> [data-testid="icon-verified"]),
    span:has(> svg[aria-label="Verified account"]) {
      display: none !important;
    }
    a[href*="rules-and-policies/authenticity"] {
      display: none !important;
    }
    [style*="parody-mask"],
    img[src*="parody-mask"] {
      display: none !important;
    }
    div:has(> a[href*="rules-and-policies/authenticity"]) {
      display: none !important;
    }
  `;
  const LOG = "[Twitter]";
  const TOAST_MS = 2400;
  const TOAST_FADE_MS = 420;
  const TOAST_ID = "jefr-twitter-copy-toast";

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

  let lastHoverTweet = null;

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

    statusIdFromUrl(href) {
      const m = String(href || "").match(/\/status\/(\d+)/);
      return m ? m[1] : "";
    },

    pageStatusId() {
      return util.statusIdFromUrl(location.pathname);
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

    tidyUrl(url) {
      let raw = String(url || "")
        .replace(/[…]+$/g, "")
        .replace(/\.{2,}$/g, "")
        .trim();
      if (!raw) return "";
      if (!/^https?:\/\//i.test(raw) && /^[\w.-]+\.[a-z]{2,}\//i.test(raw)) {
        raw = "https://" + raw;
      }
      try {
        const u = new URL(raw);
        for (const k of [...u.searchParams.keys()]) {
          if (/^(utm_|ref$)/i.test(k) || /^utm_/i.test(k)) u.searchParams.delete(k);
        }
        u.hash = "";
        let s = u.toString();
        if (s.endsWith("?")) s = s.slice(0, -1);
        return s;
      } catch (_) {
        return raw.split("?")[0];
      }
    },

    hostLabel(url) {
      try {
        return new URL(url).hostname.replace(/^www\./i, "");
      } catch (_) {
        return "link";
      }
    },

    mdLink(text, href) {
      const label = String(text || "")
        .replace(/\[/g, "\\[")
        .replace(/\]/g, "\\]")
        .replace(/\s+/g, " ")
        .trim();
      if (!label) return "";
      let url = util.tidyUrl(util.absUrl(href));
      if (!url || url === label) return label;
      if (/[\s()]/.test(url)) url = "<" + url.replace(/[<>]/g, "") + ">";
      return `[${label}](${url})`;
    },

    skipNode(el) {
      if (!el || el.nodeType !== 1) return false;
      if (SKIP.has(el.tagName.toLowerCase())) return true;
      const testid = el.getAttribute?.("data-testid") || "";
      if (
        /^(caret|reply|retweet|like|bookmark|app-text-transition-container)$/.test(
          testid
        )
      ) {
        return true;
      }
      if (el.closest?.("[data-testid='icon-verified']")) return true;
      if (el.getAttribute?.("aria-label") === "Verified account") return true;
      return false;
    },

    wrapMark(mark, inner) {
      const raw = String(inner ?? "");
      const t = raw.trim();
      if (!t || /^[\s.,;:!?…—–\-]+$/.test(t)) return raw;
      return mark + t + mark;
    },

    beautify(s) {
      return String(s || "")
        .replace(/[ \t]+\n/g, "\n")
        .replace(/[ \t]{2,}/g, " ")
        .replace(/\n{3,}/g, "\n\n")
        .trim();
    },

    isMediaHref(href) {
      return /\/status\/\d+\/(photo|video|analytics|quotes)(?:\/|$)/i.test(
        href || ""
      );
    },

    anchorMarkdown(el) {
      const href = util.absUrl(el.getAttribute("href") || "");
      if (util.isMediaHref(href)) return "";
      const title = (el.getAttribute("title") || "").trim();
      let visible = util.inline(el);
      let url = href;
      if (/^https?:\/\//i.test(title) && !/t\.co\//i.test(title)) {
        url = title;
      } else if (/t\.co\//i.test(href) || !href) {
        const visUrl = visible.replace(/[…]+$/g, "").trim();
        if (/^(https?:\/\/)?[\w.-]+\.[a-z]{2,}\//i.test(visUrl)) url = visUrl;
      }
      url = util.tidyUrl(url);
      const isWeb =
        /^(https?:\/\/)?[\w.-]+\.[a-z]{2,}/i.test(visible) ||
        /t\.co\//i.test(href);
      const label = isWeb ? util.hostLabel(url) : visible;
      return util.mdLink(label, url) || visible;
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
        if (t === "br") {
          s += "\n";
          return;
        }
        if (t === "img") {
          const alt = (n.getAttribute("alt") || "").trim();
          if (alt && alt.length <= 8) s += alt;
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
          s += util.anchorMarkdown(n);
          return;
        }
        n.childNodes.forEach(walk);
      };
      el.childNodes.forEach(walk);
      return s.replace(/[ \t]+\n/g, "\n").replace(/[ \t]{2,}/g, " ").trim();
    },

    formatBody(raw) {
      let s = String(raw || "");
      s = s.replace(/\s+(Read more:)\s*/i, "\n\n$1 ");
      s = s.replace(/\s*📸\s*:\s*/g, "\n\n_Photo: ");
      s = s.replace(/\s+:\s+(?=[\w].{8,120}$)/g, "\n\n_Photo: ");
      if (/_Photo: /.test(s) && !s.trim().endsWith("_")) s = s.trim() + "_";
      return s.trim();
    },

    tweetArticles() {
      const col =
        document.querySelector('[data-testid="primaryColumn"]') || document;
      return [...col.querySelectorAll('article[data-testid="tweet"]')].filter(
        (el) => !el.querySelector('[data-testid="tweetTextarea_0"]')
      );
    },

    tweetId(article) {
      if (!article) return "";
      for (const a of article.querySelectorAll('a[href*="/status/"]')) {
        const href = a.getAttribute("href") || "";
        if (a.closest('[data-testid="User-Name"]')) continue;
        if (util.isMediaHref(href)) {
          const id = util.statusIdFromUrl(href);
          if (id) return id;
          continue;
        }
        const id = util.statusIdFromUrl(href);
        if (id) return id;
      }
      return util.statusIdFromUrl(
        article.querySelector('a[href*="/status/"]')?.getAttribute("href") || ""
      );
    },

    expandShowMore(root) {
      if (!root) return;
      for (const btn of root.querySelectorAll(
        '[data-testid="tweet-text-show-more-link"]'
      )) {
        try {
          btn.click();
        } catch (_) {}
      }
    },

    pickTweet() {
      const arts = util.tweetArticles();
      if (!arts.length) return null;
      const id = util.pageStatusId();
      if (id) {
        const hit = arts.find((el) => util.tweetId(el) === id);
        if (hit) return hit;
        return arts[0];
      }
      const focus = document.activeElement;
      if (focus) {
        const fromFocus = focus.closest?.('article[data-testid="tweet"]');
        if (fromFocus && arts.includes(fromFocus)) return fromFocus;
      }
      if (lastHoverTweet && arts.includes(lastHoverTweet)) return lastHoverTweet;
      return arts[0];
    },

    displayAndHandle(article) {
      const nameRoot = article.querySelector('[data-testid="User-Name"]');
      let display = "";
      let handle = "";
      if (nameRoot) {
        const handleEl = [...nameRoot.querySelectorAll("span")].find((el) =>
          /^@\w/.test((el.textContent || "").trim())
        );
        handle = handleEl ? handleEl.textContent.trim() : "";
        const nameLink = nameRoot.querySelector('a[role="link"]');
        if (nameLink) {
          const span = nameLink.querySelector("span span") || nameLink;
          display = (span.textContent || "").replace(/\s+/g, " ").trim();
        }
        if (!display) display = util.inline(nameRoot);
        if (handle) {
          display = display.replace(handle, "").replace(/[·]+/g, "").trim();
        }
      }
      const time = article.querySelector("time");
      const when = time
        ? (time.textContent || "").replace(/\s+/g, " ").trim()
        : "";
      return { display, handle, when };
    },

    bodyMarkdown(article) {
      const texts = [...article.querySelectorAll('[data-testid="tweetText"]')]
        .filter((el) => !el.closest('[data-testid="tweetTextarea_0"]'))
        .filter((el) => !el.closest('[data-testid="quoteTweet"]'))
        .map((el) => util.formatBody(util.inline(el)))
        .filter((t) => t && !/^post your reply$/i.test(t));
      const quote = article.querySelector('[data-testid="quoteTweet"]');
      let q = "";
      if (quote) {
        const qt = quote.querySelector('[data-testid="tweetText"]');
        const qn = util.displayAndHandle(quote);
        const qb = qt ? util.formatBody(util.inline(qt)) : "";
        const who = [qn.display, qn.handle].filter(Boolean).join(" ");
        q = [who && "> **" + who + "**", qb && "> " + qb.replace(/\n/g, "\n> ")]
          .filter(Boolean)
          .join("\n");
      }
      return [texts.join("\n\n"), q].filter(Boolean).join("\n\n");
    },

    permalink(article) {
      const id = util.tweetId(article) || util.pageStatusId();
      if (!id) return location.href.split("?")[0];
      const { handle } = util.displayAndHandle(article);
      const h = (handle || "").replace(/^@/, "");
      if (h) return `https://x.com/${h}/status/${id}`;
      return `https://x.com/i/status/${id}`;
    },

    formatTweet(article, asMain) {
      if (!article) return "";
      util.expandShowMore(article);
      const { display, handle, when } = util.displayAndHandle(article);
      const body = util.bodyMarkdown(article);
      if (!body && !display) return "";
      const credit = [handle, when].filter(Boolean).join(" · ");
      if (asMain) {
        return [display && "# " + display, credit, body, util.permalink(article)]
          .filter(Boolean)
          .join("\n\n");
      }
      const who = display
        ? `**${display}**${handle ? " (" + handle + ")" : ""}`
        : handle || "Reply";
      return [who + (when ? " · " + when : ""), body].filter(Boolean).join("\n\n");
    },

    extractMarkdown() {
      const arts = util.tweetArticles();
      const main = util.pickTweet();
      if (!main) return "";
      const col =
        document.querySelector('[data-testid="primaryColumn"]') || document;
      util.expandShowMore(col);
      const mainMd = util.formatTweet(main, true);
      const onStatus = !!util.pageStatusId();
      if (!onStatus) return util.beautify(mainMd);
      const mainId = util.tweetId(main);
      const comments = arts
        .filter((el) => el !== main && util.tweetId(el) !== mainId)
        .map((el) => util.formatTweet(el, false))
        .filter(Boolean);
      if (!comments.length) return util.beautify(mainMd);
      return util.beautify(
        mainMd + "\n\n## Comments\n\n" + comments.join("\n\n---\n\n")
      );
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

    nearestScroller(from) {
      let el = from;
      while (el && el !== document.documentElement) {
        if (el === document.body) break;
        const st = getComputedStyle(el);
        const oy = st.overflowY;
        if (
          (oy === "auto" || oy === "scroll" || oy === "overlay") &&
          el.scrollHeight > el.clientHeight + 80
        ) {
          return el;
        }
        el = el.parentElement;
      }
      return document.scrollingElement || document.documentElement;
    },

    timelineScroller() {
      const tweet =
        lastHoverTweet ||
        document.querySelector(
          '[data-testid="primaryColumn"] article[data-testid="tweet"]'
        ) ||
        document.querySelector('article[data-testid="tweet"]');
      const col = document.querySelector('[data-testid="primaryColumn"]');
      if (tweet) return util.nearestScroller(tweet);
      if (col) return util.nearestScroller(col);
      return document.scrollingElement || document.documentElement;
    },

    releaseTweetFocus() {
      const ae = document.activeElement;
      if (!ae || util.isInEditable(ae)) return;
      if (ae.closest?.('article[data-testid="tweet"]')) {
        try {
          ae.blur();
        } catch (_) {}
      }
    },

    scrollPage(dir) {
      util.releaseTweetFocus();
      const scroller = util.timelineScroller();
      const isDoc =
        scroller === document.documentElement ||
        scroller === document.body ||
        scroller === document.scrollingElement;
      const viewH = isDoc ? window.innerHeight : scroller.clientHeight;
      const delta = viewH * PAGE_SCROLL_PCT * dir;
      const target = isDoc
        ? Math.max(0, window.scrollY + delta)
        : scroller.scrollTop + delta;
      const pin = () => {
        if (isDoc) {
          window.scrollTo(0, target);
          return;
        }
        const max = Math.max(0, scroller.scrollHeight - scroller.clientHeight);
        scroller.scrollTop = Math.max(0, Math.min(max, target));
      };
      pin();
      requestAnimationFrame(() => {
        pin();
        requestAnimationFrame(pin);
      });
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

  util.addStyle(UI_CSS, UI_CSS_ID);

  const showToast = () => {
    util.addStyle(
      `
      #${TOAST_ID}{
        position:fixed !important;left:50% !important;right:auto !important;
        top:auto !important;bottom:36px;z-index:2147483647 !important;
        pointer-events:none;display:flex;align-items:center;gap:12px;
        padding:10px 20px 10px 10px;border-radius:999px;
        font:500 15px/1.25 "TwitterChirp","Segoe UI",system-ui,sans-serif;
        letter-spacing:.02em;color:#fff;background:#0f1419;
        border:1px solid rgba(255,255,255,.12);
        box-shadow:0 8px 28px rgba(0,0,0,.32);
        transform:translate(-50%,10px) scale(.97);opacity:0;
        transition:opacity ${TOAST_FADE_MS}ms ease, transform ${TOAST_FADE_MS}ms ease;
      }
      #${TOAST_ID}.on{opacity:1;transform:translate(-50%,0) scale(1)}
      #${TOAST_ID} .mark{
        width:26px;height:26px;border-radius:50%;flex:none;
        display:flex;align-items:center;justify-content:center;background:#1d9bf0;
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

  document.addEventListener(
    "mouseover",
    (e) => {
      const art = e.target?.closest?.('article[data-testid="tweet"]');
      if (art && !art.querySelector('[data-testid="tweetTextarea_0"]')) {
        lastHoverTweet = art;
      }
    },
    true
  );

  // PageUp/Down timeline scroll (v1.3.0) — off for now. Snap-back was
  // likely Chrome F7 caret browsing, not the feed virtualizer.
  // document.addEventListener(
  //   "keydown",
  //   (e) => {
  //     if (e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
  //     const up = e.key === "PageUp" || e.code === "PageUp";
  //     const down = e.key === "PageDown" || e.code === "PageDown";
  //     if (!up && !down) return;
  //     if (util.isInEditable(e.target) || util.isInEditable(document.activeElement)) {
  //       return;
  //     }
  //     e.preventDefault();
  //     e.stopImmediatePropagation();
  //     util.scrollPage(down ? 1 : -1);
  //   },
  //   true
  // );

  let busy = false;
  document.addEventListener(
    "keydown",
    (e) => {
      if (!(e.key === "c" || e.key === "C")) return;
      if (!e.ctrlKey || e.altKey || e.metaKey || e.shiftKey) return;
      if (util.hasTextSelection()) return;
      if (util.isInEditable(document.activeElement)) return;
      const article = util.pickTweet();
      if (!article) {
        util.log("Ctrl+C skipped — no tweet");
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

  global.twitterTm = { version: VERSION, util };
  util.log(`v${VERSION} · Ctrl+C copies tweet · hide pill + verified`);
})(typeof window !== "undefined" ? window : this);
