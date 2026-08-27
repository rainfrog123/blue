// ==UserScript==
// @name         Hyperliquid Light Theme
// @namespace    http://tampermonkey.net/
// @version      1.10.0
// @description  Light chrome + TV invert. No dark first-paint; hover ink; slider/primary.
// @author       You
// @match        https://app.hyperliquid.xyz/*
// @match        https://app.hyperliquid.com/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

/*
 * v1.10.0 — cloak until first light paint so the app never flashes dark then white.
 * v1.9.0 — dump 2026-08-26: :hover still #F6FEFD; new dark greys; body #303030;
 *          observer skipped style on lit nodes. Hover paint + CSS backups.
 * v1.8.0 — leverage slider track/fill/thumb and primary buttons were
 *          painted white (dark teal failed isBrightAccent). Restore mint.
 * v1.7.0 — invert of white TV chrome/gaps painted thick black edges.
 *          Pre-invert html/body to near-black; separators to #3a3f3d
 *          so they read as light gray after invert.
 * v1.6.0 — account-table chevron (sc-lbVpMG) still had a dark ::before
 *          scroll fade over "Order History". Kill overlay + remap gradients.
 * v1.5.0 — TradingView: always invert the about:blank document (and nested
 *          iframes) with an inline filter. changeTheme / parent iframe
 *          filter / data-hl-tv=native never actually lit the canvas.
 * v1.4.0 — whole.txt: :root --hl-* tokens + themed.css (.theme-dark only).
 * v1.3.0 — rewrite #F6FEFD attrs; invert iframe element; visible borders only.
 * v1.2.0 — TV hook + stroke CSS.
 * v1.1.0 — luminance painter, parents first.
 */

(function () {
  "use strict";

  const LOG = "[HL Light]";
  const STYLE_ID = "hl-light-theme";
  const DONE = "data-hl-lit";

  const PAGE = "#f3f5f4";
  const PANEL = "#ffffff";
  const TEXT = "#1a2421";
  const TEXT_STRONG = "#111816";
  const MUTED = "#5c6865";
  const BORDER = "#d7dedb";
  const ACCENT_BG = "#d4ebe6";
  const MINT = "#50d2c1";
  const MINT_OFF = "#c5ebe3";
  const TRACK = "#e4eae8";
  const INK = "#04120f";

  const LIGHT_INK = new Set([
    "#f6fefd",
    "#d2dad7",
    "#ffffff",
    "#fff",
    "white",
    "rgb(246, 254, 253)",
    "rgb(246,254,253)",
    "rgb(210, 218, 215)",
    "rgb(210,218,215)",
    "rgb(255, 255, 255)",
    "rgb(255,255,255)",
    "rgba(246, 254, 253, 0.6)",
    "rgba(246,254,253,0.6)",
  ]);

  const SKIP_TAG = new Set([
    "SCRIPT",
    "STYLE",
    "LINK",
    "NOSCRIPT",
    "IFRAME",
    "CANVAS",
    "VIDEO",
    "IMG",
  ]);

  const DARK_RGB = [
    [15, 26, 31],
    [15, 26, 30],
    [4, 37, 31],
    [27, 36, 41],
    [25, 27, 24],
    [34, 36, 40],
    [39, 48, 53],
    [48, 48, 48],
  ];

  function injectCss() {
    const css = `
      html {
        color-scheme: light !important;
        background: ${PAGE} !important;
        background-color: ${PAGE} !important;
        --hl-surface: ${PANEL} !important;
        --hl-surface-inset: #eef2f1 !important;
        --hl-border: ${BORDER} !important;
        --hl-divider: #1a242114 !important;
        --hl-title: ${TEXT_STRONG} !important;
        --hl-text: ${TEXT} !important;
        --hl-text-muted: ${MUTED} !important;
        --hl-text-faint: #5c686599 !important;
        --hl-accent: #0d8a78 !important;
        --hl-accent-soft: ${MINT} !important;
        --hl-accent-text: ${INK} !important;
        --hl-input-focus: ${MUTED} !important;
        --hl-error: #ed7088 !important;
        --hl-radius: 12px !important;
        --hl-radius-sm: 8px !important;
        --hl-radius-modal: 16px !important;
      }
      html, body, #root {
        background: ${PAGE} !important;
        background-color: ${PAGE} !important;
        color: ${TEXT} !important;
      }
      html:not(.hl-ready) body,
      html:not(.hl-ready) #root {
        opacity: 0 !important;
      }
      html.hl-ready body,
      html.hl-ready #root {
        opacity: 1 !important;
      }
      #tv_chart_container,
      #tv_chart_container iframe {
        background: ${PANEL} !important;
        background-color: ${PANEL} !important;
        border: none !important;
        outline: none !important;
        box-shadow: none !important;
      }
      #tv_chart_container {
        overflow: hidden !important;
      }
      ::selection {
        background: ${ACCENT_BG} !important;
        color: ${TEXT_STRONG} !important;
      }
      * { scrollbar-color: #b7c2be #e8eeec; }
      *::-webkit-scrollbar { width: 10px; height: 10px; }
      *::-webkit-scrollbar-track { background: #e8eeec; }
      *::-webkit-scrollbar-thumb { background: #b7c2be; border-radius: 8px; }

      html body [fill="#F6FEFD"], html body [fill="#f6fefd"],
      html body [fill="#D2DAD7"], html body [fill="#d2dad7"],
      html body [fill="#FFFFFF"], html body [fill="#ffffff"],
      html body [fill="white"], html body [fill="White"] {
        fill: ${TEXT_STRONG} !important;
      }
      html body [stroke="#F6FEFD"], html body [stroke="#f6fefd"],
      html body [stroke="#D2DAD7"], html body [stroke="#d2dad7"],
      html body [stroke="#FFFFFF"], html body [stroke="#ffffff"],
      html body [stroke="white"], html body [stroke="White"] {
        stroke: ${TEXT_STRONG} !important;
      }

      html body button[color="primary"],
      html body button[color=primary] {
        background-color: ${MINT} !important;
        color: ${INK} !important;
      }
      html body button[color="primary"].disabled,
      html body button[color="primary"]:disabled,
      html body button[color=primary].disabled,
      html body button[color=primary]:disabled {
        background-color: ${MINT_OFF} !important;
        color: ${MUTED} !important;
      }

      html body .pull-to-refresh-ignore:not(#tv_chart_container) > [value] {
        background-color: ${MINT} !important;
      }
      html body .pull-to-refresh-ignore:not(#tv_chart_container) .highlighted {
        background-color: ${MINT} !important;
      }
      html body .pull-to-refresh-ignore:not(#tv_chart_container) > div:first-child:not([value]) {
        background-color: ${TRACK} !important;
      }

      /* Styled-components still hardcode dark-theme hover ink / panels. */
      @media (hover: hover) {
        html body :is(a, button, [role="button"], label):not([color="primary"]):hover,
        html body :is(a, button, [role="button"], label):not([color="primary"]):focus-visible {
          color: ${TEXT_STRONG} !important;
        }
        html body :is(a, button, [role="button"]):not([color="primary"]):hover svg,
        html body :is(a, button, [role="button"]):not([color="primary"]):hover path,
        html body :is(a, button, [role="button"]):not([color="primary"]):focus-visible svg,
        html body :is(a, button, [role="button"]):not([color="primary"]):focus-visible path {
          fill: ${TEXT_STRONG} !important;
          stroke: ${TEXT_STRONG} !important;
        }
        html body button:not([color="primary"]):not(.variant_green):not(.variant_red):hover,
        html body [role="button"]:hover {
          background-color: #eef2f1 !important;
        }
        html body button[color="primary"]:hover,
        html body button[color=primary]:hover {
          background-color: ${MINT} !important;
          color: ${INK} !important;
        }
      }

      #accountTable button,
      #favoriteCoins button,
      #marketData button,
      button:has(path[d^="M5.64645"]) {
        background-color: ${PANEL} !important;
        background-image: none !important;
        box-shadow: none !important;
      }
      #accountTable button::before,
      #accountTable button::after,
      #favoriteCoins button::before,
      #favoriteCoins button::after,
      #marketData button::before,
      #marketData button::after,
      button:has(path[d^="M5.64645"])::before,
      button:has(path[d^="M5.64645"])::after {
        background: transparent !important;
        background-image: none !important;
        box-shadow: none !important;
        opacity: 0 !important;
      }
    `;
    let el = document.getElementById(STYLE_ID);
    if (!el) {
      el = document.createElement("style");
      el.id = STYLE_ID;
      const host = document.documentElement;
      host.insertBefore(el, host.firstChild);
    }
    el.textContent = css;
    const html = document.documentElement;
    html.style.setProperty("background", PAGE, "important");
    html.style.setProperty("background-color", PAGE, "important");
    html.style.setProperty("color-scheme", "light", "important");
  }

  function parseRgba(str) {
    if (!str || str === "transparent" || str === "none") return null;
    const hex = String(str).trim();
    const hm = hex.match(/^#([0-9a-f]{3,8})$/i);
    if (hm) {
      let h = hm[1];
      if (h.length === 3 || h.length === 4) h = [...h].map((c) => c + c).join("");
      const a = h.length >= 8 ? parseInt(h.slice(6, 8), 16) / 255 : 1;
      return {
        r: parseInt(h.slice(0, 2), 16),
        g: parseInt(h.slice(2, 4), 16),
        b: parseInt(h.slice(4, 6), 16),
        a,
      };
    }
    const m = String(str).match(
      /rgba?\(\s*(\d+)\s*[,/\s]\s*(\d+)\s*[,/\s]\s*(\d+)(?:\s*[,/]\s*([\d.]+%?))?\s*\)/i
    );
    if (!m) return null;
    let a = 1;
    if (m[4] !== undefined) {
      a = m[4].endsWith("%") ? parseFloat(m[4]) / 100 : +m[4];
    }
    return { r: +m[1], g: +m[2], b: +m[3], a };
  }

  function lum(c) {
    return 0.2126 * c.r + 0.7152 * c.g + 0.0722 * c.b;
  }

  function sat(c) {
    return Math.max(c.r, c.g, c.b) - Math.min(c.r, c.g, c.b);
  }

  function isBrightAccent(c) {
    if (!c || c.a < 0.35 || sat(c) < 28 || lum(c) < 90) return false;
    if (c.g >= 100 && c.g >= c.r && c.g >= c.b * 0.65 && c.r < 210) return true;
    if (c.r >= 180 && c.r > c.g + 15 && c.r > c.b) return true;
    if (c.r > 200 && c.g > 140 && c.b < 130) return true;
    return false;
  }

  function isChart(el) {
    if (!el || el.nodeType !== 1) return false;
    if (el.tagName === "IFRAME") return true;
    return !!(el.closest && el.closest("iframe"));
  }

  function skip(el) {
    if (!el || el.nodeType !== 1) return true;
    if (SKIP_TAG.has(el.tagName)) return true;
    if (isChart(el)) return true;
    return false;
  }

  function isChrome(el) {
    return (
      el === document.documentElement ||
      el === document.body ||
      el.id === "root"
    );
  }

  function sliderWrap(el) {
    const wrap = el.closest?.(".pull-to-refresh-ignore");
    if (!wrap || wrap.id === "tv_chart_container") return null;
    if (!wrap.querySelector(":scope > [value]")) return null;
    return wrap;
  }

  function paintSlider(el) {
    if (el.matches?.("button[color='primary'], button[color=primary]")) {
      const off = el.classList.contains("disabled") || el.disabled;
      el.style.setProperty("background-color", off ? MINT_OFF : MINT, "important");
      el.style.setProperty("color", off ? MUTED : INK, "important");
      return true;
    }
    const wrap = sliderWrap(el);
    if (!wrap) return false;
    if (el.classList.contains("highlighted") || /^\d/.test(el.getAttribute("value") || "")) {
      el.style.setProperty("background-color", MINT, "important");
      return true;
    }
    if (
      el.parentElement === wrap &&
      !el.hasAttribute("value") &&
      !el.querySelector(":scope > .highlighted, :scope > [value]")
    ) {
      el.style.setProperty("background-color", TRACK, "important");
      return true;
    }
    return true;
  }

  function isLightInk(value) {
    if (!value) return false;
    const s = String(value).trim().toLowerCase().replace(/\s+/g, "");
    if (LIGHT_INK.has(String(value).trim().toLowerCase()) || LIGHT_INK.has(s)) return true;
    const c = parseRgba(value);
    if (!c || c.a < 0.35 || isBrightAccent(c)) return false;
    return lum(c) >= 220 && sat(c) < 45;
  }

  function forceInk(el, attr) {
    const raw = el.getAttribute(attr);
    if (!raw || raw === "none" || raw === "currentColor") return;
    if (!isLightInk(raw)) return;
    el.setAttribute(attr, TEXT_STRONG);
    el.style.setProperty(attr, TEXT_STRONG, "important");
  }

  function fixIcons(root) {
    if (!root || root.querySelectorAll == null) return;
    const nodes = root.querySelectorAll("[fill], [stroke]");
    for (const el of nodes) {
      if (isChart(el)) continue;
      forceInk(el, "fill");
      forceInk(el, "stroke");
    }
    if (root.getAttribute) {
      forceInk(root, "fill");
      forceInk(root, "stroke");
    }
  }

  function paintInk(el, value, cssProp, effective) {
    if (isLightInk(value)) {
      el.style.setProperty(cssProp, TEXT_STRONG, "important");
      if (el.hasAttribute(cssProp) && isLightInk(el.getAttribute(cssProp))) {
        el.setAttribute(cssProp, TEXT_STRONG);
      }
      return;
    }
    const c = parseRgba(value);
    if (!c || c.a < 0.15 || isBrightAccent(c)) return;
    if (!effective || lum(effective) < 140) return;
    if (lum(c) < 170) return;
    el.style.setProperty(cssProp, TEXT_STRONG, "important");
  }

  function remapDarkImage(img) {
    let next = img
      .replace(/#0f1a1f/gi, "#ffffff")
      .replace(/#04251f/gi, "#f3f5f4")
      .replace(/#273035/gi, "#ffffff")
      .replace(/#303030/gi, PAGE)
      .replace(/#17453f/gi, MINT_OFF);
    for (const [r, g, b] of DARK_RGB) {
      const to =
        (r === 4 && g === 37) || (r === 15 && g === 26 && b === 30)
          ? "rgb(243, 245, 244)"
          : "rgb(255, 255, 255)";
      const comma = new RegExp(
        `rgba?\\(\\s*${r}\\s*,\\s*${g}\\s*,\\s*${b}(?:\\s*,\\s*[\\d.]+%?)?\\s*\\)`,
        "gi"
      );
      const space = new RegExp(
        `rgba?\\(\\s*${r}\\s+${g}\\s+${b}(?:\\s*\\/\\s*[\\d.]+%?)?\\s*\\)`,
        "gi"
      );
      next = next.replace(comma, to).replace(space, to);
    }
    return next;
  }

  function paintEl(el, inheritedBg) {
    if (skip(el)) return inheritedBg;

    const cs = getComputedStyle(el);
    const bg = parseRgba(cs.backgroundColor);
    let effective = inheritedBg;

    if (isChrome(el)) {
      el.style.setProperty("background-color", PAGE, "important");
      el.style.setProperty("background", PAGE, "important");
      el.style.setProperty("color", TEXT, "important");
      effective = parseRgba("rgb(243, 245, 244)");
    } else if (paintSlider(el)) {
      effective = inheritedBg;
    } else if (bg && bg.a >= 0.35 && !isBrightAccent(bg) && lum(bg) < 95) {
      const next = PANEL;
      el.style.setProperty("background-color", next, "important");
      if (el.id === "tv_chart_container") {
        el.style.setProperty("background", next, "important");
      }
      effective = parseRgba("rgb(255, 255, 255)");
    } else if (bg && bg.a >= 0.35) {
      effective = bg;
    }

    const img = cs.backgroundImage;
    if (img && img !== "none" && /gradient/i.test(img)) {
      const nextImg = remapDarkImage(img);
      if (nextImg !== img) {
        el.style.setProperty("background-image", nextImg, "important");
      }
    }

    const fg = parseRgba(cs.color);
    if (fg && !isBrightAccent(fg) && effective && lum(effective) >= 140) {
      if (isLightInk(cs.color) || lum(fg) >= 150) {
        el.style.setProperty(
          "color",
          lum(fg) >= 220 || fg.a < 0.85 ? TEXT_STRONG : TEXT,
          "important"
        );
      } else if (fg.r > 130 && sat(fg) < 20) {
        el.style.setProperty("color", MUTED, "important");
      }
    }

    if (!(el instanceof SVGElement)) {
      for (const side of ["Top", "Right", "Bottom", "Left"]) {
        const width = parseFloat(cs[`border${side}Width`]);
        const style = cs[`border${side}Style`];
        if (!(width > 0) || !style || style === "none") continue;
        const bc = parseRgba(cs[`border${side}Color`]);
        if (!bc || bc.a < 0.2 || isBrightAccent(bc) || lum(bc) >= 140) continue;
        if (sat(bc) > 30) continue;
        el.style.setProperty(`border-${side.toLowerCase()}-color`, BORDER, "important");
      }
    }

    if (el instanceof SVGElement) {
      paintInk(el, el.getAttribute("fill") || cs.fill, "fill", effective);
      paintInk(el, el.getAttribute("stroke") || cs.stroke, "stroke", effective);
    }

    el.setAttribute(DONE, "1");
    return effective;
  }

  let painting = false;

  function paintTree(root) {
    if (!root || root.nodeType !== 1) return;
    if (isChart(root)) return;

    const startBg = parseRgba("rgb(243, 245, 244)");
    const stack = [[root, startBg]];
    painting = true;
    try {
      while (stack.length) {
        const [el, inherited] = stack.pop();
        if (skip(el) && el !== root) continue;
        const nextBg = skip(el) ? inherited : paintEl(el, inherited);
        const kids = el.children;
        for (let i = kids.length - 1; i >= 0; i--) {
          const kid = kids[i];
          if (isChart(kid)) continue;
          stack.push([kid, nextBg]);
        }
      }
      fixIcons(root);
    } finally {
      painting = false;
    }
  }

  let ticking = false;
  let pendingRoot = null;
  let unveiled = false;

  function unveil() {
    if (unveiled) return;
    unveiled = true;
    document.documentElement.classList.add("hl-ready");
  }

  function maybeUnveil() {
    if (unveiled) return;
    const root = document.getElementById("root");
    if (root && root.childElementCount > 0) unveil();
  }

  function schedule(root) {
    const next = root && root.nodeType === 1 ? root : document.documentElement;
    if (!unveiled) {
      paintTree(document.documentElement);
      themeTradingView();
      maybeUnveil();
      return;
    }
    if (!pendingRoot) pendingRoot = next;
    else if (pendingRoot !== next) {
      if (pendingRoot.contains(next)) {
        /* keep ancestor */
      } else if (next.contains?.(pendingRoot)) pendingRoot = next;
      else pendingRoot = document.documentElement;
    }
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      ticking = false;
      const target = pendingRoot || document.documentElement;
      pendingRoot = null;
      paintTree(target);
      themeTradingView();
    });
  }

  function inheritedBgOf(el) {
    let p = el.parentElement;
    while (p) {
      if (!skip(p)) {
        const c = parseRgba(getComputedStyle(p).backgroundColor);
        if (c && c.a >= 0.35 && lum(c) >= 140) return c;
      }
      p = p.parentElement;
    }
    return parseRgba("rgb(243, 245, 244)");
  }

  function paintLive(el) {
    if (!(el instanceof Element) || skip(el)) return;
    paintEl(el, inheritedBgOf(el));
    if (el instanceof SVGElement) fixIcons(el);
    else if (el.querySelector?.("svg, [fill], [stroke]")) fixIcons(el);
  }

  const TV_FILTER = "invert(1) hue-rotate(180deg) brightness(1.03)";
  const TV_PRE_BG = "#0c0e0d";
  const TV_PRE_LINE = "#3a3f3d";

  function ensureTvCss(doc) {
    if (!doc.getElementById("hl-tv-polish")) {
      const st = doc.createElement("style");
      st.id = "hl-tv-polish";
      st.textContent = `
        html, body {
          background: ${TV_PRE_BG} !important;
          background-color: ${TV_PRE_BG} !important;
        }
        #header-toolbar,
        .layout__area--left,
        .layout__area--top,
        .layout__area--right,
        .layout__area--bottom,
        .layout__area--center,
        .chart-controls-bar,
        .chart-page,
        .chart-container {
          border-color: ${TV_PRE_LINE} !important;
          box-shadow: none !important;
          outline: none !important;
        }
        .layout__area--left {
          border-right: 1px solid ${TV_PRE_LINE} !important;
        }
        #header-toolbar {
          border-bottom: 1px solid ${TV_PRE_LINE} !important;
        }
        .paneSeparator-uqBaC1Ki,
        .screen-otjoFNF2 {
          background: ${TV_PRE_LINE} !important;
        }
      `;
      (doc.head || doc.documentElement).appendChild(st);
    }
  }

  function invertDoc(doc) {
    if (!doc || !doc.documentElement) return;
    ensureTvCss(doc);
    const html = doc.documentElement;
    html.style.setProperty("filter", TV_FILTER, "important");
    html.style.setProperty("background", TV_PRE_BG, "important");
    if (doc.body) doc.body.style.setProperty("background", TV_PRE_BG, "important");
    let frames;
    try {
      frames = doc.querySelectorAll("iframe");
    } catch (_) {
      return;
    }
    for (const f of frames) invertFrame(f);
  }

  function invertFrame(iframe) {
    if (!iframe || iframe.tagName !== "IFRAME") return;
    if (!iframe.__hlTvLoad) {
      iframe.__hlTvLoad = true;
      iframe.addEventListener("load", () => invertFrame(iframe));
    }
    let doc = null;
    try {
      doc = iframe.contentDocument;
    } catch (_) {
      doc = null;
    }
    if (doc) invertDoc(doc);
    else iframe.style.setProperty("filter", TV_FILTER, "important");
  }

  function themeTradingView() {
    const box = document.getElementById("tv_chart_container");
    if (box) {
      box.style.setProperty("background", PANEL, "important");
      box.style.setProperty("background-color", PANEL, "important");
    }
    const frames = document.querySelectorAll(
      "#tv_chart_container iframe, iframe[title='Financial Chart']"
    );
    for (const iframe of frames) invertFrame(iframe);
  }

  function watchTradingView() {
    themeTradingView();
    let n = 0;
    const id = setInterval(() => {
      themeTradingView();
      if (++n > 600) clearInterval(id);
    }, 250);
  }

  function lightColorScheme() {
    document.querySelectorAll('meta[name="color-scheme"]').forEach((m) => {
      m.setAttribute("content", "light");
    });
  }

  injectCss();
  lightColorScheme();

  document.addEventListener("pointerover", (e) => paintLive(e.target), true);
  document.addEventListener("focusin", (e) => paintLive(e.target), true);

  const mo = new MutationObserver((records) => {
    if (painting) return;
    let dirty = null;
    for (const rec of records) {
      if (rec.type === "attributes") {
        if (rec.attributeName === "fill" || rec.attributeName === "stroke") {
          forceInk(rec.target, rec.attributeName);
          continue;
        }
        dirty = rec.target;
        break;
      }
      for (const node of rec.addedNodes) {
        if (node.nodeType === 1) {
          dirty = node;
          break;
        }
      }
      if (dirty) break;
    }
    if (dirty) schedule(dirty);
  });

  mo.observe(document.documentElement, {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ["style", "class", "fill", "stroke"],
  });

  const boot = () => {
    injectCss();
    lightColorScheme();
    schedule(document.documentElement);
  };
  boot();
  document.addEventListener("DOMContentLoaded", boot, { once: true });
  window.addEventListener("load", () => {
    boot();
    unveil();
  }, { once: true });
  setTimeout(unveil, 1500);
  watchTradingView();

  console.log(LOG, "1.10.0 — no dark first paint");
})();
