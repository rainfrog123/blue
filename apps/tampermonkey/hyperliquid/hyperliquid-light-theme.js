// ==UserScript==
// @name         Hyperliquid Light Theme
// @namespace    http://tampermonkey.net/
// @version      1.8.0
// @description  Light chrome + TV invert. Restores leverage slider / primary buttons.
// @author       You
// @match        https://app.hyperliquid.xyz/*
// @match        https://app.hyperliquid.com/*
// @grant        GM_addStyle
// @run-at       document-start
// ==/UserScript==

/*
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

  const LIGHT_INK = new Set([
    "#f6fefd",
    "#d2dad7",
    "#ffffff",
    "#fff",
    "white",
    "rgb(246, 254, 253)",
    "rgb(210, 218, 215)",
    "rgb(255, 255, 255)",
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

  function injectCss() {
    const css = `
      html {
        color-scheme: light !important;
        --hl-surface: ${PANEL};
        --hl-surface-inset: #eef2f1;
        --hl-border: ${BORDER};
        --hl-divider: #1a242114;
        --hl-title: ${TEXT_STRONG};
        --hl-text: ${TEXT};
        --hl-text-muted: ${MUTED};
        --hl-text-faint: #5c686599;
        --hl-accent: #0d8a78;
        --hl-accent-soft: #50d2c1;
        --hl-accent-text: #04120f;
        --hl-input-focus: ${MUTED};
        --hl-error: #ed7088;
      }
      html, body, #root {
        background: ${PAGE} !important;
        background-color: ${PAGE} !important;
        color: ${TEXT} !important;
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

      /* Tab scroller chevron: dark linear-gradient fade on the edge. */
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
    if (typeof GM_addStyle === "function") GM_addStyle(css);
    else {
      const el = document.createElement("style");
      el.id = STYLE_ID;
      el.textContent = css;
      (document.head || document.documentElement).appendChild(el);
    }
  }

  function parseRgba(str) {
    if (!str || str === "transparent" || str === "none") return null;
    const hex = String(str).trim();
    const hm = hex.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
    if (hm) {
      let h = hm[1];
      if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
      return {
        r: parseInt(h.slice(0, 2), 16),
        g: parseInt(h.slice(2, 4), 16),
        b: parseInt(h.slice(4, 6), 16),
        a: 1,
      };
    }
    const m = str.match(
      /rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)(?:\s*,\s*([\d.]+))?\s*\)/i
    );
    if (!m) return null;
    return {
      r: +m[1],
      g: +m[2],
      b: +m[3],
      a: m[4] === undefined ? 1 : +m[4],
    };
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
    if (el.matches?.("button[color='primary']")) {
      const off = el.classList.contains("disabled") || el.disabled;
      el.style.setProperty("background-color", off ? "#c5ebe3" : "#50d2c1", "important");
      el.style.setProperty("color", off ? MUTED : "#04120f", "important");
      return true;
    }
    const wrap = sliderWrap(el);
    if (!wrap) return false;
    if (el.classList.contains("highlighted") || /^\d/.test(el.getAttribute("value") || "")) {
      el.style.setProperty("background-color", "#50d2c1", "important");
      return true;
    }
    if (el.parentElement === wrap && !el.hasAttribute("value") && !el.querySelector(":scope > .highlighted, :scope > [value]")) {
      el.style.setProperty("background-color", "#e4eae8", "important");
      return true;
    }
    return true;
  }

  function isLightInk(value) {
    if (!value) return false;
    return LIGHT_INK.has(String(value).trim().toLowerCase());
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

  function paintEl(el, inheritedBg) {
    if (skip(el)) return inheritedBg;

    const cs = getComputedStyle(el);
    const bg = parseRgba(cs.backgroundColor);
    let effective = inheritedBg;

    if (paintSlider(el)) {
      effective = inheritedBg;
    } else if (bg && bg.a >= 0.35 && !isBrightAccent(bg) && lum(bg) < 95) {
      const next = isChrome(el) || el.id === "tv_chart_container" ? (isChrome(el) ? PAGE : PANEL) : PANEL;
      el.style.setProperty("background-color", next, "important");
      if (el.id === "tv_chart_container") {
        el.style.setProperty("background", next, "important");
      }
      effective = parseRgba(
        next === PAGE ? "rgb(243, 245, 244)" : "rgb(255, 255, 255)"
      );
    } else if (bg && bg.a >= 0.35) {
      effective = bg;
    }

    const img = cs.backgroundImage;
    if (img && img !== "none" && /gradient/i.test(img)) {
      const nextImg = img
        .replace(/rgb\(\s*15\s*,\s*26\s*,\s*31\s*\)/gi, "rgb(255, 255, 255)")
        .replace(/rgb\(\s*4\s*,\s*37\s*,\s*31\s*\)/gi, "rgb(243, 245, 244)")
        .replace(/rgb\(\s*27\s*,\s*36\s*,\s*41\s*\)/gi, "rgb(255, 255, 255)")
        .replace(/#0f1a1f/gi, "#ffffff")
        .replace(/#04251f/gi, "#f3f5f4")
        .replace(/#273035/gi, "#ffffff");
      if (nextImg !== img) {
        el.style.setProperty("background-image", nextImg, "important");
      }
    }

    const fg = parseRgba(cs.color);
    if (fg && !isBrightAccent(fg) && effective && lum(effective) >= 140) {
      if (lum(fg) >= 150) {
        el.style.setProperty(
          "color",
          lum(fg) >= 220 ? TEXT_STRONG : TEXT,
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

  function paintTree(root) {
    if (!root || root.nodeType !== 1) return;
    if (isChart(root)) return;

    const startBg = parseRgba("rgb(243, 245, 244)");
    const stack = [[root, startBg]];

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
  }

  let ticking = false;
  let pendingRoot = null;

  function schedule(root) {
    pendingRoot = root || document.documentElement;
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
  watchTradingView();

  const boot = () => {
    lightColorScheme();
    schedule(document.documentElement);
  };
  if (document.documentElement) boot();
  document.addEventListener("DOMContentLoaded", boot, { once: true });
  window.addEventListener("load", boot, { once: true });

  const mo = new MutationObserver((records) => {
    let dirty = false;
    for (const rec of records) {
      if (rec.type === "attributes") {
        if (rec.attributeName === "fill" || rec.attributeName === "stroke") {
          forceInk(rec.target, rec.attributeName);
          continue;
        }
        if (rec.target?.getAttribute?.(DONE) === "1" && rec.attributeName === "style") {
          continue;
        }
        dirty = true;
        break;
      }
      for (const node of rec.addedNodes) {
        if (node.nodeType === 1) {
          dirty = true;
          break;
        }
      }
      if (dirty) break;
    }
    if (dirty) schedule(document.documentElement);
  });

  mo.observe(document.documentElement, {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ["style", "class", "fill", "stroke"],
  });

  console.log(LOG, "1.8.0 — restore leverage slider");
})();
