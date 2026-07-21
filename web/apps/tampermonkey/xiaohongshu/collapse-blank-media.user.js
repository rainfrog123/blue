// ==UserScript==
// @name         XHS Collapse Blank Media Stage
// @namespace    https://github.com/jar71/blue
// @version      1.2.0
// @description  Shrink the oversized note media stage so letterbox bars collapse and comments move up.
// @author       jar71
// @match        *://www.xiaohongshu.com/*
// @match        *://xiaohongshu.com/*
// @run-at       document-end
// @grant        none
// ==/UserScript==

(() => {
  "use strict";

  const NOTE_RE = /\/(?:explore|search_result|discovery)\/[0-9a-f]{16,}/i;
  const ATTR = "data-xhs-tight";
  const STYLE_ID = "xhs-collapse-blank-media-style";
  const PAD = 8;
  const MIN_STAGE_H = 280;
  const MAX_MEDIA_VH = 0.85;

  /** Shells that actually form the note media stage (not comments). */
  const STAGE_SELECTORS = [
    "#noteContainer .media-container",
    "#noteContainer [class*='media-container']",
    ".note-container .media-container",
    ".note-detail-mask .media-container",
    "[class*='note-container'] .media-container",
  ];

  const INNER_SHELL_SELECTORS = [
    ".xhs-slider-container",
    ".swiper",
    ".swiper-wrapper",
    ".swiper-slide",
    ".img-container",
    "[class*='note-slider']",
    "[class*='player']",
  ];

  let scheduled = false;
  let lastKey = "";

  function isNotePage() {
    return NOTE_RE.test(location.pathname);
  }

  function ensureStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = `
      html[${ATTR}-page="1"] [${ATTR}="1"] {
        height: var(--xhs-tight-h, auto) !important;
        max-height: var(--xhs-tight-h, none) !important;
        min-height: 0 !important;
        aspect-ratio: auto !important;
        flex: 0 0 auto !important;
      }

      html[${ATTR}-page="1"] [${ATTR}="1"] img,
      html[${ATTR}-page="1"] [${ATTR}="1"] video {
        max-height: min(85vh, 100%) !important;
        width: auto !important;
        max-width: 100% !important;
        height: auto !important;
        object-fit: contain !important;
        display: block !important;
        margin: 0 auto !important;
        position: relative !important;
        inset: auto !important;
        top: auto !important;
        left: auto !important;
        right: auto !important;
        bottom: auto !important;
      }

      /* Keep absolute fill from forcing the stage tall again */
      html[${ATTR}-page="1"] [${ATTR}="1"] [class*="note-slider"],
      html[${ATTR}-page="1"] [${ATTR}="1"] .img-container,
      html[${ATTR}-page="1"] [${ATTR}="1"] .swiper-slide {
        height: 100% !important;
        min-height: 0 !important;
      }
    `;
    document.documentElement.appendChild(style);
  }

  function clearTight(root = document) {
    root.querySelectorAll(`[${ATTR}="1"]`).forEach((el) => {
      el.removeAttribute(ATTR);
      el.style.removeProperty("--xhs-tight-h");
      el.style.removeProperty("height");
      el.style.removeProperty("max-height");
      el.style.removeProperty("min-height");
    });
  }

  /**
   * Visual size of an image/video under object-fit: contain inside a box of
   * known width. Absolute-fill imgs report stage-sized getBoundingClientRect,
   * so natural dimensions are required.
   */
  function visualMediaSize(media, stageWidth) {
    let nw = 0;
    let nh = 0;
    if (media instanceof HTMLImageElement) {
      nw = media.naturalWidth;
      nh = media.naturalHeight;
    } else if (media instanceof HTMLVideoElement) {
      nw = media.videoWidth;
      nh = media.videoHeight;
    }
    if (!(nw > 0 && nh > 0 && stageWidth > 0)) return null;

    const fittedH = (stageWidth * nh) / nw;
    const maxH = window.innerHeight * MAX_MEDIA_VH;
    const h = Math.min(fittedH, maxH);
    const w = (h * nw) / nh;
    return { width: w, height: h, naturalWidth: nw, naturalHeight: nh };
  }

  function pickPrimaryMedia(stage) {
    const active =
      stage.querySelector(".swiper-slide-active img, .swiper-slide-active video") ||
      stage.querySelector(".swiper-slide-visible img, .swiper-slide-visible video");
    if (active) return active;

    const candidates = [...stage.querySelectorAll("img, video")].filter((el) => {
      if (el.closest(".author, .avatar, .comment-item, .interactions")) return false;
      if (el instanceof HTMLImageElement) {
        return el.naturalWidth > 80 && el.naturalHeight > 80;
      }
      if (el instanceof HTMLVideoElement) {
        return el.videoWidth > 80 && el.videoHeight > 80;
      }
      return false;
    });
    if (!candidates.length) return null;

    // Prefer the largest natural area (main cover over icons).
    candidates.sort((a, b) => {
      const aa =
        (a.naturalWidth || a.videoWidth || 0) * (a.naturalHeight || a.videoHeight || 0);
      const bb =
        (b.naturalWidth || b.videoWidth || 0) * (b.naturalHeight || b.videoHeight || 0);
      return bb - aa;
    });
    return candidates[0];
  }

  function findStages() {
    const found = new Set();
    for (const sel of STAGE_SELECTORS) {
      document.querySelectorAll(sel).forEach((el) => {
        if (!(el instanceof HTMLElement)) return;
        // Skip tiny / non-visible shells
        const r = el.getBoundingClientRect();
        if (r.width < 200 || r.height < 120) return;
        found.add(el);
      });
    }
    return [...found];
  }

  function applyTight(stage, targetH) {
    const h = Math.max(1, Math.ceil(targetH));
    stage.setAttribute(ATTR, "1");
    stage.style.setProperty("--xhs-tight-h", `${h}px`);
    // Inline override beats XHS's own style="height: calc(133.333vw)"
    stage.style.setProperty("height", `${h}px`, "important");
    stage.style.setProperty("max-height", `${h}px`, "important");
    stage.style.setProperty("min-height", "0", "important");

    for (const sel of INNER_SHELL_SELECTORS) {
      stage.querySelectorAll(sel).forEach((el) => {
        if (!(el instanceof HTMLElement)) return;
        el.setAttribute(ATTR, "1");
        el.style.setProperty("--xhs-tight-h", `${h}px`);
        el.style.setProperty("height", `${h}px`, "important");
        el.style.setProperty("max-height", `${h}px`, "important");
        el.style.setProperty("min-height", "0", "important");
      });
    }
  }

  function tighten() {
    ensureStyle();

    if (!isNotePage()) {
      document.documentElement.removeAttribute("data-xhs-note");
      document.documentElement.removeAttribute(`${ATTR}-page`);
      clearTight();
      lastKey = "";
      return;
    }

    document.documentElement.setAttribute("data-xhs-note", "1");
    document.documentElement.setAttribute(`${ATTR}-page`, "1");

    const stages = findStages();
    if (!stages.length) return;

    const parts = [];
    for (const stage of stages) {
      const stageRect = stage.getBoundingClientRect();
      const media = pickPrimaryMedia(stage);
      if (!media) continue;

      const visual = visualMediaSize(media, stageRect.width);
      if (!visual) continue;

      const targetH = Math.ceil(visual.height + PAD);
      // Only collapse when the stage is meaningfully taller than the media.
      if (stageRect.height < MIN_STAGE_H) continue;
      if (stageRect.height - targetH < 48) continue;
      if (targetH / stageRect.height > 0.92) continue;

      applyTight(stage, targetH);
      parts.push(`${Math.round(stageRect.width)}x${targetH}`);
    }

    const key = `${location.pathname}|${parts.join(",")}`;
    if (key !== lastKey) {
      lastKey = key;
      // Nudge layout after height change (swiper / sticky panels).
      window.dispatchEvent(new Event("resize"));
    }
  }

  function schedule() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      try {
        tighten();
      } catch (err) {
        console.warn("[xhs-collapse-blank-media]", err);
      }
    });
  }

  const mo = new MutationObserver(schedule);
  mo.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["style", "class", "src"],
  });

  window.addEventListener("popstate", schedule);
  window.addEventListener("resize", schedule);
  window.addEventListener("load", schedule);
  document.addEventListener(
    "load",
    (e) => {
      if (e.target instanceof HTMLImageElement || e.target instanceof HTMLVideoElement) {
        schedule();
      }
    },
    true
  );

  const wrapHistory = (method) => {
    const original = history[method];
    history[method] = function (...args) {
      const ret = original.apply(this, args);
      schedule();
      return ret;
    };
  };
  wrapHistory("pushState");
  wrapHistory("replaceState");

  schedule();
  setTimeout(schedule, 300);
  setTimeout(schedule, 1000);
  setTimeout(schedule, 2500);
})();
