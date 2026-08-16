// ==UserScript==
// @name         Gemini Copy Latest (Ctrl+C)
// @namespace    http://tampermonkey.net/
// @version      1.0.1
// @description  Ctrl+C with no selection clicks Copy on the most recent Gemini response
// @author       You
// @match        https://gemini.google.com/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(function () {
  "use strict";

  let busy = false;

  function debug(...args) {
    console.log("[Gemini Copy Latest]", ...args);
  }

  function hasTextSelection() {
    const el = document.activeElement;
    if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA")) {
      const start = el.selectionStart;
      const end = el.selectionEnd;
      if (typeof start === "number" && typeof end === "number" && start !== end) {
        return true;
      }
    }

    const sel = window.getSelection();
    if (!sel || sel.isCollapsed) return false;
    return sel.toString().length > 0;
  }

  function getLastCopyButton() {
    // New UI: <copy-button><gem-icon-button arialabel="Copy"><button aria-label="Copy">
    // data-test-id="copy-button" is gone.
    const hosts = document.querySelectorAll("copy-button");
    for (let i = hosts.length - 1; i >= 0; i--) {
      const host = hosts[i];
      const btn =
        host.querySelector("button[aria-label='Copy']") ||
        host.querySelector("button") ||
        host.querySelector("gem-icon-button");
      if (btn) return btn;
    }

    const labeled = document.querySelectorAll("button[aria-label='Copy']");
    // Skip "Copy prompt" on user queries
    for (let i = labeled.length - 1; i >= 0; i--) {
      const b = labeled[i];
      const label = (b.getAttribute("aria-label") || "").toLowerCase();
      if (label.includes("prompt")) continue;
      return b;
    }

    const icons = document.querySelectorAll(
      'mat-icon[fonticon="copy"], mat-icon[data-mat-icon-name="copy"]'
    );
    if (icons.length) {
      const btn = icons[icons.length - 1].closest("button");
      if (btn) return btn;
    }

    return null;
  }

  function clickLatestCopy() {
    if (busy) {
      debug("busy, skip");
      return;
    }
    busy = true;
    try {
      const btn = getLastCopyButton();
      if (!btn) {
        debug("no Copy button found");
        return;
      }
      debug("clicking latest Copy", btn);
      btn.click();
    } catch (e) {
      debug("error", e);
    } finally {
      setTimeout(() => {
        busy = false;
      }, 300);
    }
  }

  document.addEventListener(
    "keydown",
    (e) => {
      if (!(e.key === "c" || e.key === "C")) return;
      if (!e.ctrlKey || e.altKey || e.metaKey || e.shiftKey) return;
      if (hasTextSelection()) {
        debug("selection present — native copy");
        return;
      }

      e.preventDefault();
      e.stopPropagation();
      clickLatestCopy();
    },
    true
  );

  debug("loaded — Ctrl+C (no selection) copies latest response");
})();
