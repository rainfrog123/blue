// ==UserScript==
// @name         Xiaohongshu (Ctrl+Click New Tab)
// @namespace    http://tampermonkey.net/
// @version      1.0.2
// @description  Open Xiaohongshu links in a new tab with Ctrl+Click
// @author       You
// @match        https://www.xiaohongshu.com/*
// @match        *://www.xiaohongshu.com/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

/*
 * Live script (from repo / TM backup 2026-08-08).
 * Source snapshot: archive/ctrl-click-new-tab.user.js.bak
 *
 * Unused (disabled in TM backup):
 *   - archive/collapse-blank-media.user.js.bak  (XHS Collapse Blank Media Stage)
 */

(function () {
  'use strict';

  const NOTE_HREF =
    /\/(?:explore|search_result|discovery|user\/[^/]+\/)?[0-9a-f]{16,}/i;

  function isModifiedOpen(e) {
    // Ctrl/Cmd/Shift+left click, or middle click (button 1 / auxclick)
    return (
      e.ctrlKey ||
      e.metaKey ||
      e.shiftKey ||
      e.button === 1 ||
      e.type === 'auxclick'
    );
  }

  function findNoteAnchor(target) {
    if (!(target instanceof Element)) return null;
    const a = target.closest('a[href]');
    if (!a) return null;
    const href = a.getAttribute('href') || '';
    if (!NOTE_HREF.test(href) && !NOTE_HREF.test(a.href || '')) return null;
    // Skip pure external / footer legal links
    if (/^https?:\/\//i.test(href) && !href.includes('xiaohongshu.com')) {
      return null;
    }
    return a;
  }

  function openInNewTab(a, e) {
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
    const url = a.href || a.getAttribute('href');
    if (!url) return;
    window.open(url, '_blank', 'noopener,noreferrer');
  }

  function onPointerOpen(e) {
    if (!isModifiedOpen(e)) return;
    // Ignore non-primary auxclick buttons other than middle
    if (e.type === 'auxclick' && e.button !== 1) return;
    const a = findNoteAnchor(e.target);
    if (!a) return;
    openInNewTab(a, e);
  }

  // Capture phase + document-start so we run before XHS Vue handlers
  document.addEventListener('click', onPointerOpen, true);
  document.addEventListener('auxclick', onPointerOpen, true);
})();
