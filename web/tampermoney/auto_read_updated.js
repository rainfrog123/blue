// ==UserScript==
// @name         auto-read
// @description  Auto-clicks the Read Aloud (朗读) button after each new assistant answer
// @match        https://chat.openai.com/*
// @match        https://chatgpt.com/*
// @match        https://www.chatgpt.com/*
// @grant        none
// ==/UserScript==

(function () {
  'use strict';

  let enabled = true;
  let lastProcessedId = null;
  let processing = false;

  const sleep = ms => new Promise(r => setTimeout(r, ms));

  // Toggle with Ctrl+Alt+V
  window.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.altKey && e.key.toLowerCase() === 'v') {
      enabled = !enabled;
      console.log(`[auto-read] ${enabled ? 'ENABLED' : 'DISABLED'}`);
      e.preventDefault();
    }
  });

  // Disable when scrolling up (user browsing history)
  let lastScrollY = window.scrollY;
  window.addEventListener('scroll', () => {
    if (window.scrollY < lastScrollY - 100) {
      enabled = false;
    }
    lastScrollY = window.scrollY;
  }, { passive: true });

  // Find the latest assistant message container
  function getLatestAssistantMessage() {
    const messages = Array.from(document.querySelectorAll('[data-message-author-role="assistant"]'));
    return messages.at(-1);
  }

  // Click read aloud for a specific message
  async function clickReadAloudForMessage(messageEl) {
    if (!messageEl || processing) return false;
    
    // Get or create message ID
    const msgId = messageEl.dataset.messageId || 
                 (messageEl.dataset._autoId = String(Date.now() + Math.random()));
    
    if (msgId === lastProcessedId) return false;

    processing = true;
    try {
      // Find More actions button within this message
      const moreBtn = messageEl.querySelector('button[aria-label="More actions"], button[id^="radix-"][aria-haspopup="menu"]');
      if (!moreBtn) return false;

      // Simple click - no complex pointer simulation
      moreBtn.click();
      lastProcessedId = msgId;

      // Wait for menu
      let menu = null;
      for (let i = 0; i < 40; i++) { // 2 second timeout
        menu = document.querySelector('[role="menu"][data-state="open"]');
        if (menu) break;
        await sleep(50);
      }
      
      if (!menu) return false;

      // Find read aloud item
      let readItem = menu.querySelector('[role="menuitem"][aria-label="Read aloud"]') ||
                     menu.querySelector('[data-testid="voice-play-turn-action-button"]');

      if (!readItem) {
        const items = menu.querySelectorAll('[role="menuitem"]');
        readItem = Array.from(items).find(el => /read\s*aloud/i.test(el.textContent));
      }

      if (readItem) {
        readItem.click();
        return true;
      }
    } catch (e) {
      console.warn('[auto-read] Error:', e);
    } finally {
      processing = false;
    }
    return false;
  }

  // Check once for new message
  async function checkOnce() {
    if (!enabled || processing) return;
    
    const latest = getLatestAssistantMessage();
    if (latest) {
      await clickReadAloudForMessage(latest);
    }
  }

  // Targeted observer - only for assistant messages
  const observer = new MutationObserver((mutations) => {
    if (!enabled) return;
    
    let hasNewAssistantContent = false;
    for (const mut of mutations) {
      for (const node of mut.addedNodes) {
        if (node.nodeType === 1) {
          // Check if this is or contains an assistant message
          if (node.matches?.('[data-message-author-role="assistant"]') ||
              node.querySelector?.('[data-message-author-role="assistant"]')) {
            hasNewAssistantContent = true;
            break;
          }
        }
      }
      if (hasNewAssistantContent) break;
    }

    if (hasNewAssistantContent) {
      setTimeout(checkOnce, 500); // Debounce
    }
  });

  // Start observing
  observer.observe(document.body, { childList: true, subtree: true });

  // Initial check
  setTimeout(checkOnce, 1000);

  // Cleanup on page unload
  window.addEventListener('beforeunload', () => observer.disconnect());
})();
