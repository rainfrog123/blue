// ==UserScript==
// @name         TV WS Hook
// @namespace    http://tampermonkey.net/
// @version      1.0
// @match        https://www.tradingview.com/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function() {
  const WS = window.WebSocket;
  window.WebSocket = function(url, proto) {
    const ws = new WS(url, proto);
    ws.addEventListener('message', e => {
      console.log('WS:', e.data);
      fetch('http://localhost:3000/log', {
        method: 'POST',
        body: e.data
      });
    });
    return ws;
  };
})();
