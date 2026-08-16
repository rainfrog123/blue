// ==UserScript==
// @name               Block Caixin Global Redirect
// @namespace          http://www.caixin.com/
// @version            1.0.0
// @description        Prevents caixin.com from redirecting to caixinglobal.com
// @author             User
// @match              *://*.caixin.com/*
// @grant              none
// @run-at             document-start
// ==/UserScript==

(function () {
    'use strict';

    // Fake navigator properties to appear as Chinese user
    Object.defineProperty(navigator, 'language', { get: () => 'zh-CN' });
    Object.defineProperty(navigator, 'languages', { get: () => ['zh-CN', 'zh'] });
    Object.defineProperty(navigator, 'userLanguage', { get: () => 'zh-CN' });
    Object.defineProperty(navigator, 'browserLanguage', { get: () => 'zh-CN' });
    Object.defineProperty(navigator, 'systemLanguage', { get: () => 'zh-CN' });
})();
