// ==UserScript==
// @name         Xiaomi Router (Auto Login)
// @namespace    http://tampermonkey.net/
// @version      2.0.2
// @description  Auto-login to Xiaomi router LuCI web UI
// @author       You
// @match        http://192.168.31.1/cgi-bin/luci/web
// @match        http://192.168.31.1/cgi-bin/luci/web*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

/*
 * From TM backup 2026-08-08 (enabled).
 * Snapshot: archive/xiaomi-router-auto-login.user.js.bak
 */

(function() {
    'use strict';

    const PASSWORD = 'jingxian';
    const extractStokFromUrl = () => {
        const match = window.location.href.match(/;stok=([a-f0-9]+)/i);
        return match ? match[1] : null;
    };

    const autoLogin = () => {
        const passwordInput = document.getElementById('password');
        const loginBtn = document.getElementById('btnRtSubmit');

        if (!passwordInput || !loginBtn) {
            console.log('[Xiaomi Router] Login form not found, retrying...');
            setTimeout(autoLogin, 500);
            return;
        }

        if (passwordInput.value) {
            console.log('[Xiaomi Router] Password already filled, skipping auto-login.');
            return;
        }

        console.log('[Xiaomi Router] Auto-filling password and logging in...');

        passwordInput.value = PASSWORD;
        passwordInput.dispatchEvent(new Event('input', { bubbles: true }));
        passwordInput.dispatchEvent(new Event('change', { bubbles: true }));

        setTimeout(() => {
            loginBtn.click();
            console.log('[Xiaomi Router] Login submitted!');
        }, 300);
    };

    const stok = extractStokFromUrl();

    if (stok) {
        console.log('[Xiaomi Router] Logged in, stok:', stok);

        // Remove upgrade notice bar
        const noticebar = document.getElementById('noticebar');
        if (noticebar) {
            noticebar.remove();
            console.log('[Xiaomi Router] Removed upgrade notice.');
        }

        // Keep session alive - ping every 2 minutes
        const keepAlive = () => {
            fetch(`/cgi-bin/luci/;stok=${stok}/api/misystem/status`, { method: 'GET' })
                .then(() => console.log('[Xiaomi Router] Session kept alive.'))
                .catch(() => console.log('[Xiaomi Router] Keep-alive failed, session may have expired.'));
        };
        setInterval(keepAlive, 2 * 60 * 1000);

        // Only redirect to WAN from home page (after login), not from other pages
        if (window.location.pathname.includes('/web/home')) {
            const wanUrl = `http://192.168.31.1/cgi-bin/luci/;stok=${stok}/web/setting/wan`;
            console.log('[Xiaomi Router] Redirecting to WAN settings...');
            window.location.href = wanUrl;
        }
    } else if (window.location.pathname === '/cgi-bin/luci/web') {
        console.log('[Xiaomi Router] On login page, auto-logging in...');
        autoLogin();
    }
})();
