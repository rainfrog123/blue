// ==UserScript==
// @name               财新自动登录
// @name:en            Caixin Auto Relogin
// @namespace          http://www.caixin.com/
// @version            1.0.0
// @description        检测登录失效后自动重新登录，防止被其他设备踢下线
// @description:en     Auto re-login when session is kicked by another device
// @author             Your Name
// @match              *://*.caixin.com/*
// @grant              GM_xmlhttpRequest
// @grant              GM_getValue
// @grant              GM_setValue
// @grant              GM_addStyle
// @grant              GM_registerMenuCommand
// @connect            gateway.caixin.com
// @run-at             document-start
// @license            MIT
// ==/UserScript==

(function () {
    'use strict';

    // ==================== Configuration ====================
    const CONFIG = {
        // Credentials (encrypted password is pre-computed using AES-128-ECB)
        // To regenerate: echo -n 'YOUR_PASSWORD' | openssl enc -aes-128-ecb -K $(echo -n 'G3JH98Y8MY9GWKWG' | xxd -p) -a
        ACCOUNT: '19282708311',
        ENCRYPTED_PASSWORD: 'vKdw0DxaLEVJI%2BtTfSmRFQ%3D%3D',  // Aa@19282708311
        AREA_CODE: '+86',
        
        // Auto relogin when kicked
        AUTO_RELOGIN: true,
        
        // Debug mode
        DEBUG: false,
    };
    
    // Track our own auth token to detect if WE logged in or got kicked
    let lastKnownAuthToken = null;
    let isRelogging = false;
    
    // AES-128-ECB encryption key (from Caixin's login.js)
    const AES_KEY = 'G3JH98Y8MY9GWKWG';

    // ==================== Logging ====================
    function log(...args) {
        if (CONFIG.DEBUG) {
            const timestamp = new Date().toISOString().split('T')[1].split('.')[0];
            console.log(`[Caixin ${timestamp}]`, ...args);
        }
    }
    
    function logState(label) {
        if (CONFIG.DEBUG) {
            const currentToken = getCookie('SA_USER_auth');
            console.group(`[Caixin State] ${label}`);
            console.log('lastKnownAuthToken:', lastKnownAuthToken ? lastKnownAuthToken.substring(0, 30) + '...' : 'null');
            console.log('currentCookieToken:', currentToken ? currentToken.substring(0, 30) + '...' : 'null');
            console.log('tokensMatch:', lastKnownAuthToken === currentToken);
            console.log('isRelogging:', isRelogging);
            console.groupEnd();
        }
    }

    function notify(title, text) {
        console.log(`[Caixin Auto Relogin] ${title}: ${text}`);
    }

    // ==================== AES Encryption ====================
    // Simple AES-ECB implementation using SubtleCrypto
    async function encryptPassword(password) {
        const encoder = new TextEncoder();
        const keyData = encoder.encode(AES_KEY);
        const passwordData = encoder.encode(password);
        
        // PKCS7 padding
        const blockSize = 16;
        const padLength = blockSize - (passwordData.length % blockSize);
        const paddedData = new Uint8Array(passwordData.length + padLength);
        paddedData.set(passwordData);
        paddedData.fill(padLength, passwordData.length);
        
        // Import key
        const key = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'AES-CBC' },
            false,
            ['encrypt']
        );
        
        // AES-ECB via CBC with zero IV (process block by block)
        const zeroIV = new Uint8Array(16);
        const encryptedBlocks = [];
        
        for (let i = 0; i < paddedData.length; i += 16) {
            const block = paddedData.slice(i, i + 16);
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-CBC', iv: zeroIV },
                key,
                block
            );
            // Take only first 16 bytes (CBC adds extra block)
            encryptedBlocks.push(new Uint8Array(encrypted).slice(0, 16));
        }
        
        // Combine blocks and base64 encode
        const combined = new Uint8Array(encryptedBlocks.reduce((a, b) => a + b.length, 0));
        let offset = 0;
        for (const block of encryptedBlocks) {
            combined.set(block, offset);
            offset += block.length;
        }
        
        return btoa(String.fromCharCode(...combined));
    }

    // ==================== Cookie Management ====================
    function setCookie(name, value, days = 365) {
        const expires = new Date(Date.now() + days * 864e5).toUTCString();
        document.cookie = `${name}=${encodeURIComponent(value)}; expires=${expires}; path=/; domain=.caixin.com`;
    }

    function getCookie(name) {
        const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
        return match ? decodeURIComponent(match[2]) : null;
    }

    function deleteCookie(name) {
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; domain=.caixin.com`;
    }

    // ==================== Session Check ====================
    function checkSession() {
        log('checkSession() - calling API...');
        return new Promise((resolve) => {
            const url = `https://gateway.caixin.com/api/ucenter/userinfo/get?_t=${Date.now()}`;
            log('checkSession URL:', url);
            
            GM_xmlhttpRequest({
                method: 'GET',
                url: url,
                headers: {
                    'Accept': '*/*',
                    'Referer': 'https://u.caixin.com/',
                },
                onload: function(response) {
                    log('checkSession response status:', response.status);
                    log('checkSession response text:', response.responseText.substring(0, 200));
                    
                    try {
                        const data = JSON.parse(response.responseText);
                        if (data.code === 0) {
                            const result = { valid: true, msg: 'Session valid', data: data.data };
                            log('checkSession result:', result);
                            resolve(result);
                        } else {
                            const result = { valid: false, code: data.code, msg: data.msg };
                            log('checkSession result:', result);
                            resolve(result);
                        }
                    } catch (e) {
                        log('checkSession parse error:', e);
                        resolve({ valid: false, code: -1, msg: 'Parse error' });
                    }
                },
                onerror: function(e) {
                    log('checkSession network error:', e);
                    resolve({ valid: false, code: -1, msg: 'Network error' });
                }
            });
        });
    }

    // ==================== Login ====================
    function doLogin(account, encryptedPassword, areaCode = '+86') {
        return new Promise((resolve, reject) => {
            const callback = `__caixincallback${Date.now()}`;
            const params = new URLSearchParams({
                account: account,
                password: encryptedPassword,
                deviceType: '5',
                unit: '1',
                areaCode: areaCode,
                extend: JSON.stringify({ resource_article: '' }),
                callback: callback,
            });

            const url = `https://gateway.caixin.com/api/ucenter/user/v1/loginJsonp?${params}`;

            GM_xmlhttpRequest({
                method: 'GET',
                url: url,
                headers: {
                    'Accept': '*/*',
                    'Referer': 'https://u.caixin.com/',
                },
                onload: function(response) {
                    try {
                        // Parse JSONP response
                        const match = response.responseText.match(/__caixincallback\d+\((.*)\)/s);
                        if (!match) {
                            reject(new Error('Invalid JSONP response'));
                            return;
                        }
                        
                        const data = JSON.parse(match[1]);
                        
                        if (data.code === 0) {
                            // Set cookies from response
                            const userData = data.data;
                            const newAuthToken = userData.userAuth;
                            
                            setCookie('SA_USER_auth', newAuthToken);
                            setCookie('UID', userData.uid);
                            setCookie('SA_USER_UID', userData.uid);
                            setCookie('SA_USER_NICK_NAME', userData.nickname);
                            setCookie('SA_USER_USER_NAME', userData.mobile);
                            setCookie('SA_USER_UNIT', userData.unit || '1');
                            setCookie('SA_USER_DEVICE_TYPE', userData.deviceType || '5');
                            setCookie('USER_LOGIN_CODE', userData.code);
                            setCookie('SA_AUTH_TYPE', userData.authType || '财新网');
                            
                            // Store our own token to detect if WE got kicked vs someone else
                            lastKnownAuthToken = newAuthToken;
                            log('Stored new auth token:', newAuthToken.substring(0, 20) + '...');
                            
                            resolve(data);
                        } else {
                            reject(new Error(`Login failed: ${data.msg} (code: ${data.code})`));
                        }
                    } catch (e) {
                        reject(e);
                    }
                },
                onerror: function(e) {
                    reject(new Error('Network error'));
                }
            });
        });
    }

    // ==================== Auto Relogin Logic ====================
    async function performRelogin() {
        log('=== RELOGIN START ===');
        logState('Before relogin');
        
        if (isRelogging) {
            log('Already relogging in this tab - abort');
            return false;
        }
        
        if (!CONFIG.ACCOUNT || !CONFIG.ENCRYPTED_PASSWORD) {
            log('Credentials not configured - abort');
            return false;
        }

        isRelogging = true;
        log('Calling doLogin()...');

        try {
            const result = await doLogin(CONFIG.ACCOUNT, CONFIG.ENCRYPTED_PASSWORD, CONFIG.AREA_CODE);
            log('doLogin() returned:', result);
            notify('✓ 重新登录成功', `账号: ${CONFIG.ACCOUNT}`);
            
            logState('After successful relogin');
            log('=== RELOGIN SUCCESS ===');
            return true;
            
        } catch (e) {
            notify('✗ 重新登录失败', e.message);
            log('Re-login failed:', e.message, e);
            log('=== RELOGIN FAILED ===');
            return false;
        } finally {
            isRelogging = false;
        }
    }

    // Check session and auto-login if invalid
    async function checkAndLogin() {
        log('=== CHECK AND LOGIN ===');
        logState('Current state');
        
        // First check: is there a cookie we don't know about? (another tab may have logged in)
        const currentCookieToken = getCookie('SA_USER_auth');
        
        if (currentCookieToken && currentCookieToken !== lastKnownAuthToken) {
            log('Cookie exists but different from stored - another tab may have logged in');
            log('Updating stored token and skipping re-login');
            lastKnownAuthToken = currentCookieToken;
            // No notification - just silently use the existing session
            return true;
        }
        
        // No cookie at all - need to login
        if (!currentCookieToken) {
            log('No cookie found - need to login');
            const success = await performRelogin();
            return success;
        }
        
        // Cookie exists and matches our stored token - verify with server
        const result = await checkSession();
        log('Server result:', result);
        
        if (result.valid) {
            log('Session is valid');
            // No notification on valid session - only notify when re-logging
            return true;
        } else {
            log('Session invalid (server says no) - need to re-login');
            const success = await performRelogin();
            return success;
        }
    }

    // ==================== Suppress Alerts ====================
    // Override alert/confirm immediately to prevent any popups
    window.alert = function(message) {
        log('Alert suppressed:', message);
        // If it's a session-related alert, trigger re-login
        if (message && (message.includes('其他设备') || message.includes('登录失效') || message.includes('请先登录'))) {
            checkAndLogin();
        }
    };
    window.confirm = function() { return true; };
    log('Alerts suppressed');

    // ==================== Settings UI ====================
    function createSettingsUI() {
        const container = document.createElement('div');
        container.id = 'caixin-relogin-settings';
        container.innerHTML = `
            <style>
                #caixin-relogin-settings {
                    position: fixed;
                    top: 50%;
                    left: 50%;
                    transform: translate(-50%, -50%);
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                    z-index: 99999;
                    min-width: 350px;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                }
                #caixin-relogin-settings h3 {
                    margin: 0 0 15px 0;
                    color: #333;
                    border-bottom: 1px solid #eee;
                    padding-bottom: 10px;
                }
                #caixin-relogin-settings label {
                    display: block;
                    margin: 10px 0 5px 0;
                    color: #666;
                    font-size: 13px;
                }
                #caixin-relogin-settings input[type="text"],
                #caixin-relogin-settings input[type="password"] {
                    width: 100%;
                    padding: 8px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    box-sizing: border-box;
                }
                #caixin-relogin-settings .checkbox-row {
                    display: flex;
                    align-items: center;
                    margin: 10px 0;
                }
                #caixin-relogin-settings .checkbox-row input {
                    margin-right: 8px;
                }
                #caixin-relogin-settings .buttons {
                    margin-top: 15px;
                    display: flex;
                    gap: 10px;
                    justify-content: flex-end;
                }
                #caixin-relogin-settings button {
                    padding: 8px 16px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                }
                #caixin-relogin-settings .btn-primary {
                    background: #b5232e;
                    color: white;
                }
                #caixin-relogin-settings .btn-secondary {
                    background: #f0f0f0;
                    color: #333;
                }
                #caixin-relogin-settings .status {
                    margin-top: 10px;
                    padding: 8px;
                    border-radius: 4px;
                    font-size: 12px;
                }
                #caixin-relogin-settings .status.success { background: #d4edda; color: #155724; }
                #caixin-relogin-settings .status.error { background: #f8d7da; color: #721c24; }
                #caixin-relogin-settings .status.info { background: #cce5ff; color: #004085; }
                #caixin-relogin-settings .overlay {
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    background: rgba(0,0,0,0.5);
                    z-index: -1;
                }
            </style>
            <div class="overlay"></div>
            <h3>🔐 财新自动登录设置</h3>
            
            <label>手机号:</label>
            <input type="text" id="cxr-account" placeholder="19282708311" value="${CONFIG.ACCOUNT}">
            
            <label>密码:</label>
            <input type="password" id="cxr-password" placeholder="输入密码 (将自动加密)">
            
            <label>区号:</label>
            <input type="text" id="cxr-areacode" value="${CONFIG.AREA_CODE}">
            
            <div class="checkbox-row">
                <input type="checkbox" id="cxr-auto" ${CONFIG.AUTO_RELOGIN ? 'checked' : ''}>
                <label for="cxr-auto" style="display:inline;margin:0;">自动重新登录</label>
            </div>
            
            <div class="checkbox-row">
                <input type="checkbox" id="cxr-debug" ${CONFIG.DEBUG ? 'checked' : ''}>
                <label for="cxr-debug" style="display:inline;margin:0;">调试模式</label>
            </div>
            
            <div id="cxr-status"></div>
            
            <div class="buttons">
                <button class="btn-secondary" id="cxr-test">测试登录</button>
                <button class="btn-secondary" id="cxr-check">检查状态</button>
                <button class="btn-primary" id="cxr-save">保存</button>
                <button class="btn-secondary" id="cxr-close">关闭</button>
            </div>
        `;

        document.body.appendChild(container);

        const statusDiv = document.getElementById('cxr-status');
        
        function showStatus(msg, type = 'info') {
            statusDiv.className = `status ${type}`;
            statusDiv.textContent = msg;
        }

        // Close button
        document.getElementById('cxr-close').addEventListener('click', () => {
            container.remove();
        });
        
        // Click overlay to close
        container.querySelector('.overlay').addEventListener('click', () => {
            container.remove();
        });

        // Save button
        document.getElementById('cxr-save').addEventListener('click', async () => {
            const account = document.getElementById('cxr-account').value.trim();
            const password = document.getElementById('cxr-password').value;
            const areaCode = document.getElementById('cxr-areacode').value.trim();
            
            GM_setValue('account', account);
            GM_setValue('areaCode', areaCode);
            GM_setValue('autoRelogin', document.getElementById('cxr-auto').checked);
            GM_setValue('debug', document.getElementById('cxr-debug').checked);
            
            // Encrypt and save password if provided
            if (password) {
                try {
                    const encrypted = await encryptPassword(password);
                    GM_setValue('encryptedPassword', encodeURIComponent(encrypted));
                    showStatus('✓ 设置已保存 (密码已加密)', 'success');
                } catch (e) {
                    showStatus('✗ 密码加密失败: ' + e.message, 'error');
                    return;
                }
            } else {
                showStatus('✓ 设置已保存', 'success');
            }
            
            // Update config
            CONFIG.ACCOUNT = account;
            CONFIG.AREA_CODE = areaCode;
            CONFIG.AUTO_RELOGIN = document.getElementById('cxr-auto').checked;
            CONFIG.DEBUG = document.getElementById('cxr-debug').checked;
        });

        // Test login button
        document.getElementById('cxr-test').addEventListener('click', async () => {
            const account = document.getElementById('cxr-account').value.trim();
            const password = document.getElementById('cxr-password').value;
            const areaCode = document.getElementById('cxr-areacode').value.trim();
            
            if (!account) {
                showStatus('请输入手机号', 'error');
                return;
            }
            
            let encryptedPwd = CONFIG.ENCRYPTED_PASSWORD;
            if (password) {
                try {
                    encryptedPwd = encodeURIComponent(await encryptPassword(password));
                } catch (e) {
                    showStatus('密码加密失败', 'error');
                    return;
                }
            }
            
            if (!encryptedPwd) {
                showStatus('请输入密码或使用硬编码密码', 'error');
                return;
            }
            
            showStatus('正在登录...', 'info');
            
            try {
                const result = await doLogin(account, encryptedPwd, areaCode);
                showStatus(`✓ 登录成功: ${result.data.nickname}`, 'success');
            } catch (e) {
                showStatus(`✗ 登录失败: ${e.message}`, 'error');
            }
        });

        // Check status button
        document.getElementById('cxr-check').addEventListener('click', async () => {
            showStatus('检查中...', 'info');
            const result = await checkSession();
            if (result.valid) {
                showStatus(`✓ 已登录: ${result.data.nickname}`, 'success');
            } else {
                showStatus(`✗ 未登录: ${result.msg}`, 'error');
            }
        });
    }

    // ==================== Menu Commands ====================
    if (typeof GM_registerMenuCommand !== 'undefined') {
        GM_registerMenuCommand('⚙️ 设置', createSettingsUI);
        GM_registerMenuCommand('🔄 检查并登录', checkAndLogin);
        GM_registerMenuCommand('🔑 强制登录', performRelogin);
    }

    // ==================== Initialize ====================
    async function init() {
        console.log('========================================');
        console.log('[Caixin Auto Relogin] INITIALIZED');
        console.log('========================================');
        console.log('CONFIG:', JSON.stringify(CONFIG, null, 2));
        
        // Store current auth token on startup
        const currentToken = getCookie('SA_USER_auth');
        if (currentToken) {
            lastKnownAuthToken = currentToken;
            log('Stored initial token:', currentToken.substring(0, 30) + '...');
        } else {
            log('No existing auth token in cookies');
        }
        
        logState('After init');
        
        if (!CONFIG.ACCOUNT || !CONFIG.ENCRYPTED_PASSWORD) {
            log('WARNING: Credentials not configured!');
            return;
        }
        
        // Auto check and login on page load
        log('Checking session on page load...');
        await checkAndLogin();
        
        console.log('========================================');
    }

    // Wait for DOM
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
