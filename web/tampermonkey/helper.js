// ==UserScript==
// @name         helper
// @namespace    https://linux.do/u/f-droid
// @version      1.3
// @description  一站式ChatGPT增强工具，支持Access Token获取、服务降级检测等功能
// @license      GNU Affero General Public License v3.0 or later
// @author       F-Droid
// @match        https://chatgpt.com/*
// @match        https://new.oaifree.com/*
// @match        https://*.new.oaifree.com/*
// @match        https://shared.oaifree.com/*
// @match        https://chat.rawchat.top/*
// @match        https://chat.sharedchat.cn/*
// @match        https://gpt.github.cn.com/*
// @match        https://free.xyhelper.cn/*
// @match        https://chatgpt.dairoot.cn/*
// @icon         https://linux.do/user_avatar/linux.do/f-droid/288/228666_2.png
// @grant        GM_xmlhttpRequest
// @grant        GM_setClipboard
// @run-at       document-end
// @unsafeWindow
// @downloadURL https://update.greasyfork.org/scripts/517144/ChatGPT%20Helper.user.js
// @updateURL https://update.greasyfork.org/scripts/517144/ChatGPT%20Helper.meta.js
// ==/UserScript==

(function () {
    'use strict';
    
    const currentUrl = window.location.href;
    if (!(
        currentUrl.startsWith('https://chatgpt.com/') ||
        currentUrl.startsWith('https://new.oaifree.com/') ||
        currentUrl.startsWith('https://shared.oaifree.com/') ||
        currentUrl.startsWith('https://chat.rawchat.top/') ||
        currentUrl.startsWith('https://chat.sharedchat.cn/') ||
        currentUrl.startsWith('https://gpt.github.cn.com/') ||
        currentUrl.startsWith('https://free.xyhelper.cn/') ||
        currentUrl.startsWith('https://chatgpt.dairoot.cn/') ||
        currentUrl.match(/^https:\/\/(?:[^\/]+\.)?new\.oaifree\.com\//)
    )) {
        return;
    }

    (() => {
        const $toString = unsafeWindow.Function.toString;
        const myFunction_toString_symbol = unsafeWindow.Symbol('('.concat('', ')_', (Math.random()) + '').toString());
        const myToString = function () {
            return typeof this === 'function' && this[myFunction_toString_symbol] || $toString.call(this);
        };

        function set_native(func, key, value) {
            Object.defineProperty(func, key, {
                enumerable: false,
                configurable: true,
                writable: true,
                value: value,
            });
        }

        delete unsafeWindow.Function.prototype.toString;
        set_native(unsafeWindow.Function.prototype, 'toString', myToString);
        set_native(unsafeWindow.Function.prototype.toString, myFunction_toString_symbol, 'function toString() { [native code] }');
        globalThis.hookFix = (func, functionName) => {
            set_native(func, myFunction_toString_symbol, `function ${functionName || ''}() { [native code] }`);
        };
    }).call(this);

    const panel = document.createElement('div');
    panel.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 350px;
        background: linear-gradient(145deg, #f8f9fa, #e9ecef);
        border-radius: 15px;
        box-shadow: 0 15px 35px rgba(0,0,0,0.1), 0 5px 15px rgba(0,0,0,0.05);
        padding: 20px;
        z-index: 10001;
        font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
        color: #2c3e50;
        transition: all 0.3s ease;
        display: none;
    `;

    const titleBar = document.createElement('div');
    titleBar.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
            <h2 style="margin: 0; font-size: 18px; color: #2c3e50;">
                ChatGPT Helper
            </h2>
            <button id="close-btn" style="background: none; border: none; color: #6c757d; font-size: 20px; cursor: pointer;">×</button>
        </div>
    `;
    panel.appendChild(titleBar);

    const statusSection = document.createElement('div');
    statusSection.innerHTML = `
        <div style="background-color: #f1f3f5; border-radius: 10px; padding: 15px; margin-bottom: 0;">
            <div style="font-weight: 600;">服务降级检测</div>
            <div>PoW难度: <span id="difficulty">N/A</span> <span id="difficulty-level"></span></div>
            <div style="font-size: 12px; color: #6c757d; margin-top: 5px;">
                <em>这个值越小，代表PoW难度越高，ChatGPT认为你的IP风险越高。</em>
            </div>
            <div>IP质量: <span id="ip-quality">N/A</span></div>
            <div id="persona-container" style="display: none;">用户类型: <span id="persona">N/A</span></div>
        </div>
    `;
    panel.appendChild(statusSection);

    const tokenSection = document.createElement('div');
    tokenSection.innerHTML = `
        <div style="background-color: #f1f3f5; border-radius: 10px; padding: 15px; margin-bottom: 15px;">
            <div style="font-weight: 600; font-size: 16px; text-align: center; margin-bottom: 10px;">Access Token Tool</div>
            <div style="margin-bottom: 15px;">
                <textarea id="token-display" style="
                    width: 100%;
                    height: 100px;
                    border: 1px solid #ced4da;
                    border-radius: 8px;
                    padding: 10px;
                    resize: none;
                    font-family: monospace;
                    background-color: #f8f9fa;
                "></textarea>
            </div>
            <div style="display: flex; justify-content: center; gap: 10px;">
                <button id="fetch-btn" style="
                    flex: 1;
                    padding: 10px;
                    background-color: #2ecc71;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    cursor: pointer;
                    transition: background-color 0.3s;
                ">获取</button>
                <button id="copy-btn" style="
                    flex: 1;
                    padding: 10px;
                    background-color: #3498db;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    cursor: pointer;
                    transition: background-color 0.3s;
                ">复制</button>
            </div>
        </div>
    `;
    panel.appendChild(tokenSection);

    const createToast = (message) => {
        const toast = document.createElement('div');
        toast.innerText = message;
        toast.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: rgba(76, 175, 80, 0.9);
            color: white;
            border-radius: 8px;
            padding: 10px 20px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
            font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
            z-index: 10001;
            transition: opacity 0.5s ease;
        `;
        document.body.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => {
                document.body.removeChild(toast);
            }, 500);
        }, 1000);
    };

    const ball = document.createElement('div');

    const getFavicon = () => {
        const favicon = document.querySelector("link[rel~='icon']") ||
            document.querySelector("link[rel='shortcut icon']") ||
            document.querySelector("link[rel='icon']");

        if (favicon) {
            const faviconUrl = favicon.href;
            ball.style.backgroundImage = `url(${faviconUrl})`;
            ball.style.backgroundSize = 'cover';
            ball.style.backgroundPosition = 'center';
        } else {
            ball.style.backgroundColor = 'rgba(0, 123, 255, 0.8)';
        }
    };

    ball.style.cssText = `
        position: fixed;
        top: 25%;
        right: 20px;
        width: 40px;
        height: 40px;
        border-radius: 50%;
        cursor: pointer;
        z-index: 10000;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        transition: transform 0.2s;
    `;

    getFavicon();

    ball.addEventListener('mouseenter', () => {
        ball.style.transform = 'scale(1.1)';
    });
    ball.addEventListener('mouseleave', () => {
        ball.style.transform = 'scale(1)';
    });

    document.body.appendChild(ball);

    ball.onclick = () => {
        panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
    };

    let isDragging = false;
    let currentX;
    let currentY;
    let initialX;
    let initialY;
    let xOffset = 0;
    let yOffset = 0;
    const dragStart = (e) => {
        initialX = e.type === 'mousedown' ? e.clientX - xOffset : e.touches[0].clientX - xOffset;
        initialY = e.type === 'mousedown' ? e.clientY - yOffset : e.touches[0].clientY - yOffset;
        if (e.target === titleBar) {
            isDragging = true;
        }
    };
    const drag = (e) => {
        if (isDragging) {
            e.preventDefault();
            currentX = e.type === 'mousemove' ? e.clientX - initialX : e.touches[0].clientX - initialX;
            currentY = e.type === 'mousemove' ? e.clientY - initialY : e.touches[0].clientY - initialY;
            xOffset = currentX;
            yOffset = currentY;
            setTranslate(currentX, currentY, panel);
        }
    };
    const dragEnd = () => {
        initialX = currentX;
        initialY = currentY;
        isDragging = false;
    };
    const setTranslate = (xPos, yPos, el) => {
        el.style.transform = `translate(-50%, -50%) translate(${xPos}px, ${yPos}px)`;
    };
    titleBar.addEventListener('mousedown', dragStart);
    titleBar.addEventListener('touchstart', dragStart);
    document.addEventListener('mousemove', drag);
    document.addEventListener('touchmove', drag);
    document.addEventListener('mouseup', dragEnd);
    document.addEventListener('touchend', dragEnd);

    document.body.appendChild(panel);
    const tokenDisplay = document.getElementById('token-display');
    const closeBtn = document.getElementById('close-btn');
    const fetchBtn = document.getElementById('fetch-btn');
    const copyBtn = document.getElementById('copy-btn');

    fetchBtn.onclick = function () {
        GM_xmlhttpRequest({
            method: "GET",
            url: "/api/auth/session",
            onload: function (response) {
                try {
                    const data = JSON.parse(response.responseText);
                    tokenDisplay.value = data.accessToken || '获取失败';
                } catch (e) {
                    tokenDisplay.value = '获取失败：' + e.message;
                }
            },
            onerror: function () {
                tokenDisplay.value = '网络错误，请重试';
            }
        });
    };

    copyBtn.onclick = function () {
        if (tokenDisplay.value) {
            GM_setClipboard(tokenDisplay.value);
            createToast('Access Token已复制到剪贴板');
        }
    };

    closeBtn.onclick = function () {
        panel.style.display = 'none';
    };

    const updateDifficultyIndicator = (difficulty) => {
        const difficultyLevel = document.getElementById('difficulty-level');
        const ipQuality = document.getElementById('ip-quality');
        if (difficulty === 'N/A') {
            difficultyLevel.innerText = '';
            ipQuality.innerHTML = 'N/A';
            return;
        }
        const cleanDifficulty = difficulty.replace('0x', '').replace(/^0+/, '');
        const hexLength = cleanDifficulty.length;
        let level, qualityText, color;
        if (hexLength <= 2) {
            level = '(困难)';
            qualityText = '高风险';
            color = '#FF0000';
        } else if (hexLength === 3) {
            level = '(中等)';
            qualityText = '中等';
            color = '#FFA500';
        } else if (hexLength === 4) {
            level = '(简单)';
            qualityText = '良好';
            color = '#FFFF00';
        } else {
            level = '(极易)';
            qualityText = '优秀';
            color = '#00FF00';
        }
        difficultyLevel.innerHTML = `<span style="color: ${color}">${level}</span>`;
        ipQuality.innerHTML = `<span style="color: ${color}">${qualityText}</span>`;
    };

    function findChallengeElements() {
        const formFound = document.querySelector('form#challenge-form') !== null;

        const paragraphFound = document.querySelector('p#cf-spinner-please-wait, p#cf-spinner-redirecting') !== null;

        if (formFound && paragraphFound) {
            console.log('发现cf盾');
            return true;
        }
        return false;
    }


    if (!findChallengeElements()) {
        const originalFetch = unsafeWindow.fetch;
        const sentinelPaths = [
            '/backend-api/sentinel/chat-requirements/prepare',
            '/backend-anon/sentinel/chat-requirements/prepare',
        ];
        unsafeWindow.fetch = async function (resource, options) {
            try {
                const response = await originalFetch(resource, options);
                const url = typeof resource === 'string' ? resource : resource.url;

                if (sentinelPaths.some((path) => url.includes(path))) {
                    const data = await response.clone().json();
                    const difficulty = data.proofofwork?.difficulty || 'N/A';
                    document.getElementById('difficulty').innerText = difficulty;
                    updateDifficultyIndicator(difficulty);
                }
                return response;
            } catch (e) {
                console.error('请求拦截时出错:', e);
                return originalFetch(resource, options);
            }
        };
        hookFix(originalFetch, 'fetch');
    }

    const footer = document.createElement('div');
    footer.style.marginTop = '15px';
    footer.style.textAlign = 'center';
    footer.innerHTML = `Copyright &copy; ${new Date().getFullYear()} <a href="https://linux.do/u/f-droid" target="_blank" style="color: #007BFF; text-decoration: none;">F-Droid</a> retain all rights reserved.<br>如果您喜欢这个工具，请给作者点个赞吧！😊`;
    panel.appendChild(footer);
})();
