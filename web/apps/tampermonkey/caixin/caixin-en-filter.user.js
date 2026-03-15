// ==UserScript==
// @name         Caixin EN Articles Filter
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Only show Caixin articles that have an English version on Caixin Global
// @author       You
// @match        https://www.caixin.com/*
// @match        https://weekly.caixin.com/*
// @match        https://finance.caixin.com/*
// @match        https://economy.caixin.com/*
// @match        https://companies.caixin.com/*
// @match        https://china.caixin.com/*
// @match        https://international.caixin.com/*
// @match        https://opinion.caixin.com/*
// @match        https://science.caixin.com/*
// @grant        GM_addStyle
// @run-at       document-end
// ==/UserScript==

(function() {
    'use strict';

    const EN_ICON_SELECTOR = 'img[src*="icon_en02.png"]';
    const EN_LINK_SELECTOR = 'a[href*="caixinglobal.com"]';

    function hasEnglishVersion(element) {
        return element.querySelector(EN_ICON_SELECTOR) !== null ||
               element.querySelector(EN_LINK_SELECTOR) !== null;
    }

    function filterArticles() {
        // Main news list articles (dl elements)
        document.querySelectorAll('.news_list > dl').forEach(dl => {
            if (!hasEnglishVersion(dl)) {
                dl.style.display = 'none';
            }
        });

        // Photo galleries (news_img_box)
        document.querySelectorAll('.news_list .news_img_box').forEach(box => {
            if (!hasEnglishVersion(box)) {
                box.style.display = 'none';
            }
        });

        // Headline section (toutiao_box) - individual articles
        document.querySelectorAll('.toutiao_box .demolNews dl').forEach(dl => {
            if (!hasEnglishVersion(dl)) {
                dl.style.display = 'none';
            }
        });

        // Image list box (img_list_box)
        document.querySelectorAll('.img_list_box li').forEach(li => {
            if (!hasEnglishVersion(li)) {
                li.style.display = 'none';
            }
        });

        // Scrolling news ticker
        document.querySelectorAll('.scrollnews li').forEach(li => {
            if (!hasEnglishVersion(li)) {
                li.style.display = 'none';
            }
        });
    }

    function observeAndFilter() {
        filterArticles();

        // Observe for dynamically loaded content (infinite scroll, etc.)
        const observer = new MutationObserver((mutations) => {
            let shouldFilter = false;
            for (const mutation of mutations) {
                if (mutation.addedNodes.length > 0) {
                    shouldFilter = true;
                    break;
                }
            }
            if (shouldFilter) {
                filterArticles();
            }
        });

        const newsContainer = document.querySelector('.news_list');
        if (newsContainer) {
            observer.observe(newsContainer, { childList: true, subtree: true });
        }

        const mainContent = document.querySelector('.main_con');
        if (mainContent) {
            observer.observe(mainContent, { childList: true, subtree: true });
        }
    }

    // Add indicator showing filter is active
    GM_addStyle(`
        .en-filter-badge {
            position: fixed;
            top: 10px;
            right: 10px;
            background: #1f286f;
            color: white;
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 12px;
            z-index: 10000;
            font-family: Arial, sans-serif;
        }
    `);

    function addFilterBadge() {
        const badge = document.createElement('div');
        badge.className = 'en-filter-badge';
        badge.textContent = 'EN Only';
        document.body.appendChild(badge);
    }

    // Run when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            observeAndFilter();
            addFilterBadge();
        });
    } else {
        observeAndFilter();
        addFilterBadge();
    }
})();
