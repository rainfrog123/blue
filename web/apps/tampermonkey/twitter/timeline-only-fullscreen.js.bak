// ==UserScript==
// @name         Twitter Timeline Only
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Show only the timeline, hide all other UI elements
// @author       You
// @match        https://twitter.com/*
// @match        https://x.com/*
// @grant        GM_addStyle
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    const css = `
        /* Hide the left sidebar/header navigation by default */
        header[role="banner"] {
            display: none !important;
        }

        /* Show sidebar when toggled */
        header[role="banner"].show-sidebar {
            display: flex !important;
            position: fixed !important;
            left: 0 !important;
            top: 0 !important;
            height: 100vh !important;
            width: 275px !important;
            z-index: 9998 !important;
            background-color: var(--background-color-primary, #fff) !important;
            box-shadow: 2px 0 10px rgba(0, 0, 0, 0.1) !important;
        }

        /* Shift main content when sidebar is open */
        body.sidebar-open main[role="main"] {
            margin-left: 275px !important;
        }

        /* Hide the right sidebar (trends, who to follow, premium, etc.) */
        [data-testid="sidebarColumn"] {
            display: none !important;
        }

        /* Hide Grok drawer */
        [data-testid="GrokDrawer"] {
            display: none !important;
        }

        /* Hide chat drawer */
        [data-testid="chat-drawer-root"] {
            display: none !important;
        }

        /* Hide the "What's happening" composer at the top of timeline */
        [data-testid="tweetTextarea_0_label"] {
            display: none !important;
        }

        /* Hide the composer box container */
        [data-testid="primaryColumn"] > div > div:first-child > div:nth-child(3) {
            display: none !important;
        }

        /* Make the main content full width */
        main[role="main"] {
            margin-left: 0 !important;
            max-width: 100% !important;
            width: 100% !important;
        }

        /* Expand the primary column to full width */
        [data-testid="primaryColumn"] {
            max-width: 100% !important;
            width: 100% !important;
            margin: 0 !important;
            border: none !important;
        }

        /* Override Twitter's internal width constraints on nested containers */
        [data-testid="primaryColumn"] > div > div,
        [data-testid="primaryColumn"] > div > div > div,
        [data-testid="primaryColumn"] section > div > div {
            max-width: 100% !important;
        }

        /* Force all parent containers to be full width */
        #react-root > div,
        #react-root > div > div,
        #react-root > div > div > div,
        #react-root > div > div > div > div {
            max-width: 100% !important;
            width: 100% !important;
        }

        /* Remove the empty sidebar space */
        main[role="main"] > div {
            max-width: 100% !important;
            width: 100% !important;
            justify-content: flex-start !important;
        }

        /* Override all max-width on common Twitter container classes */
        main[role="main"] div[class*="r-"] {
            max-width: 100% !important;
        }

        /* Force primaryColumn parent wrappers to full width */
        [data-testid="primaryColumn"],
        [data-testid="primaryColumn"] > div,
        [data-testid="primaryColumn"] > div > div,
        [data-testid="primaryColumn"] > div > div > div,
        [data-testid="primaryColumn"] > div > div > div > div {
            max-width: 100% !important;
            width: 100% !important;
        }

        /* Make timeline section fill available space */
        section[role="region"] {
            max-width: 100% !important;
        }

        /* Expand tweet articles to full width */
        article[data-testid="tweet"] {
            max-width: 100% !important;
            width: 100% !important;
        }

        /* Make all tweet cell wrappers full width */
        [data-testid="cellInnerDiv"] {
            max-width: 100% !important;
            width: 100% !important;
        }

        /* Expand the tweet text content area */
        [data-testid="tweetText"] {
            max-width: 100% !important;
        }

        /* Make media (images/videos) in tweets wider */
        [data-testid="tweetPhoto"],
        [data-testid="videoPlayer"],
        [data-testid="card.wrapper"] {
            max-width: 100% !important;
        }

        /* Timeline container full width - home, profile, and individual pages */
        [aria-label="Timeline: Your Home Timeline"],
        [aria-label="Timeline: Trending now"],
        [aria-label^="Timeline:"],
        [aria-label="Section details"],
        [data-testid="tweet"] [data-testid="User-Name"],
        section[role="region"] > div {
            max-width: 100% !important;
            width: 100% !important;
        }

        /* Individual tweet/status page - expand conversation thread */
        [aria-label^="Timeline: Conversation"],
        [data-testid="tweet-reply"],
        [data-testid="inline-reply"] {
            max-width: 100% !important;
            width: 100% !important;
        }

        /* Profile page - expand user profile header and all components */
        [data-testid="UserProfileHeader_Items"],
        [data-testid="UserDescription"],
        [data-testid="UserName"],
        [data-testid="UserAvatar-Container-unknown"],
        [data-testid="placementTracking"],
        [data-testid="userActions"] {
            max-width: 100% !important;
        }

        /* Profile header banner - full width */
        [href$="/header_photo"],
        [href$="/header_photo"] > div {
            max-width: 100% !important;
            width: 100% !important;
        }

        /* Profile timeline section - full width */
        [aria-label$="'s posts"],
        [aria-label$="'s posts"] > div,
        section[aria-labelledby] {
            max-width: 100% !important;
            width: 100% !important;
        }

        /* Timeline virtualized container */
        [aria-label^="Timeline:"] > div[style*="position: relative"],
        div[style*="min-height"][style*="position: relative"] {
            max-width: 100% !important;
            width: 100% !important;
        }

        /* Hide the bottom bar/dock if present */
        [data-testid="BottomBar"] {
            display: none !important;
        }

        /* Hide any fixed positioning elements at the bottom */
        div[style*="position: fixed"][style*="bottom: 0"] {
            display: none !important;
        }

        /* Hide scroll snap container artifacts */
        [data-testid="ScrollSnap-SwipeableList"] {
            display: none !important;
        }

        /* Hide keyboard shortcuts modal trigger */
        [data-testid="Shortcut-modal"] {
            display: none !important;
        }

        /* Toggle button styles */
        #sidebar-toggle-btn {
            position: fixed !important;
            bottom: 20px !important;
            left: 20px !important;
            z-index: 9999 !important;
            width: 40px !important;
            height: 40px !important;
            border: none !important;
            border-radius: 50% !important;
            background: var(--background-color-primary, #fff) !important;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15) !important;
            cursor: pointer !important;
            font-size: 18px !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            transition: transform 0.2s, box-shadow 0.2s !important;
        }

        #sidebar-toggle-btn:hover {
            transform: scale(1.1) !important;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2) !important;
        }

        /* Move button when sidebar is open */
        body.sidebar-open #sidebar-toggle-btn {
            left: 295px !important;
        }
    `;

    if (typeof GM_addStyle !== 'undefined') {
        GM_addStyle(css);
    } else {
        const style = document.createElement('style');
        style.textContent = css;
        (document.head || document.documentElement).appendChild(style);
    }

    function createToggleButton() {
        if (document.getElementById('sidebar-toggle-btn')) return;

        const btn = document.createElement('button');
        btn.id = 'sidebar-toggle-btn';
        btn.innerHTML = '☰';
        btn.title = 'Toggle sidebar';

        btn.addEventListener('click', () => {
            const sidebar = document.querySelector('header[role="banner"]');
            if (sidebar) {
                sidebar.classList.toggle('show-sidebar');
                document.body.classList.toggle('sidebar-open');
            }
        });

        document.body.appendChild(btn);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', createToggleButton);
    } else {
        createToggleButton();
    }
})();
