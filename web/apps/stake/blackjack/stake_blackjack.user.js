// ==UserScript==
// @name         Stake Blackjack Automation
// @namespace    http://tampermonkey.net/
// @version      1.3
// @description  Automate blackjack on Stake.com with basic strategy
// @author       You
// @match        https://stake.com/casino/games/blackjack*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

/*
 * STAKE.COM BLACKJACK RULES:
 *   1. Unlimited decks in play (no card counting advantage)
 *   2. Insurance available when dealer shows Ace
 *   3. Both natural blackjack = push
 *   4. Dealer natural blackjack ends game immediately
 *   5. You can only split ONCE (no re-splitting)
 *   6. You CANNOT hit on split Aces (one card only)
 *   7. You can double on any first two cards
 *   8. You can double after split (DAS)
 *   9. Dealer STANDS on soft 17 (S17) - favorable to player
 *   10. Blackjack pays 3:2 (2.5x)
 *
 * DEBUG LOG FORMAT - All logs are JSON with [BJ:TYPE] prefix
 * 
 * Log Types:
 *   INIT           - Script loaded, config, token status
 *   HAND_START     - New hand started with bet details
 *   REQ            - API request (endpoint, body)
 *   RES            - API response (status, body, errors)
 *   GAME_STATE     - Current game state (cards, values, actions)
 *   ACTION         - Chosen action with strategy reasoning
 *   INSURANCE      - Insurance offered/taken/declined
 *   HAND_END       - Hand finished with result
 *   STATS          - Running statistics
 *   ERROR          - Any errors with context
 *   AUTOPLAY_*     - Auto-play start/stop/error
 *   STRATEGY_CHANGED - Strategy selection changed
 *   DEBUG_DUMP     - Full state dump (call bjDebug.dumpState())
 *
 * Available Strategies (card play):
 *   basic        - Mathematically optimal for S17+DAS rules
 *   conservative - Stand earlier, rarely double (minimize variance)
 *   aggressive   - Double more, hit more (higher variance)
 *   never_bust   - Stand on 12+ (never risk busting)
 *   mimic_dealer - Hit until 17, stand on 17+ (like the house)
 *
 * Available Betting Systems:
 *   flat         - Same bet every hand (default)
 *   martingale   - Double bet after loss, reset on win (RISKY!)
 *
 * Console Commands:
 *   bjDebug.getStats()           - Get current statistics
 *   bjDebug.dumpState()          - Dump full state for debugging
 *   bjDebug.setDebugLevel(n)     - Set debug verbosity (0=min, 1=normal, 2=verbose)
 *   bjDebug.setStrategy(name)    - Change strategy (basic, conservative, aggressive, etc.)
 *   bjDebug.getStrategies()      - List all available strategies
 *   bjDebug.setBettingSystem(s)  - Change betting system (flat, martingale)
 *   bjDebug.getBettingSystems()  - List all betting systems
 *   bjDebug.resetMartingale()    - Reset martingale to base bet
 *   bjDebug.getConfig()          - Get current config
 */

(function() {
    'use strict';

    // Configuration
    const CONFIG = {
        betAmount: 0.3,          // Base bet amount per hand
        currency: 'usdt',        // Currency to use
        autoPlay: false,         // Start auto-play immediately
        delayBetweenHands: 2000, // Delay between hands (ms)
        delayBetweenActions: 500, // Delay between actions (ms)
        takeInsurance: false,    // Take insurance when offered? (basic strategy says NEVER)
        debugLevel: 2,           // 0=minimal, 1=normal, 2=verbose
        strategy: 'basic',       // Strategy: basic, conservative, aggressive, never_bust, mimic_dealer
        bettingSystem: 'flat',   // Betting system: flat, martingale
        maxMartingaleBet: 100    // Maximum bet for martingale (safety cap)
    };
    
    // Strategy descriptions (optimized for Stake rules: S17, DAS, no re-split, no hit split aces)
    const STRATEGIES = {
        basic: {
            name: 'Basic Strategy',
            description: 'Optimal for Stake rules (S17, DAS) - best long-term EV'
        },
        conservative: {
            name: 'Conservative',
            description: 'Stand earlier, rarely double - minimize variance'
        },
        aggressive: {
            name: 'Aggressive', 
            description: 'Double more often, split more - higher variance'
        },
        never_bust: {
            name: 'Never Bust',
            description: 'Stand on 12+ hard - eliminates bust risk'
        },
        mimic_dealer: {
            name: 'Mimic Dealer',
            description: 'Stand on 17+ (like Stake dealer with S17 rule)'
        }
    };
    
    // Betting system descriptions
    const BETTING_SYSTEMS = {
        flat: {
            name: 'Flat Betting',
            description: 'Same bet amount every hand'
        },
        martingale: {
            name: 'Martingale',
            description: 'Double bet after loss, reset after win (risky!)'
        }
    };
    
    // Martingale tracking
    let currentBet = CONFIG.betAmount;  // Current bet (may differ from base in martingale)
    let consecutiveLosses = 0;

    // Debug logging - structured for easy copy/paste debugging
    let handNumber = 0;
    let currentHandId = null;
    let isHandInProgress = false;  // Lock to prevent parallel hands
    
    function debugLog(type, data) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            t: timestamp,
            hand: handNumber,
            handId: currentHandId,
            type: type,
            ...data
        };
        console.log(`[BJ:${type}]`, JSON.stringify(logEntry));
        return logEntry;
    }
    
    function debugState(label, bet) {
        if (CONFIG.debugLevel < 2) return;
        if (!bet) {
            debugLog('STATE', { label, error: 'no bet object' });
            return;
        }
        const state = bet.state;
        const player = state?.player?.[0];
        const dealer = state?.dealer?.[0];
        debugLog('STATE', {
            label,
            active: bet.active,
            amount: bet.amount,
            payout: bet.payout,
            playerCards: player?.cards?.map(c => c.rank + c.suit) || [],
            playerValue: player?.value,
            playerActions: player?.actions || [],
            dealerCards: dealer?.cards?.map(c => c.rank + c.suit) || [],
            dealerValue: dealer?.value,
            dealerActions: dealer?.actions || []
        });
    }

    // Generate random identifier for bets
    function generateIdentifier(length = 21) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }

    // Get access token from page data, localStorage, or cookies
    function getAccessToken() {
        // Method 1: Try localStorage first (Stake often stores session here)
        const localSession = localStorage.getItem('session');
        if (localSession) {
            try {
                const parsed = JSON.parse(localSession);
                if (parsed.session) return parsed.session;
                if (typeof parsed === 'string') return parsed;
            } catch (e) {
                if (typeof localSession === 'string' && localSession.length > 20) {
                    return localSession;
                }
            }
        }

        // Method 2: Try to extract from page's embedded data
        const scripts = document.querySelectorAll('script');
        for (const script of scripts) {
            const content = script.textContent || '';
            // Pattern 1: session:{session:"TOKEN"} (Stake's SvelteKit format)
            let match = content.match(/session:\s*\{\s*session:\s*["']([a-f0-9]{64,})["']/);
            if (match && match[1]) {
                console.log('[BJ DEBUG] Found token via pattern 1');
                return match[1];
            }
            // Pattern 2: "session":"TOKEN"
            match = content.match(/["']session["']\s*:\s*["']([a-f0-9]{64,})["']/);
            if (match && match[1]) {
                console.log('[BJ DEBUG] Found token via pattern 2');
                return match[1];
            }
            // Pattern 3: Just look for any 64+ char hex string near "session"
            match = content.match(/session[^\{]*\{[^}]*?([a-f0-9]{64,})/);
            if (match && match[1]) {
                console.log('[BJ DEBUG] Found token via pattern 3');
                return match[1];
            }
        }

        // Method 3: Try sessionStorage
        const sessionSession = sessionStorage.getItem('session');
        if (sessionSession) {
            try {
                const parsed = JSON.parse(sessionSession);
                if (parsed.session) return parsed.session;
            } catch (e) {
                if (typeof sessionSession === 'string' && sessionSession.length > 20) {
                    return sessionSession;
                }
            }
        }

        // Method 4: Try cookies as fallback
        const cookies = document.cookie.split(';');
        for (const cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'session' || name === 'access_token') {
                return value;
            }
        }

        // Method 5: Look for __sveltekit_* data which may contain session
        const dataScript = document.querySelector('script[data-sveltekit-fetched]');
        if (dataScript) {
            try {
                const data = JSON.parse(dataScript.textContent);
                if (data?.body?.session?.session) return data.body.session.session;
            } catch (e) {}
        }

        return null;
    }

    // Get lockdown token from localStorage
    function getLockdownToken() {
        const lockdown = localStorage.getItem('lockdown-token') || localStorage.getItem('lockdownToken');
        if (lockdown) return lockdown;
        
        // Try other possible storage locations
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.toLowerCase().includes('lockdown')) {
                return localStorage.getItem(key);
            }
        }
        return null;
    }

    // API request helper
    async function apiRequest(endpoint, data = {}) {
        const token = getAccessToken();
        if (!token) {
            debugLog('ERROR', { msg: 'No session token', localStorage: Object.keys(localStorage), sessionStorage: Object.keys(sessionStorage) });
            log('ERROR: No session token found. Make sure you are logged in.');
            throw new Error('No session token found. Please log in and refresh the page.');
        }

        const headers = {
            'Content-Type': 'application/json',
            'x-access-token': token,
            'x-language': 'en'
        };

        const lockdownToken = getLockdownToken();
        if (lockdownToken) {
            headers['x-lockdown-token'] = lockdownToken;
        }

        // Log request
        debugLog('REQ', { 
            endpoint, 
            body: data,
            hasToken: !!token,
            hasLockdown: !!lockdownToken
        });

        const startTime = Date.now();
        const response = await fetch(`https://stake.com${endpoint}`, {
            method: 'POST',
            headers,
            body: JSON.stringify(data),
            credentials: 'include'
        });

        const responseText = await response.text();
        const elapsed = Date.now() - startTime;
        
        let parsed = null;
        let parseError = null;
        try {
            parsed = JSON.parse(responseText);
        } catch (e) {
            parseError = e.message;
        }

        // Log response
        debugLog('RES', { 
            endpoint,
            status: response.status,
            elapsed: elapsed + 'ms',
            hasErrors: !!parsed?.errors,
            errorType: parsed?.errors?.[0]?.errorType,
            errorMsg: parsed?.errors?.[0]?.message,
            parseError,
            body: parsed || responseText.substring(0, 500)
        });

        if (!response.ok) {
            log(`API Error: ${response.status} - ${responseText}`);
            throw new Error(`API Error: ${response.status} ${response.statusText}`);
        }

        if (!parsed) {
            log(`Failed to parse JSON response: ${responseText}`);
            throw new Error('Invalid JSON response from API');
        }
        
        return parsed;
    }

    // GraphQL request helper
    async function graphqlRequest(query, variables = {}, operationName = null) {
        const token = getAccessToken();
        if (!token) {
            throw new Error('No session token found. Please log in.');
        }

        const payload = { query };
        if (Object.keys(variables).length > 0) {
            payload.variables = variables;
        }
        if (operationName) {
            payload.operationName = operationName;
        }

        const headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/graphql+json, application/json',
            'x-access-token': token,
            'x-language': 'en'
        };

        const lockdownToken = getLockdownToken();
        if (lockdownToken) {
            headers['x-lockdown-token'] = lockdownToken;
        }

        const response = await fetch('https://stake.com/_api/graphql', {
            method: 'POST',
            headers,
            body: JSON.stringify(payload),
            credentials: 'include'
        });

        if (!response.ok) {
            const text = await response.text();
            console.log('[BJ DEBUG] GraphQL error:', text);
            throw new Error(`GraphQL Error: ${response.status}`);
        }

        return response.json();
    }

    // Get user balances
    async function getBalances() {
        const query = `query UserBalances {
            user {
                id
                balances {
                    available {
                        amount
                        currency
                    }
                }
            }
        }`;
        return graphqlRequest(query, {}, 'UserBalances');
    }

    // Check for active bet
    async function getActiveBet() {
        return apiRequest('/_api/casino/active-bet/blackjack', {});
    }

    // Place a bet
    async function placeBet(amount, currency, identifier = null) {
        if (!identifier) {
            identifier = generateIdentifier();
        }
        return apiRequest('/_api/casino/blackjack/bet', {
            identifier,
            amount,
            currency: currency.toLowerCase()
        });
    }

    // Take an action (hit, stand, double, split)
    async function takeAction(action, identifier) {
        return apiRequest('/_api/casino/blackjack/next', {
            action,
            identifier
        });
    }

    // Calculate hand value
    function calculateHandValue(cards) {
        let value = 0;
        let aces = 0;

        for (const card of cards) {
            const rank = card.rank || card;
            if (['J', 'Q', 'K'].includes(rank)) {
                value += 10;
            } else if (rank === 'A') {
                aces++;
                value += 11;
            } else {
                value += parseInt(rank);
            }
        }

        let soft = aces > 0;
        while (value > 21 && aces > 0) {
            value -= 10;
            aces--;
            if (aces === 0) soft = false;
        }

        return { value, soft };
    }

    // Get dealer value helper
    function getDealerValue(dealerUpcard) {
        const dealerRank = dealerUpcard.rank || dealerUpcard;
        if (['J', 'Q', 'K', '10'].includes(dealerRank)) return 10;
        if (dealerRank === 'A') return 11;
        return parseInt(dealerRank);
    }

    // Strategy dispatcher - calls the appropriate strategy function
    function getAction(playerCards, dealerUpcard, canDouble = true, canSplit = true) {
        const strategy = CONFIG.strategy || 'basic';
        
        switch (strategy) {
            case 'conservative':
                return strategyConservative(playerCards, dealerUpcard, canDouble, canSplit);
            case 'aggressive':
                return strategyAggressive(playerCards, dealerUpcard, canDouble, canSplit);
            case 'never_bust':
                return strategyNeverBust(playerCards, dealerUpcard, canDouble, canSplit);
            case 'mimic_dealer':
                return strategyMimicDealer(playerCards, dealerUpcard, canDouble, canSplit);
            case 'basic':
            default:
                return strategyBasic(playerCards, dealerUpcard, canDouble, canSplit);
        }
    }

    // STRATEGY: Basic - Optimal for Stake rules (S17, DAS, split once, no hit split aces)
    function strategyBasic(playerCards, dealerUpcard, canDouble = true, canSplit = true) {
        const { value: playerValue, soft: isSoft } = calculateHandValue(playerCards);
        const dealerValue = getDealerValue(dealerUpcard);

        // PAIRS - Check for splits (remember: can only split once, no hit on split aces)
        if (playerCards.length === 2 && canSplit) {
            const rank1 = playerCards[0].rank || playerCards[0];
            const rank2 = playerCards[1].rank || playerCards[1];

            if (rank1 === rank2) {
                // Always split Aces and 8s
                if (rank1 === 'A') return 'split';  // Note: can't hit after, but still +EV
                if (rank1 === '8') return 'split';  // 16 is worst hand, split it
                
                // Split 9s except vs 7, 10, A (dealer likely has 17 or 20)
                if (rank1 === '9' && ![7, 10, 11].includes(dealerValue)) return 'split';
                
                // Split 7s vs 2-7 (with DAS makes this profitable)
                if (rank1 === '7' && dealerValue <= 7) return 'split';
                
                // Split 6s vs 2-6 (dealer likely to bust)
                if (rank1 === '6' && dealerValue <= 6) return 'split';
                
                // Split 3s and 2s vs 2-7 (with DAS)
                if (['2', '3'].includes(rank1) && dealerValue <= 7) return 'split';
                
                // Split 4s vs 5-6 only (with DAS, can double the split hands)
                if (rank1 === '4' && [5, 6].includes(dealerValue)) return 'split';
                
                // Never split 10s (20 is strong) or 5s (10 is better to double)
            }
        }

        // SOFT HANDS (Ace counted as 11)
        if (isSoft) {
            if (playerValue >= 19) return 'stand';  // A8+ always stand
            if (playerValue === 18) {
                // A7: Double vs 3-6, stand vs 2/7/8, hit vs 9/10/A
                if (dealerValue >= 9) return 'hit';
                if ([3, 4, 5, 6].includes(dealerValue) && canDouble && playerCards.length === 2) return 'double';
                return 'stand';
            }
            if (playerValue === 17) {
                // A6: Double vs 3-6, otherwise hit
                if ([3, 4, 5, 6].includes(dealerValue) && canDouble && playerCards.length === 2) return 'double';
                return 'hit';
            }
            if ([15, 16].includes(playerValue)) {
                // A4, A5: Double vs 4-6, otherwise hit
                if ([4, 5, 6].includes(dealerValue) && canDouble && playerCards.length === 2) return 'double';
                return 'hit';
            }
            if ([13, 14].includes(playerValue)) {
                // A2, A3: Double vs 5-6, otherwise hit
                if ([5, 6].includes(dealerValue) && canDouble && playerCards.length === 2) return 'double';
                return 'hit';
            }
            return 'hit';
        }

        // HARD HANDS
        if (playerValue >= 17) return 'stand';  // Always stand on 17+
        
        if (playerValue >= 13 && playerValue <= 16) {
            // 13-16: Stand vs 2-6 (dealer likely busts), hit vs 7+ 
            return dealerValue <= 6 ? 'stand' : 'hit';
        }
        
        if (playerValue === 12) {
            // 12: Stand vs 4-6 only (dealer most likely to bust)
            return [4, 5, 6].includes(dealerValue) ? 'stand' : 'hit';
        }
        
        if (playerValue === 11) {
            // 11: Always double (best double hand)
            return (canDouble && playerCards.length === 2) ? 'double' : 'hit';
        }
        
        if (playerValue === 10) {
            // 10: Double vs 2-9
            return (dealerValue <= 9 && canDouble && playerCards.length === 2) ? 'double' : 'hit';
        }
        
        if (playerValue === 9) {
            // 9: Double vs 3-6 only
            return ([3, 4, 5, 6].includes(dealerValue) && canDouble && playerCards.length === 2) ? 'double' : 'hit';
        }

        // 8 or less: always hit
        return 'hit';
    }

    // STRATEGY: Conservative - Stand earlier, minimize variance, fewer risks
    function strategyConservative(playerCards, dealerUpcard, canDouble = true, canSplit = true) {
        const { value: playerValue, soft: isSoft } = calculateHandValue(playerCards);
        const dealerValue = getDealerValue(dealerUpcard);

        // Only split Aces and 8s (the "must split" pairs)
        if (playerCards.length === 2 && canSplit) {
            const rank1 = playerCards[0].rank || playerCards[0];
            const rank2 = playerCards[1].rank || playerCards[1];
            if (rank1 === rank2 && ['A', '8'].includes(rank1)) return 'split';
        }

        // Soft hands - more conservative, stand earlier
        if (isSoft) {
            if (playerValue >= 18) return 'stand';  // Stand on soft 18+
            if (playerValue === 17 && dealerValue <= 6) return 'stand';  // Stand soft 17 vs weak dealer
            return 'hit';  // No soft doubles
        }

        // Hard hands - stand earlier to reduce bust risk
        if (playerValue >= 15) return 'stand';  // Stand on 15+ (basic says hit 15-16 vs high cards)
        if (playerValue >= 12 && dealerValue <= 6) return 'stand';  // Stand 12+ vs weak dealer
        
        // Only double on 11 vs weak dealer (safest double)
        if (playerValue === 11 && canDouble && playerCards.length === 2 && dealerValue <= 9) {
            return 'double';
        }
        
        // Only double on 10 vs very weak dealer
        if (playerValue === 10 && canDouble && playerCards.length === 2 && dealerValue <= 6) {
            return 'double';
        }

        return 'hit';
    }

    // STRATEGY: Aggressive - Double more, split more (using DAS advantage)
    function strategyAggressive(playerCards, dealerUpcard, canDouble = true, canSplit = true) {
        const { value: playerValue, soft: isSoft } = calculateHandValue(playerCards);
        const dealerValue = getDealerValue(dealerUpcard);

        // Split more aggressively (taking advantage of DAS)
        if (playerCards.length === 2 && canSplit) {
            const rank1 = playerCards[0].rank || playerCards[0];
            const rank2 = playerCards[1].rank || playerCards[1];

            if (rank1 === rank2) {
                // Always split A, 8
                if (['A', '8'].includes(rank1)) return 'split';
                // Split 9s except vs 7 (already have 18 vs likely 17)
                if (rank1 === '9' && dealerValue !== 7) return 'split';
                // Split 7s, 6s, 3s, 2s vs dealer 2-8 (more aggressive than basic)
                if (['7', '6', '3', '2'].includes(rank1) && dealerValue <= 8) return 'split';
                // Split 4s vs 4-6 (can double the 5s and 6s after split)
                if (rank1 === '4' && [4, 5, 6].includes(dealerValue)) return 'split';
            }
        }

        // Soft hands - double more aggressively
        if (isSoft) {
            if (playerValue >= 19) return 'stand';
            if (playerValue === 18) {
                // Double vs 2-6 (more aggressive), hit vs 9+
                if (dealerValue <= 6 && canDouble && playerCards.length === 2) return 'double';
                return dealerValue >= 9 ? 'hit' : 'stand';
            }
            // A7: also double vs 7-8
            if (playerValue === 17 && canDouble && playerCards.length === 2) {
                if (dealerValue <= 6) return 'double';
            }
            // Double soft 13-17 vs 3-6 (expanded range)
            if (playerValue >= 13 && playerValue <= 17 && [3, 4, 5, 6].includes(dealerValue) && canDouble && playerCards.length === 2) {
                return 'double';
            }
            if (playerValue <= 17) return 'hit';
            return 'stand';
        }

        // Hard hands - double more aggressively
        if (playerValue >= 17) return 'stand';
        
        if (canDouble && playerCards.length === 2) {
            // Double 11 always
            if (playerValue === 11) return 'double';
            // Double 10 vs 2-9
            if (playerValue === 10 && dealerValue <= 9) return 'double';
            // Double 9 vs 2-6 (more aggressive)
            if (playerValue === 9 && dealerValue <= 6) return 'double';
            // Double 8 vs 5-6
            if (playerValue === 8 && [5, 6].includes(dealerValue)) return 'double';
        }

        // Standard hitting rules
        if (playerValue >= 13) {
            return dealerValue <= 6 ? 'stand' : 'hit';
        }
        if (playerValue === 12) {
            return [4, 5, 6].includes(dealerValue) ? 'stand' : 'hit';
        }

        return 'hit';
    }

    // STRATEGY: Never Bust - Never hit if there's any chance to bust
    function strategyNeverBust(playerCards, dealerUpcard, canDouble = true, canSplit = true) {
        const { value: playerValue, soft: isSoft } = calculateHandValue(playerCards);
        const dealerValue = getDealerValue(dealerUpcard);

        // Split only Aces (note: can't hit after split aces anyway)
        if (playerCards.length === 2 && canSplit) {
            const rank1 = playerCards[0].rank || playerCards[0];
            const rank2 = playerCards[1].rank || playerCards[1];
            if (rank1 === rank2 && rank1 === 'A') return 'split';
            // Also split 8s since 16 is terrible and we can't bust on the split
            if (rank1 === rank2 && rank1 === '8') return 'split';
        }

        // Soft hands - safe to hit, can't bust
        if (isSoft) {
            if (playerValue >= 18) return 'stand';
            // Can double soft hands safely (getting one more card can't bust)
            if (playerValue === 11 && canDouble && playerCards.length === 2) return 'double';
            return 'hit';
        }

        // Hard hands - NEVER risk busting (stand on 12+)
        if (playerValue >= 12) return 'stand';

        // 11 or less: safe to hit or double
        if (playerValue === 11 && canDouble && playerCards.length === 2) return 'double';
        if (playerValue === 10 && canDouble && playerCards.length === 2 && dealerValue <= 9) return 'double';
        
        return 'hit';
    }

    // STRATEGY: Mimic Dealer - Play exactly like Stake's dealer (S17 rule)
    function strategyMimicDealer(playerCards, dealerUpcard, canDouble = true, canSplit = true) {
        const { value: playerValue, soft: isSoft } = calculateHandValue(playerCards);

        // No splits, no doubles - dealer never does these
        // Stake dealer STANDS on soft 17 (S17 rule)

        // Stand on 17+ (including soft 17)
        if (playerValue >= 17) return 'stand';

        // Hit on 16 or less
        return 'hit';
    }

    // Alias for backward compatibility
    function basicStrategy(playerCards, dealerUpcard, canDouble = true, canSplit = true) {
        return getAction(playerCards, dealerUpcard, canDouble, canSplit);
    }

    // Check if insurance is being offered
    function isInsuranceOffered(bet, dealerCards) {
        // Insurance is offered when:
        // 1. Dealer shows an Ace
        // 2. Game is active and waiting for action
        // 3. bet.insurance or state.insuranceOffered flag might be set
        if (!bet?.active) return false;
        
        const dealerUpcard = dealerCards?.[0];
        if (!dealerUpcard) return false;
        
        const dealerRank = dealerUpcard.rank || dealerUpcard;
        if (dealerRank !== 'A') return false;
        
        // Check for insurance-related flags in the bet or state
        // The API might indicate insurance is available through:
        // - bet.insuranceOffered
        // - state.insuranceAvailable
        // - playerHand.actions containing 'insurance'
        const state = bet.state;
        const playerHand = state?.player?.[0];
        const actions = playerHand?.actions || [];
        
        // If the last action was 'deal' (initial deal), insurance is likely offered
        if (actions.includes('deal') || actions.includes('insurance')) {
            return true;
        }
        
        // Also check bet-level flags
        if (bet.insuranceOffered || bet.insurance?.offered || state?.insuranceOffered) {
            return true;
        }
        
        return false;
    }

    // Play a single hand
    async function playHand(betAmount, currency) {
        // Prevent parallel hands - if a hand is already in progress, skip
        if (isHandInProgress) {
            debugLog('HAND_SKIPPED', { reason: 'hand already in progress', currentHandId });
            return null;
        }
        isHandInProgress = true;
        
        handNumber++;
        let identifier = generateIdentifier();
        currentHandId = identifier;
        let actionNum = 0;
        
        debugLog('HAND_START', { 
            betAmount, 
            currency, 
            identifier,
            config: { ...CONFIG, debugLevel: undefined } 
        });
        log(`Placing bet: ${betAmount} ${currency.toUpperCase()}`);

        let result = await placeBet(betAmount, currency, identifier);
        
        // Check for errors (like existing game)
        if (result.errors) {
            const errorType = result.errors[0]?.errorType;
            debugLog('BET_ERROR', { errorType, msg: result.errors[0]?.message });
            
            if (errorType === 'existingGame') {
                log('Found existing game, resuming...');
                const activeBet = await getActiveBet();
                
                // The active bet is at user.activeCasinoBet (not blackjackActiveBet)
                const existingGame = activeBet?.user?.activeCasinoBet;
                debugLog('ACTIVE_BET', { 
                    found: !!existingGame, 
                    gameId: existingGame?.id,
                    active: existingGame?.active,
                    data: activeBet 
                });
                
                if (existingGame && existingGame.active) {
                    result = { blackjackBet: existingGame };
                    // The identifier might not be in the response, use the game's id
                    identifier = existingGame.identifier || existingGame.id || identifier;
                    currentHandId = identifier;
                    log(`Resumed game ID: ${existingGame.id}`);
                } else {
                    debugLog('ERROR', { msg: 'Could not retrieve active game', existingGame });
                    log('ERROR: Could not retrieve active game');
                    isHandInProgress = false;  // Release lock
                    return result;
                }
            } else if (errorType === 'insufficientBalance') {
                // Handle insufficient balance - reset and continue
                debugLog('INSUFFICIENT_BALANCE', { 
                    currentBet, 
                    baseBet: CONFIG.betAmount,
                    bettingSystem: CONFIG.bettingSystem,
                    consecutiveLosses
                });
                
                if (CONFIG.bettingSystem === 'martingale') {
                    log(`INSUFFICIENT BALANCE: Cannot afford ${currentBet.toFixed(4)}, resetting to ${CONFIG.betAmount}`);
                    // Reset martingale to base bet and continue
                    currentBet = CONFIG.betAmount;
                    consecutiveLosses = 0;
                    updateBetDisplay();
                    log('Martingale reset. Continuing with base bet.');
                } else {
                    log(`ERROR: Insufficient balance for ${betAmount} bet`);
                }
                isHandInProgress = false;  // Release lock
                return result;  // Return to try again with reset bet
            } else {
                log(`ERROR: ${result.errors[0]?.message || 'Unknown error'}`);
                isHandInProgress = false;  // Release lock
                return result;
            }
        }
        
        log(`Bet placed. ID: ${identifier}`);

        // Track if we've handled insurance for this hand
        let insuranceHandled = false;

        while (true) {
            actionNum++;
            
            // Get the bet object (blackjackBet for initial bet, blackjackNext for actions)
            const bet = result?.blackjackBet || result?.blackjackNext;
            if (!bet || !bet.state) {
                debugLog('ERROR', { 
                    msg: 'Game state not available', 
                    resultKeys: Object.keys(result || {}),
                    hasBet: !!bet,
                    hasState: !!bet?.state,
                    result 
                });
                log('ERROR: Game state not available');
                isHandInProgress = false;  // Release lock
                break;
            }

            const state = bet.state;
            const playerHand = state.player?.[0];
            const dealerHand = state.dealer?.[0];
            
            const playerCards = playerHand?.cards || [];
            const dealerCards = dealerHand?.cards || [];

            if (!playerCards.length || !dealerCards.length) {
                debugLog('ERROR', { 
                    msg: 'Cards not available', 
                    stateKeys: Object.keys(state || {}),
                    playerCards,
                    dealerCards,
                    state 
                });
                log('ERROR: Cards not available in game state');
                isHandInProgress = false;  // Release lock
                break;
            }

            const { value: playerValue, soft } = calculateHandValue(playerCards);
            const dealerUpcard = dealerCards[0];
            const dealerRank = dealerUpcard?.rank || dealerUpcard;
            
            debugLog('GAME_STATE', {
                actionNum,
                active: bet.active,
                insuranceHandled,
                player: {
                    cards: playerCards.map(c => c.rank + c.suit),
                    value: playerValue,
                    soft,
                    actions: playerHand?.actions
                },
                dealer: {
                    cards: dealerCards.map(c => c.rank + c.suit),
                    upcard: dealerRank,
                    value: dealerHand?.value,
                    actions: dealerHand?.actions
                },
                payout: bet.payout,
                amount: bet.amount
            });
            
            log(`Player: ${formatCards(playerCards)} (${playerValue}${soft ? 'S' : ''})`);
            log(`Dealer shows: ${formatCards([dealerCards[0]])}`);

            // Check if game is complete (bet is no longer active)
            const isComplete = !bet.active;
            
            if (isComplete) {
                const payout = bet.payout || 0;
                const actualBet = bet.amount || betAmount;  // Use actual bet (includes doubles/splits)
                const profit = payout - actualBet;
                const gameResult = payout > actualBet ? 'win' : (payout === actualBet ? 'push' : 'lose');
                
                debugLog('HAND_END', {
                    result: gameResult,
                    payout,
                    profit,
                    initialBet: betAmount,
                    actualBet: actualBet,
                    playerFinal: playerCards.map(c => c.rank + c.suit),
                    playerValue,
                    dealerFinal: dealerCards.map(c => c.rank + c.suit),
                    dealerValue: dealerHand?.value,
                    actions: playerHand?.actions
                });
                
                log(`Game complete! Result: ${gameResult}, Payout: ${payout}, Bet: ${actualBet}, Profit: ${profit >= 0 ? '+' : ''}${profit.toFixed(8)}`);
                updateStats(gameResult, profit);
                isHandInProgress = false;  // Release lock
                break;
            }

            // Check if insurance is being offered (dealer shows Ace)
            if (!insuranceHandled && isInsuranceOffered(bet, dealerCards)) {
                const insuranceAction = CONFIG.takeInsurance ? 'insurance' : 'noInsurance';
                debugLog('INSURANCE', { 
                    offered: true, 
                    taking: CONFIG.takeInsurance,
                    action: insuranceAction 
                });
                
                log(CONFIG.takeInsurance ? 'Insurance offered - TAKING (not recommended!)' : 'Insurance offered - DECLINING (basic strategy)');
                await sleep(CONFIG.delayBetweenActions);
                result = await takeAction(insuranceAction, identifier);
                insuranceHandled = true;
                
                if (!result.errors) {
                    continue;
                }
                debugLog('INSURANCE_FAILED', { errors: result.errors });
                log('Insurance action failed, trying normal action...');
            }

            // Determine action using basic strategy
            const canDouble = true;
            const canSplit = playerCards.length === 2 && playerCards[0].rank === playerCards[1].rank;
            const action = getAction(playerCards, dealerCards[0], canDouble, canSplit);
            
            debugLog('ACTION', { 
                strategy: CONFIG.strategy,
                chosen: action, 
                playerValue, 
                soft, 
                dealerUpcard: dealerRank,
                canDouble,
                canSplit,
                cardCount: playerCards.length
            });
            
            log(`[${STRATEGIES[CONFIG.strategy]?.name || CONFIG.strategy}] Action: ${action.toUpperCase()}`);

            await sleep(CONFIG.delayBetweenActions);
            result = await takeAction(action, identifier);
            
            // Handle action errors
            if (result.errors) {
                const errorType = result.errors[0]?.errorType;
                const errorMsg = result.errors[0]?.message || '';
                
                debugLog('ACTION_ERROR', { 
                    action, 
                    errorType, 
                    errorMsg,
                    insuranceHandled,
                    dealerIsAce: dealerRank === 'A'
                });
                
                log(`Action error: ${errorMsg}`);
                
                // If action was invalid due to insurance being required, handle it
                if (errorType === 'blackjackInvalidAction' && !insuranceHandled && dealerRank === 'A') {
                    const insuranceAction = CONFIG.takeInsurance ? 'insurance' : 'noInsurance';
                    debugLog('INSURANCE_RETRY', { action: insuranceAction });
                    
                    log(CONFIG.takeInsurance ? 'Insurance required - TAKING' : 'Insurance required - DECLINING');
                    await sleep(CONFIG.delayBetweenActions);
                    result = await takeAction(insuranceAction, identifier);
                    
                    if (!result.errors) {
                        insuranceHandled = true;
                        continue;
                    }
                }
                
                // Try stand as final fallback
                if (errorType === 'blackjackInvalidAction') {
                    debugLog('FALLBACK', { action: 'stand' });
                    log('Trying STAND as fallback...');
                    await sleep(CONFIG.delayBetweenActions);
                    result = await takeAction('stand', identifier);
                    
                    if (result.errors) {
                        debugLog('FALLBACK_FAILED', { errors: result.errors });
                        log('ERROR: Could not recover from invalid action');
                        isHandInProgress = false;  // Release lock
                        break;
                    }
                } else {
                    isHandInProgress = false;  // Release lock
                    break;
                }
            }
        }

        isHandInProgress = false;  // Release lock at function end
        return result;
    }

    // Format cards for display
    function formatCards(cards) {
        return cards.map(c => `${c.rank || c}${c.suit ? c.suit[0] : ''}`).join(' ');
    }

    // Sleep helper
    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // Stats tracking
    let stats = {
        hands: 0,
        wins: 0,
        losses: 0,
        pushes: 0,
        blackjacks: 0,
        profit: 0,
        sessionStart: new Date().toISOString()
    };

    function updateStats(result, profit) {
        stats.hands++;
        stats.profit += profit;

        if (result === 'win') stats.wins++;
        else if (result === 'lose') stats.losses++;
        else if (result === 'push') stats.pushes++;
        else if (result === 'blackjack') {
            stats.blackjacks++;
            stats.wins++;
        }
        
        // Martingale betting system adjustment
        if (CONFIG.bettingSystem === 'martingale') {
            if (result === 'lose') {
                consecutiveLosses++;
                const nextBet = currentBet * 2;
                if (nextBet <= CONFIG.maxMartingaleBet) {
                    currentBet = nextBet;
                    debugLog('MARTINGALE', { action: 'double', nextBet: currentBet, consecutiveLosses });
                    log(`Martingale: Doubling bet to ${currentBet.toFixed(4)} (${consecutiveLosses} losses)`);
                } else {
                    currentBet = CONFIG.betAmount;  // Reset if would exceed max
                    consecutiveLosses = 0;
                    debugLog('MARTINGALE', { action: 'reset_max', reason: 'exceeded max bet', maxBet: CONFIG.maxMartingaleBet });
                    log(`Martingale: Hit max bet limit, resetting to ${currentBet.toFixed(4)}`);
                }
            } else if (result === 'win' || result === 'blackjack') {
                currentBet = CONFIG.betAmount;  // Reset on win
                consecutiveLosses = 0;
                debugLog('MARTINGALE', { action: 'reset_win', nextBet: currentBet });
                log(`Martingale: Win! Resetting bet to ${currentBet.toFixed(4)}`);
            }
            // Push: keep same bet
            updateBetDisplay();
        }

        // Log stats every 10 hands or on significant events
        if (stats.hands % 10 === 0 || CONFIG.debugLevel >= 2) {
            debugLog('STATS', {
                ...stats,
                winRate: stats.hands > 0 ? ((stats.wins / stats.hands) * 100).toFixed(1) + '%' : '0%',
                avgProfit: stats.hands > 0 ? (stats.profit / stats.hands).toFixed(8) : '0',
                currentBet: CONFIG.bettingSystem === 'martingale' ? currentBet : CONFIG.betAmount,
                consecutiveLosses
            });
        }

        updateUI();
        
        // Check profit target
        if (CONFIG.profitTargetEnabled && stats.profit >= CONFIG.profitTarget) {
            debugLog('PROFIT_TARGET_HIT', { 
                profit: stats.profit, 
                target: CONFIG.profitTarget,
                hands: stats.hands
            });
            log(`🎯 PROFIT TARGET HIT! Profit: +${stats.profit.toFixed(4)} (Target: ${CONFIG.profitTarget})`);
            stopPlay();
        }
    }
    
    // Update bet display for martingale
    function updateBetDisplay() {
        const betInput = document.getElementById('bj-bet');
        const currentBetDisplay = document.getElementById('bj-current-bet');
        if (CONFIG.bettingSystem === 'martingale') {
            if (currentBetDisplay) {
                currentBetDisplay.textContent = `Next bet: ${currentBet.toFixed(4)}`;
                currentBetDisplay.style.display = 'block';
            }
        } else {
            if (currentBetDisplay) currentBetDisplay.style.display = 'none';
        }
    }
    
    // Get current stats for debugging
    function getStats() {
        return {
            ...stats,
            winRate: stats.hands > 0 ? ((stats.wins / stats.hands) * 100).toFixed(1) + '%' : '0%',
            avgProfit: stats.hands > 0 ? (stats.profit / stats.hands).toFixed(8) : '0',
            currentHand: handNumber,
            currentBet: currentBet,
            consecutiveLosses: consecutiveLosses,
            bettingSystem: CONFIG.bettingSystem
        };
    }
    
    // Expose for console debugging
    window.bjDebug = {
        getStats,
        getConfig: () => CONFIG,
        getStrategies: () => STRATEGIES,
        getBettingSystems: () => BETTING_SYSTEMS,
        setDebugLevel: (level) => { CONFIG.debugLevel = level; },
        setStrategy: (strategy) => {
            if (STRATEGIES[strategy]) {
                CONFIG.strategy = strategy;
                const select = document.getElementById('bj-strategy');
                if (select) select.value = strategy;
                const desc = document.getElementById('strategy-desc');
                if (desc) desc.textContent = STRATEGIES[strategy].description;
                debugLog('STRATEGY_CHANGED', { strategy, description: STRATEGIES[strategy].description });
                return `Strategy set to: ${STRATEGIES[strategy].name}`;
            } else {
                return `Unknown strategy. Available: ${Object.keys(STRATEGIES).join(', ')}`;
            }
        },
        setBettingSystem: (system) => {
            if (BETTING_SYSTEMS[system]) {
                CONFIG.bettingSystem = system;
                const select = document.getElementById('bj-betting');
                if (select) select.value = system;
                const desc = document.getElementById('betting-desc');
                if (desc) desc.textContent = BETTING_SYSTEMS[system].description;
                currentBet = CONFIG.betAmount;
                consecutiveLosses = 0;
                updateBetDisplay();
                debugLog('BETTING_CHANGED', { system, description: BETTING_SYSTEMS[system].description });
                return `Betting system set to: ${BETTING_SYSTEMS[system].name}`;
            } else {
                return `Unknown system. Available: ${Object.keys(BETTING_SYSTEMS).join(', ')}`;
            }
        },
        resetMartingale: () => {
            currentBet = CONFIG.betAmount;
            consecutiveLosses = 0;
            updateBetDisplay();
            debugLog('MARTINGALE_RESET', { baseBet: CONFIG.betAmount });
            return `Martingale reset. Next bet: ${currentBet}`;
        },
        dumpState: () => {
            debugLog('DEBUG_DUMP', {
                stats: getStats(),
                config: CONFIG,
                strategies: Object.keys(STRATEGIES),
                bettingSystems: Object.keys(BETTING_SYSTEMS),
                handNumber,
                currentHandId,
                isPlaying,
                isHandInProgress,
                currentBet,
                consecutiveLosses
            });
        }
    };

    // Logging
    function log(message) {
        const time = new Date().toLocaleTimeString();
        console.log(`[Blackjack] ${time}: ${message}`);

        const logDiv = document.getElementById('bj-log');
        if (logDiv) {
            const entry = document.createElement('div');
            entry.textContent = `${time}: ${message}`;
            logDiv.insertBefore(entry, logDiv.firstChild);

            // Keep only last 50 entries
            while (logDiv.children.length > 50) {
                logDiv.removeChild(logDiv.lastChild);
            }
        }
    }

    // Auto-play loop
    let isPlaying = false;
    let autoPlayLoopId = 0;  // Track which loop is active

    async function autoPlay() {
        if (isPlaying) {
            debugLog('AUTOPLAY_SKIP', { reason: 'already playing' });
            return;
        }
        isPlaying = true;
        autoPlayLoopId++;
        const myLoopId = autoPlayLoopId;

        const btn = document.getElementById('bj-play-btn');
        if (btn) btn.textContent = 'Stop';

        debugLog('AUTOPLAY_START', { config: CONFIG, stats: getStats(), loopId: myLoopId });
        log('Auto-play started');

        while (isPlaying && autoPlayLoopId === myLoopId) {
            try {
                const betToUse = CONFIG.bettingSystem === 'martingale' ? currentBet : CONFIG.betAmount;
                const result = await playHand(betToUse, CONFIG.currency);
                // Only sleep if hand actually played (wasn't skipped due to lock)
                if (result !== null) {
                    await sleep(CONFIG.delayBetweenHands);
                } else {
                    // Hand was skipped - wait a bit before retrying
                    await sleep(500);
                }
            } catch (error) {
                debugLog('AUTOPLAY_ERROR', { 
                    error: error.message, 
                    stack: error.stack?.split('\n').slice(0, 3),
                    loopId: myLoopId
                });
                log(`Error: ${error.message}`);
                await sleep(5000);
            }
        }

        debugLog('AUTOPLAY_STOP', { stats: getStats(), loopId: myLoopId });
        log('Auto-play stopped');
    }

    function stopPlay() {
        isPlaying = false;
        // Reset martingale on stop
        currentBet = CONFIG.betAmount;
        consecutiveLosses = 0;
        updateBetDisplay();
        debugLog('AUTOPLAY_STOPPED', { stats: getStats() });
        const btn = document.getElementById('bj-play-btn');
        if (btn) btn.textContent = 'Start Auto-Play';
    }

    // Create UI
    function createUI() {
        const panel = document.createElement('div');
        panel.id = 'bj-panel';
        panel.innerHTML = `
            <style>
                #bj-panel {
                    position: fixed;
                    top: 10px;
                    right: 10px;
                    width: 320px;
                    background: #1a1a2e;
                    border: 1px solid #4a4a6a;
                    border-radius: 8px;
                    padding: 15px;
                    z-index: 99999;
                    font-family: Arial, sans-serif;
                    color: #fff;
                    font-size: 13px;
                    box-shadow: 0 4px 20px rgba(0,0,0,0.5);
                }
                #bj-panel h3 {
                    margin: 0 0 10px 0;
                    color: #00ff88;
                    font-size: 16px;
                }
                #bj-panel .row {
                    display: flex;
                    justify-content: space-between;
                    margin: 5px 0;
                }
                #bj-panel input, #bj-panel select {
                    background: #2a2a4e;
                    border: 1px solid #4a4a6a;
                    color: #fff;
                    padding: 5px 8px;
                    border-radius: 4px;
                    width: 120px;
                }
                #bj-panel button {
                    background: #00ff88;
                    color: #000;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                    cursor: pointer;
                    font-weight: bold;
                    margin: 5px 5px 5px 0;
                }
                #bj-panel button:hover {
                    background: #00cc6a;
                }
                #bj-panel button.stop {
                    background: #ff4444;
                    color: #fff;
                }
                #bj-panel .stats {
                    background: #2a2a4e;
                    padding: 10px;
                    border-radius: 4px;
                    margin: 10px 0;
                }
                #bj-panel .profit-positive { color: #00ff88; }
                #bj-panel .profit-negative { color: #ff4444; }
                #bj-log {
                    max-height: 150px;
                    overflow-y: auto;
                    background: #0a0a1e;
                    padding: 8px;
                    border-radius: 4px;
                    font-size: 11px;
                    margin-top: 10px;
                }
                #bj-log div {
                    padding: 2px 0;
                    border-bottom: 1px solid #2a2a4e;
                }
                #bj-panel .minimize {
                    position: absolute;
                    top: 5px;
                    right: 10px;
                    cursor: pointer;
                    font-size: 18px;
                }
            </style>
            <span class="minimize" id="bj-minimize">−</span>
            <h3>🃏 Blackjack Bot</h3>
            <div id="bj-content">
                <div class="row">
                    <label>Bet Amount:</label>
                    <input type="number" id="bj-bet" value="${CONFIG.betAmount}" step="0.001" min="0.00000001">
                </div>
                <div class="row">
                    <label>Currency:</label>
                    <select id="bj-currency">
                        <option value="usdt" selected>USDT</option>
                        <option value="btc">BTC</option>
                        <option value="eth">ETH</option>
                        <option value="ltc">LTC</option>
                        <option value="doge">DOGE</option>
                    </select>
                </div>
                <div class="row">
                    <label>Strategy:</label>
                    <select id="bj-strategy">
                        <option value="basic" selected>Basic (Optimal)</option>
                        <option value="conservative">Conservative</option>
                        <option value="aggressive">Aggressive</option>
                        <option value="never_bust">Never Bust</option>
                        <option value="mimic_dealer">Mimic Dealer</option>
                    </select>
                </div>
                <div id="strategy-desc" style="font-size:10px;color:#888;margin:5px 0;font-style:italic;">
                    Mathematically optimal play - best long-term EV
                </div>
                <div class="row">
                    <label>Betting:</label>
                    <select id="bj-betting">
                        <option value="flat" selected>Flat (Same bet)</option>
                        <option value="martingale">Martingale (2x loss)</option>
                    </select>
                </div>
                <div id="betting-desc" style="font-size:10px;color:#888;margin:5px 0;font-style:italic;">
                    Same bet amount every hand
                </div>
                <div id="bj-current-bet" style="font-size:11px;color:#ffaa00;margin:5px 0;display:none;">
                    Next bet: ${CONFIG.betAmount.toFixed(4)}
                </div>
                <div class="row" style="margin-top:8px;">
                    <label style="display:flex;align-items:center;gap:5px;">
                        <input type="checkbox" id="bj-profit-target-enabled" style="width:auto;">
                        Profit Target:
                    </label>
                    <input type="number" id="bj-profit-target" value="${CONFIG.profitTarget}" step="0.1" min="0" style="width:80px;">
                </div>
                <div class="stats">
                    <div class="row"><span>Hands:</span><span id="stat-hands">0</span></div>
                    <div class="row"><span>Wins:</span><span id="stat-wins">0</span></div>
                    <div class="row"><span>Losses:</span><span id="stat-losses">0</span></div>
                    <div class="row"><span>Pushes:</span><span id="stat-pushes">0</span></div>
                    <div class="row"><span>Blackjacks:</span><span id="stat-bjs">0</span></div>
                    <div class="row"><span>Profit:</span><span id="stat-profit">0.00000000</span></div>
                </div>
                <button id="bj-play-btn">Start Auto-Play</button>
                <button id="bj-single-btn">Play 1 Hand</button>
                <button id="bj-balance-btn">Check Balance</button>
                <button id="bj-debug-btn" style="background:#666;">Debug Token</button>
                <div id="bj-log"></div>
            </div>
        `;

        document.body.appendChild(panel);

        // Event listeners
        document.getElementById('bj-play-btn').addEventListener('click', () => {
            if (isPlaying) {
                stopPlay();
            } else {
                CONFIG.betAmount = parseFloat(document.getElementById('bj-bet').value);
                CONFIG.currency = document.getElementById('bj-currency').value;
                CONFIG.strategy = document.getElementById('bj-strategy').value;
                CONFIG.bettingSystem = document.getElementById('bj-betting').value;
                CONFIG.profitTargetEnabled = document.getElementById('bj-profit-target-enabled').checked;
                CONFIG.profitTarget = parseFloat(document.getElementById('bj-profit-target').value) || 1.0;
                // Reset martingale state on start
                currentBet = CONFIG.betAmount;
                consecutiveLosses = 0;
                updateBetDisplay();
                if (CONFIG.profitTargetEnabled) {
                    log(`Profit target set: ${CONFIG.profitTarget}`);
                }
                autoPlay();
            }
        });

        document.getElementById('bj-single-btn').addEventListener('click', async () => {
            if (isPlaying) {
                log('Cannot play single hand while auto-play is running');
                return;
            }
            if (isHandInProgress) {
                log('A hand is already in progress');
                return;
            }
            CONFIG.betAmount = parseFloat(document.getElementById('bj-bet').value);
            CONFIG.currency = document.getElementById('bj-currency').value;
            CONFIG.strategy = document.getElementById('bj-strategy').value;
            CONFIG.bettingSystem = document.getElementById('bj-betting').value;
            const betToUse = CONFIG.bettingSystem === 'martingale' ? currentBet : CONFIG.betAmount;
            try {
                await playHand(betToUse, CONFIG.currency);
            } catch (error) {
                log(`Error: ${error.message}`);
            }
        });
        
        // Betting system selector
        document.getElementById('bj-betting').addEventListener('change', (e) => {
            CONFIG.bettingSystem = e.target.value;
            const desc = BETTING_SYSTEMS[CONFIG.bettingSystem]?.description || '';
            document.getElementById('betting-desc').textContent = desc;
            // Reset martingale state when changing betting system
            currentBet = CONFIG.betAmount;
            consecutiveLosses = 0;
            updateBetDisplay();
            debugLog('BETTING_CHANGED', { system: CONFIG.bettingSystem, description: desc });
            log(`Betting: ${BETTING_SYSTEMS[CONFIG.bettingSystem]?.name || CONFIG.bettingSystem}`);
        });
        
        // Strategy selector
        document.getElementById('bj-strategy').addEventListener('change', (e) => {
            CONFIG.strategy = e.target.value;
            const desc = STRATEGIES[CONFIG.strategy]?.description || '';
            document.getElementById('strategy-desc').textContent = desc;
            debugLog('STRATEGY_CHANGED', { strategy: CONFIG.strategy, description: desc });
            log(`Strategy: ${STRATEGIES[CONFIG.strategy]?.name || CONFIG.strategy}`);
        });
        
        // Profit target controls
        document.getElementById('bj-profit-target-enabled').addEventListener('change', (e) => {
            CONFIG.profitTargetEnabled = e.target.checked;
            debugLog('PROFIT_TARGET_TOGGLE', { enabled: CONFIG.profitTargetEnabled, target: CONFIG.profitTarget });
            if (CONFIG.profitTargetEnabled) {
                log(`Profit target enabled: ${CONFIG.profitTarget}`);
            } else {
                log('Profit target disabled');
            }
        });
        
        document.getElementById('bj-profit-target').addEventListener('change', (e) => {
            CONFIG.profitTarget = parseFloat(e.target.value) || 1.0;
            debugLog('PROFIT_TARGET_SET', { target: CONFIG.profitTarget });
            if (CONFIG.profitTargetEnabled) {
                log(`Profit target set to: ${CONFIG.profitTarget}`);
            }
        });

        document.getElementById('bj-balance-btn').addEventListener('click', async () => {
            try {
                const result = await getBalances();
                console.log('[BJ] Balance response:', JSON.stringify(result, null, 2));
                const balances = result?.data?.user?.balances;
                if (balances && Array.isArray(balances)) {
                    log('--- Balances ---');
                    balances.forEach(b => {
                        const amount = b.available?.amount || 0;
                        const currency = b.available?.currency || '';
                        if (parseFloat(amount) > 0) {
                            log(`${currency.toUpperCase()}: ${amount}`);
                        }
                    });
                } else {
                    log('Could not fetch balances - check console for response');
                }
            } catch (error) {
                log(`Error: ${error.message}`);
            }
        });

        document.getElementById('bj-debug-btn').addEventListener('click', () => {
            log('=== DEBUG INFO ===');
            const token = getAccessToken();
            if (token) {
                log(`Session token found: ${token.substring(0, 20)}...${token.substring(token.length - 10)}`);
            } else {
                log('ERROR: No session token found!');
            }
            const lockdown = getLockdownToken();
            if (lockdown) {
                log(`Lockdown token: ${lockdown}`);
            } else {
                log('No lockdown token found');
            }
            log('localStorage keys: ' + Object.keys(localStorage).join(', '));
            log('Check browser console (F12) for more details');
            console.log('[BJ DEBUG] Full localStorage:', {...localStorage});
            console.log('[BJ DEBUG] Full sessionStorage:', {...sessionStorage});
        });

        document.getElementById('bj-minimize').addEventListener('click', () => {
            const content = document.getElementById('bj-content');
            const btn = document.getElementById('bj-minimize');
            if (content.style.display === 'none') {
                content.style.display = 'block';
                btn.textContent = '−';
            } else {
                content.style.display = 'none';
                btn.textContent = '+';
            }
        });

        log('Blackjack Bot loaded');
        
        // Auto-check for token on load
        const token = getAccessToken();
        const hasToken = !!token;
        
        debugLog('INIT', {
            version: '1.2',
            hasToken,
            tokenPreview: token ? token.substring(0, 15) + '...' : null,
            url: window.location.href,
            userAgent: navigator.userAgent.substring(0, 100),
            config: { ...CONFIG }
        });
        
        if (hasToken) {
            log(`Session found: ${token.substring(0, 15)}...`);
        } else {
            log('WARNING: No session token detected - click Debug Token');
        }
        
        // Log help message
        console.log('[BJ] Debug commands available: bjDebug.getStats(), bjDebug.dumpState(), bjDebug.setDebugLevel(0|1|2)');
    }

    function updateUI() {
        document.getElementById('stat-hands').textContent = stats.hands;
        document.getElementById('stat-wins').textContent = stats.wins;
        document.getElementById('stat-losses').textContent = stats.losses;
        document.getElementById('stat-pushes').textContent = stats.pushes;
        document.getElementById('stat-bjs').textContent = stats.blackjacks;

        const profitEl = document.getElementById('stat-profit');
        profitEl.textContent = (stats.profit >= 0 ? '+' : '') + stats.profit.toFixed(8);
        profitEl.className = stats.profit >= 0 ? 'profit-positive' : 'profit-negative';
    }

    // Initialize
    function init() {
        // Wait for page to load
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', createUI);
        } else {
            setTimeout(createUI, 1000);
        }
    }

    init();
})();
