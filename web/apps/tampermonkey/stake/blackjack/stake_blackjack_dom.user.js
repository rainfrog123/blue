// ==UserScript==
// @name         Stake Blackjack DOM Automation
// @namespace    http://tampermonkey.net/
// @version      2.2
// @description  Automate blackjack on Stake.com using pure DOM observation (no API interception)
// @author       You
// @match        https://stake.com/casino/games/blackjack*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

/*
 * PURE DOM APPROACH:
 *   - Reads cards directly from DOM elements
 *   - Uses MutationObserver to detect game state changes
 *   - Clicks actual UI buttons for all actions
 *   - No API interception or fetch hooks
 *
 * DOM SELECTORS:
 *   Game status:    [data-testid="game-blackjack"][data-game-status]
 *   Player cards:   [data-testid="player"] .content.dealt .face-content span
 *   Dealer cards:   [data-testid="dealer"] .content.dealt .face-content span
 *   Hand values:    [data-testid="player"] .value, [data-testid="dealer"] .value
 *   Buttons:        [data-test-action="hit|stand|split|double"]
 *   Bet button:     [data-testid="bet-button"]
 *   Bet input:      [data-testid="input-game-amount"]
 *
 * Console Commands:
 *   bjDOM.getStats()        - Get statistics
 *   bjDOM.readState()       - Read current DOM state
 *   bjDOM.setStrategy(s)    - Change strategy
 *   bjDOM.dumpState()       - Full debug dump
 */

(function() {
    'use strict';

    // ============================================
    // CONFIGURATION
    // ============================================

    const CONFIG = {
        betAmount: 0.3,
        currency: 'usdt',
        delayBetweenHands: 2000,
        delayBetweenActions: 600,
        delayAfterBet: 1200,
        debugLevel: 2,
        strategy: 'basic',
        bettingSystem: 'flat',
        maxMartingaleBet: 100,
        takeInsurance: false // Basic strategy: always decline insurance
    };

    const STRATEGIES = {
        basic: { name: 'Basic Strategy', description: 'Optimal play for S17+DAS rules' },
        conservative: { name: 'Conservative', description: 'Stand earlier, minimize variance' },
        aggressive: { name: 'Aggressive', description: 'Double more, higher variance' },
        never_bust: { name: 'Never Bust', description: 'Stand on 12+ hard' },
        mimic_dealer: { name: 'Mimic Dealer', description: 'Stand on 17+' }
    };

    const BETTING_SYSTEMS = {
        flat: { name: 'Flat Betting', description: 'Same bet every hand' },
        martingale: { name: 'Martingale', description: 'Double after loss (risky!)' },
        fifthBalance: { name: '1/5 Balance', description: 'Bet 1/5 of current balance each hand' },
        fifthMartingale: { name: '1/5 + Martingale', description: 'Start 1/5 balance, double after loss' }
    };

    // ============================================
    // STATE
    // ============================================

    let currentBet = CONFIG.betAmount;
    let consecutiveLosses = 0;
    let fifthMartingaleBaseBet = 0; // Base bet for 1/5 + Martingale system
    let handNumber = 0;
    let isPlaying = false;
    let isHandInProgress = false;
    let actionInProgress = false;
    let lastGameStatus = 'none';
    let lastPlayerCards = [];
    let observer = null;

    let stats = {
        hands: 0,
        wins: 0,
        losses: 0,
        pushes: 0,
        blackjacks: 0,
        profit: 0,
        sessionStart: new Date().toISOString()
    };

    // ============================================
    // DOM READING FUNCTIONS
    // ============================================

    function getGameStatus() {
        const el = document.querySelector('[data-testid="game-blackjack"]');
        return el?.getAttribute('data-game-status') || 'none';
    }

    function getSuitFromIcon(iconEl) {
        if (!iconEl) return '?';
        const icon = iconEl.getAttribute('data-ds-icon') || '';
        if (icon.includes('Heart')) return 'h';
        if (icon.includes('Diamond')) return 'd';
        if (icon.includes('Club')) return 'c';
        if (icon.includes('Spade')) return 's';
        return '?';
    }

    function readCardsFromContainer(testId) {
        const container = document.querySelector(`[data-testid="${testId}"]`);
        if (!container) return [];

        const cards = [];
        const cardEls = container.querySelectorAll('.content.dealt');

        cardEls.forEach(cardEl => {
            // Check if card is face-down (hidden card)
            const cardContent = cardEl.querySelector('.content');
            if (cardContent?.classList.contains('face-down')) return;

            const faceContent = cardEl.querySelector('.face-content');
            if (!faceContent) return;

            const rankEl = faceContent.querySelector('span');
            const suitIcon = faceContent.querySelector('svg[data-ds-icon]');

            if (rankEl && rankEl.textContent.trim()) {
                const rank = rankEl.textContent.trim();
                const suit = getSuitFromIcon(suitIcon);
                cards.push({ rank, suit });
            }
        });

        return cards;
    }

    function readPlayerCards() {
        // Check for split hands - look for active hand first
        const activeHand = getActivePlayerHand();
        if (activeHand) {
            return readCardsFromElement(activeHand);
        }
        return readCardsFromContainer('player');
    }

    function readDealerCards() {
        return readCardsFromContainer('dealer');
    }

    // Handle split hands - find the currently active player hand
    // Split structure: [data-testid="player"] contains multiple .hand-wrap elements
    // Active hand has class="value active" on the value element
    function getActivePlayerHand() {
        const playerContainer = document.querySelector('[data-testid="player"]');
        if (!playerContainer) return null;

        // Look for multiple .hand-wrap elements (split scenario)
        const handWraps = playerContainer.querySelectorAll('.hand-wrap');

        if (handWraps.length <= 1) return null; // No split, single hand

        // Method 1: Find the hand with "active" class on value element (most reliable)
        for (const handWrap of handWraps) {
            const valueEl = handWrap.querySelector('.value');
            if (valueEl && valueEl.classList.contains('active')) {
                debugLog('ACTIVE_HAND_FOUND', { method: 'active_class', value: valueEl.textContent });
                return handWrap;
            }
        }

        // Method 2: Find hand with "active" class on face elements
        for (const handWrap of handWraps) {
            const faceEl = handWrap.querySelector('.face.active');
            if (faceEl) {
                debugLog('ACTIVE_HAND_FOUND', { method: 'face_active' });
                return handWrap;
            }
        }

        // Method 3: Find hand without win/lose/push/bust result (fallback)
        for (const handWrap of handWraps) {
            const valueEl = handWrap.querySelector('.value');
            if (valueEl &&
                !valueEl.classList.contains('win') &&
                !valueEl.classList.contains('lose') &&
                !valueEl.classList.contains('push') &&
                !valueEl.classList.contains('bust')) {
                debugLog('ACTIVE_HAND_FOUND', { method: 'no_result' });
                return handWrap;
            }
        }

        // All hands completed, return null
        return null;
    }

    function readCardsFromElement(container) {
        if (!container) return [];

        const cards = [];
        const cardEls = container.querySelectorAll('.content.dealt');

        cardEls.forEach(cardEl => {
            // Check for face-down cards
            const faceEl = cardEl.querySelector('.face');
            if (faceEl?.classList.contains('face-down')) return;

            const faceContent = cardEl.querySelector('.face-content');
            if (!faceContent) return;

            const rankEl = faceContent.querySelector('span');
            const suitIcon = faceContent.querySelector('svg[data-ds-icon]');

            if (rankEl && rankEl.textContent.trim()) {
                const rank = rankEl.textContent.trim();
                const suit = getSuitFromIcon(suitIcon);
                cards.push({ rank, suit });
            }
        });

        return cards;
    }

    function isSplitGame() {
        const playerContainer = document.querySelector('[data-testid="player"]');
        if (!playerContainer) return false;
        return playerContainer.querySelectorAll('.hand-wrap').length > 1;
    }

    function getSplitHandCount() {
        const playerContainer = document.querySelector('[data-testid="player"]');
        if (!playerContainer) return 1;
        const handWraps = playerContainer.querySelectorAll('.hand-wrap');
        return handWraps.length || 1;
    }

    function getSplitResults() {
        const playerContainer = document.querySelector('[data-testid="player"]');
        if (!playerContainer) return [];

        const results = [];
        const handWraps = playerContainer.querySelectorAll('.hand-wrap');

        handWraps.forEach((handWrap, index) => {
            const valueEl = handWrap.querySelector('.value');
            let result = 'pending';
            if (valueEl) {
                if (valueEl.classList.contains('win')) result = 'win';
                else if (valueEl.classList.contains('lose')) result = 'lose';
                else if (valueEl.classList.contains('push')) result = 'push';
                else if (valueEl.classList.contains('bust')) result = 'bust';
            }
            results.push({ hand: index + 1, result, value: valueEl?.textContent?.trim() });
        });

        return results;
    }

    function readHandValue(testId) {
        const el = document.querySelector(`[data-testid="${testId}"] .value`);
        if (!el) return null;
        const text = el.textContent.trim();
        // Handle soft hands like "8, 18" - take the higher value
        if (text.includes(',')) {
            const parts = text.split(',').map(p => parseInt(p.trim()));
            return Math.max(...parts);
        }
        return parseInt(text) || null;
    }

    function isButtonEnabled(action) {
        const btn = document.querySelector(`[data-test-action="${action}"]`);
        if (!btn) return false;
        if (btn.disabled) return false;
        const enabled = btn.getAttribute('data-test-action-enabled');
        return enabled === 'true';
    }

    function isBetEnabled() {
        const btn = document.querySelector('[data-testid="bet-button"]');
        if (!btn) return false;
        if (btn.disabled) return false;
        const enabled = btn.getAttribute('data-test-action-enabled');
        return enabled === 'true' || enabled !== 'false';
    }

    function getAvailableActions() {
        return {
            hit: isButtonEnabled('hit'),
            stand: isButtonEnabled('stand'),
            double: isButtonEnabled('double'),
            split: isButtonEnabled('split'),
            insurance: isButtonEnabled('insurance'),
            noInsurance: isButtonEnabled('noInsurance'),
            bet: isBetEnabled()
        };
    }

    function isInsuranceOffered() {
        const actions = getAvailableActions();
        return actions.insurance || actions.noInsurance;
    }

    function getResultClass() {
        const valueEl = document.querySelector('[data-testid="player"] .value');
        if (!valueEl) return null;
        if (valueEl.classList.contains('win')) return 'win';
        if (valueEl.classList.contains('lose')) return 'lose';
        if (valueEl.classList.contains('push') || valueEl.classList.contains('draw')) return 'push';
        return null;
    }

    // ============================================
    // UI INTERACTION
    // ============================================

    function clickButton(selector) {
        return new Promise((resolve, reject) => {
            const btn = document.querySelector(selector);
            if (!btn) {
                reject(new Error(`Button not found: ${selector}`));
                return;
            }
            if (btn.disabled) {
                reject(new Error(`Button disabled: ${selector}`));
                return;
            }

            debugLog('CLICK', { selector, text: btn.textContent?.trim()?.substring(0, 20) });
            btn.click();
            resolve(true);
        });
    }

    function clickAction(action) {
        return clickButton(`[data-test-action="${action}"]`);
    }

    function setBetAmount(amount) {
        return new Promise((resolve) => {
            const input = document.querySelector('[data-testid="input-game-amount"]');
            if (!input) {
                debugLog('BET_INPUT_NOT_FOUND');
                resolve(false);
                return;
            }

            // Check if input is disabled (game in progress)
            if (input.disabled) {
                debugLog('BET_INPUT_DISABLED');
                resolve(false);
                return;
            }

            input.focus();

            // Use native setter for Svelte reactivity
            const nativeSetter = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value'
            ).set;
            nativeSetter.call(input, amount.toString());

            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.dispatchEvent(new Event('change', { bubbles: true }));

            debugLog('BET_SET', { amount });
            resolve(true);
        });
    }

    // ============================================
    // HAND VALUE & STRATEGY
    // ============================================

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
                value += parseInt(rank) || 0;
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

    function getDealerValue(dealerUpcard) {
        const rank = dealerUpcard.rank || dealerUpcard;
        if (['J', 'Q', 'K', '10'].includes(rank)) return 10;
        if (rank === 'A') return 11;
        return parseInt(rank) || 0;
    }

    function getAction(playerCards, dealerUpcard, canDouble, canSplit) {
        switch (CONFIG.strategy) {
            case 'conservative':
                return strategyConservative(playerCards, dealerUpcard, canDouble, canSplit);
            case 'aggressive':
                return strategyAggressive(playerCards, dealerUpcard, canDouble, canSplit);
            case 'never_bust':
                return strategyNeverBust(playerCards, dealerUpcard, canDouble, canSplit);
            case 'mimic_dealer':
                return strategyMimicDealer(playerCards, dealerUpcard, canDouble, canSplit);
            default:
                return strategyBasic(playerCards, dealerUpcard, canDouble, canSplit);
        }
    }

    function strategyBasic(playerCards, dealerUpcard, canDouble, canSplit) {
        const { value: playerValue, soft } = calculateHandValue(playerCards);
        const dealerValue = getDealerValue(dealerUpcard);

        // Pairs
        if (playerCards.length === 2 && canSplit) {
            const rank1 = playerCards[0].rank;
            const rank2 = playerCards[1].rank;
            if (rank1 === rank2) {
                if (rank1 === 'A' || rank1 === '8') return 'split';
                if (rank1 === '9' && ![7, 10, 11].includes(dealerValue)) return 'split';
                if (rank1 === '7' && dealerValue <= 7) return 'split';
                if (rank1 === '6' && dealerValue <= 6) return 'split';
                if (['2', '3'].includes(rank1) && dealerValue <= 7) return 'split';
                if (rank1 === '4' && [5, 6].includes(dealerValue)) return 'split';
            }
        }

        // Soft hands
        if (soft) {
            if (playerValue >= 19) return 'stand';
            if (playerValue === 18) {
                if (dealerValue >= 9) return 'hit';
                if ([3,4,5,6].includes(dealerValue) && canDouble && playerCards.length === 2) return 'double';
                return 'stand';
            }
            if (playerValue === 17) {
                if ([3,4,5,6].includes(dealerValue) && canDouble && playerCards.length === 2) return 'double';
                return 'hit';
            }
            if ([15, 16].includes(playerValue)) {
                if ([4,5,6].includes(dealerValue) && canDouble && playerCards.length === 2) return 'double';
                return 'hit';
            }
            if ([13, 14].includes(playerValue)) {
                if ([5,6].includes(dealerValue) && canDouble && playerCards.length === 2) return 'double';
                return 'hit';
            }
            return 'hit';
        }

        // Hard hands
        if (playerValue >= 17) return 'stand';
        if (playerValue >= 13 && playerValue <= 16) return dealerValue <= 6 ? 'stand' : 'hit';
        if (playerValue === 12) return [4,5,6].includes(dealerValue) ? 'stand' : 'hit';
        if (playerValue === 11) return (canDouble && playerCards.length === 2) ? 'double' : 'hit';
        if (playerValue === 10) return (dealerValue <= 9 && canDouble && playerCards.length === 2) ? 'double' : 'hit';
        if (playerValue === 9) return ([3,4,5,6].includes(dealerValue) && canDouble && playerCards.length === 2) ? 'double' : 'hit';
        return 'hit';
    }

    function strategyConservative(playerCards, dealerUpcard, canDouble, canSplit) {
        const { value: playerValue, soft } = calculateHandValue(playerCards);
        const dealerValue = getDealerValue(dealerUpcard);

        if (playerCards.length === 2 && canSplit) {
            const rank1 = playerCards[0].rank;
            const rank2 = playerCards[1].rank;
            if (rank1 === rank2 && ['A', '8'].includes(rank1)) return 'split';
        }

        if (soft) {
            if (playerValue >= 18) return 'stand';
            if (playerValue === 17 && dealerValue <= 6) return 'stand';
            return 'hit';
        }

        if (playerValue >= 15) return 'stand';
        if (playerValue >= 12 && dealerValue <= 6) return 'stand';
        if (playerValue === 11 && canDouble && playerCards.length === 2 && dealerValue <= 9) return 'double';
        return 'hit';
    }

    function strategyAggressive(playerCards, dealerUpcard, canDouble, canSplit) {
        const { value: playerValue, soft } = calculateHandValue(playerCards);
        const dealerValue = getDealerValue(dealerUpcard);

        if (playerCards.length === 2 && canSplit) {
            const rank1 = playerCards[0].rank;
            const rank2 = playerCards[1].rank;
            if (rank1 === rank2) {
                if (['A', '8'].includes(rank1)) return 'split';
                if (rank1 === '9' && dealerValue !== 7) return 'split';
                if (['7','6','3','2'].includes(rank1) && dealerValue <= 8) return 'split';
            }
        }

        if (soft) {
            if (playerValue >= 19) return 'stand';
            if (playerValue === 18) {
                if (dealerValue <= 6 && canDouble && playerCards.length === 2) return 'double';
                return dealerValue >= 9 ? 'hit' : 'stand';
            }
            if (playerValue >= 13 && [3,4,5,6].includes(dealerValue) && canDouble && playerCards.length === 2) {
                return 'double';
            }
            return 'hit';
        }

        if (playerValue >= 17) return 'stand';
        if (canDouble && playerCards.length === 2) {
            if (playerValue === 11) return 'double';
            if (playerValue === 10 && dealerValue <= 9) return 'double';
            if (playerValue === 9 && dealerValue <= 6) return 'double';
        }
        if (playerValue >= 13) return dealerValue <= 6 ? 'stand' : 'hit';
        if (playerValue === 12) return [4,5,6].includes(dealerValue) ? 'stand' : 'hit';
        return 'hit';
    }

    function strategyNeverBust(playerCards, dealerUpcard, canDouble, canSplit) {
        const { value: playerValue, soft } = calculateHandValue(playerCards);

        if (playerCards.length === 2 && canSplit) {
            const rank1 = playerCards[0].rank;
            const rank2 = playerCards[1].rank;
            if (rank1 === rank2 && (rank1 === 'A' || rank1 === '8')) return 'split';
        }

        if (soft) {
            if (playerValue >= 18) return 'stand';
            return 'hit';
        }

        if (playerValue >= 12) return 'stand';
        if (playerValue === 11 && canDouble && playerCards.length === 2) return 'double';
        return 'hit';
    }

    function strategyMimicDealer(playerCards, dealerUpcard, canDouble, canSplit) {
        const { value: playerValue } = calculateHandValue(playerCards);
        if (playerValue >= 17) return 'stand';
        return 'hit';
    }

    // ============================================
    // GAME LOGIC
    // ============================================

    let gameLoopInterval = null;
    let handEndedAt = 0;

    async function handleGameState() {
        if (actionInProgress) return;

        const status = getGameStatus();
        const actions = getAvailableActions();
        const playerCards = readPlayerCards();
        const dealerCards = readDealerCards();

        debugLog('STATE_CHECK', {
            status,
            actions,
            isPlaying,
            isHandInProgress,
            lastGameStatus,
            playerCards: playerCards.map(c => c.rank + c.suit),
            dealerCards: dealerCards.map(c => c.rank + c.suit)
        });

        // Handle game completion (win/lose/draw) - status can be "win,lose" for splits
        const statusParts = status.split(',').map(s => s.trim());
        const endStatuses = ['win', 'lose', 'draw', 'push', 'blackjack', 'bust'];
        const isGameEnd = statusParts.some(s => endStatuses.includes(s));
        const isSplit = statusParts.length > 1;

        if (isGameEnd && isHandInProgress && status !== lastGameStatus) {
            handleGameEnd(status, isSplit);
            lastGameStatus = status;
            handEndedAt = Date.now();
            // Don't return - check if we should start next hand
        }

        // Handle insurance offer (dealer shows Ace)
        if ((actions.insurance || actions.noInsurance) && !actionInProgress && isHandInProgress) {
            actionInProgress = true;
            const takeInsurance = CONFIG.takeInsurance || false;
            const action = takeInsurance ? 'insurance' : 'noInsurance';
            log(`Insurance offered - ${takeInsurance ? 'ACCEPTING (not recommended!)' : 'DECLINING'}`);
            debugLog('INSURANCE', { takeInsurance, action });

            await sleep(CONFIG.delayBetweenActions);
            try {
                await clickAction(action);
            } catch (e) {
                debugLog('INSURANCE_ERROR', { error: e.message });
            }
            await sleep(300);
            actionInProgress = false;
            return;
        }

        // Handle active game - need to take action (hit/stand/double/split)
        if ((actions.hit || actions.stand) && !actionInProgress && isHandInProgress) {
            if (playerCards.length >= 2 && dealerCards.length >= 1) {
                const cardsKey = playerCards.map(c => c.rank).join('');
                if (cardsKey !== lastPlayerCards.join('')) {
                    lastPlayerCards = playerCards.map(c => c.rank);
                    await takeStrategyAction(playerCards, dealerCards, actions);
                }
            }
            return;
        }

        // Handle bet phase - start next hand if auto-playing
        if (actions.bet && !isHandInProgress && isPlaying) {
            // Wait a bit after hand ends before starting next
            const timeSinceEnd = Date.now() - handEndedAt;
            if (timeSinceEnd < CONFIG.delayBetweenHands) {
                debugLog('WAITING', { timeSinceEnd, delay: CONFIG.delayBetweenHands });
                return;
            }

            debugLog('STARTING_NEXT_HAND', { status, timeSinceEnd });
            lastGameStatus = 'none';
            lastPlayerCards = [];
            await startNewHand();
        }
    }

    function startGameLoop() {
        stopGameLoop();
        // Poll every 500ms as backup for MutationObserver
        gameLoopInterval = setInterval(() => {
            if (isPlaying || isHandInProgress) {
                handleGameState();
            }
        }, 500);
        debugLog('GAME_LOOP_STARTED');
    }

    function stopGameLoop() {
        if (gameLoopInterval) {
            clearInterval(gameLoopInterval);
            gameLoopInterval = null;
        }
    }

    async function takeStrategyAction(playerCards, dealerCards, actions) {
        actionInProgress = true;

        const { value: playerValue, soft } = calculateHandValue(playerCards);
        const dealerUpcard = dealerCards[0];

        // Log split info if in split game
        const splitInfo = isSplitGame() ? ` [Split: Hand ${getSplitHandCount()}]` : '';
        log(`Player: ${formatCards(playerCards)} (${playerValue}${soft ? 'S' : ''}) | Dealer: ${formatCards([dealerUpcard])}${splitInfo}`);

        let action = getAction(playerCards, dealerUpcard, actions.double, actions.split);

        // Validate action is available
        if (action === 'double' && !actions.double) action = 'hit';
        if (action === 'split' && !actions.split) action = 'hit';
        if (action === 'hit' && !actions.hit) action = 'stand';

        debugLog('ACTION', {
            strategy: CONFIG.strategy,
            action,
            playerValue,
            soft,
            dealerUpcard: dealerUpcard.rank,
            isSplit: isSplitGame(),
            splitHands: getSplitHandCount()
        });

        log(`[${STRATEGIES[CONFIG.strategy]?.name}] ${action.toUpperCase()}`);

        await sleep(CONFIG.delayBetweenActions);

        try {
            await clickAction(action);

            // After split, reset card tracking and wait longer for UI update
            if (action === 'split') {
                lastPlayerCards = [];
                log('Split! Playing first hand...');
                await sleep(800); // Extra delay for split animation
            }
        } catch (e) {
            if (action !== 'stand' && actions.stand) {
                log('Action failed, trying STAND');
                await clickAction('stand');
            }
        }

        await sleep(300);
        actionInProgress = false;
    }

    function handleGameEnd(status, isSplit = false) {
        if (!isHandInProgress) return;

        const dealerValue = readHandValue('dealer');

        let profit = 0;
        let resultSummary = '';

        if (isSplit) {
            // Handle split results - status is like "win,lose"
            const splitResults = getSplitResults();
            const betPerHand = currentBet; // Each split hand has the same bet

            let wins = 0, losses = 0, pushes = 0;

            splitResults.forEach((hand, idx) => {
                if (hand.result === 'win' || hand.result === 'blackjack') {
                    profit += betPerHand;
                    wins++;
                } else if (hand.result === 'lose' || hand.result === 'bust') {
                    profit -= betPerHand;
                    losses++;
                } else if (hand.result === 'push') {
                    pushes++;
                }
                log(`  Hand ${idx + 1}: ${hand.result.toUpperCase()} (${hand.value})`);
            });

            resultSummary = `SPLIT: ${wins}W/${losses}L/${pushes}P`;

            debugLog('HAND_END_SPLIT', {
                status,
                splitResults,
                profit,
                dealerValue,
                bet: currentBet,
                isPlaying
            });

            log(`Result: ${resultSummary} | D:${dealerValue} | ${profit >= 0 ? '+' : ''}${profit.toFixed(4)}`);

            // For martingale: split counts as win if net positive, loss if net negative
            const netResult = profit > 0 ? 'win' : (profit < 0 ? 'lose' : 'push');
            updateStats(netResult, profit);

        } else {
            // Normal single hand
            const playerValue = readHandValue('player');
            const resultClass = getResultClass();

            let result = status;
            if (resultClass) result = resultClass;

            // Calculate profit
            if (result === 'win' || result === 'blackjack') {
                profit = result === 'blackjack' ? currentBet * 1.5 : currentBet;
            } else if (result === 'lose' || result === 'bust') {
                profit = -currentBet;
            }
            // push = 0

            debugLog('HAND_END', {
                result,
                profit,
                playerValue,
                dealerValue,
                bet: currentBet,
                isPlaying
            });

            log(`Result: ${result.toUpperCase()} | P:${playerValue} D:${dealerValue} | ${profit >= 0 ? '+' : ''}${profit.toFixed(4)}`);

            updateStats(result, profit);
        }

        isHandInProgress = false;
        actionInProgress = false;

        // If auto-playing, log that next hand will start soon
        if (isPlaying) {
            log(`Next hand in ${CONFIG.delayBetweenHands/1000}s...`);
        } else {
            // Single hand mode - stop the loops
            stopObserver();
            stopGameLoop();
            log('Hand complete. Click "Play 1" for another hand.');
        }
    }

    async function startNewHand() {
        if (isHandInProgress) return;

        isHandInProgress = true;
        handNumber++;
        lastPlayerCards = [];

        const balance = getBalance();
        let betToUse;

        if (CONFIG.bettingSystem === 'martingale') {
            betToUse = currentBet;
        } else if (CONFIG.bettingSystem === 'fifthBalance') {
            if (balance !== null && balance > 0) {
                betToUse = Math.floor((balance / 5) * 100000000) / 100000000; // Round to 8 decimals
                betToUse = Math.max(betToUse, 0.00000001); // Minimum bet
                currentBet = betToUse;
                updateBetDisplay();
            } else {
                betToUse = CONFIG.betAmount;
            }
        } else if (CONFIG.bettingSystem === 'fifthMartingale') {
            if (consecutiveLosses === 0) {
                // First hand or after win: calculate 1/5 of balance
                if (balance !== null && balance > 0) {
                    fifthMartingaleBaseBet = Math.floor((balance / 5) * 100000000) / 100000000;
                    fifthMartingaleBaseBet = Math.max(fifthMartingaleBaseBet, 0.00000001);
                    currentBet = fifthMartingaleBaseBet;
                } else {
                    currentBet = CONFIG.betAmount;
                    fifthMartingaleBaseBet = CONFIG.betAmount;
                }
            }
            // Use currentBet (which may have been doubled after loss)
            betToUse = currentBet;
            updateBetDisplay();
        } else {
            betToUse = CONFIG.betAmount;
        }

        // Check for insufficient balance before betting
        if (hasInsufficientBalanceError(betToUse)) {
            debugLog('INSUFFICIENT_BALANCE', {
                balance,
                currentBet: betToUse,
                baseBet: CONFIG.betAmount,
                consecutiveLosses
            });

            // For 1/5 balance systems, recalculate based on actual balance
            if ((CONFIG.bettingSystem === 'fifthBalance' || CONFIG.bettingSystem === 'fifthMartingale') && balance !== null && balance > 0) {
                betToUse = Math.floor((balance / 5) * 100000000) / 100000000;
                betToUse = Math.max(betToUse, 0.00000001);
                currentBet = betToUse;
                consecutiveLosses = 0;
                fifthMartingaleBaseBet = betToUse;
                log(`INSUFFICIENT: Recalculating 1/5 of ${balance.toFixed(4)} = ${betToUse.toFixed(8)}`);
                updateBetDisplay();
            } else {
                log(`INSUFFICIENT BALANCE: ${betToUse.toFixed(4)} > ${balance?.toFixed(4) || '?'}, resetting to ${CONFIG.betAmount}`);
                // Reset to base bet
                currentBet = CONFIG.betAmount;
                consecutiveLosses = 0;
                betToUse = CONFIG.betAmount;
                updateBetDisplay();

                // Check if we can even afford base bet
                if (hasInsufficientBalanceError(betToUse)) {
                    log(`Cannot afford base bet ${betToUse.toFixed(4)}. Stopping.`);
                    isHandInProgress = false;
                    if (isPlaying) stopAutoPlay();
                    return;
                }
            }
        }

        debugLog('HAND_START', { handNumber, bet: betToUse, balance });
        log(`--- Hand #${handNumber} | Bet: ${betToUse} | Bal: ${balance?.toFixed(4) || '?'} ---`);

        try {
            await setBetAmount(betToUse);
            await sleep(200);

            // Check again after setting bet amount (in case balance changed)
            if (hasInsufficientBalanceError(betToUse)) {
                const currentBalance = getBalance();
                // For 1/5 systems, try recalculating with current balance
                if ((CONFIG.bettingSystem === 'fifthBalance' || CONFIG.bettingSystem === 'fifthMartingale') && currentBalance !== null && currentBalance > 0) {
                    betToUse = Math.floor((currentBalance / 5) * 100000000) / 100000000;
                    betToUse = Math.max(betToUse, 0.00000001);
                    currentBet = betToUse;
                    await setBetAmount(betToUse);
                    await sleep(200);
                }
                // Final check
                if (hasInsufficientBalanceError(betToUse)) {
                    debugLog('STILL_INSUFFICIENT', { bet: betToUse, balance: currentBalance });
                    log(`Still insufficient balance for ${betToUse.toFixed(8)}. Stopping.`);
                    isHandInProgress = false;
                    if (isPlaying) {
                        stopAutoPlay();
                    }
                    return;
                }
            }

            await clickButton('[data-testid="bet-button"]');
            await sleep(CONFIG.delayAfterBet);
        } catch (e) {
            debugLog('HAND_ERROR', { error: e.message });
            log(`Error: ${e.message}`);
            isHandInProgress = false;

            // If bet failed, might be insufficient balance - reset betting system
            if (hasInsufficientBalanceError()) {
                if (CONFIG.bettingSystem === 'martingale') {
                    log('Bet failed - resetting martingale');
                    currentBet = CONFIG.betAmount;
                    consecutiveLosses = 0;
                } else if (CONFIG.bettingSystem === 'fifthMartingale' || CONFIG.bettingSystem === 'fifthBalance') {
                    log('Bet failed - will recalculate 1/5 balance next hand');
                    consecutiveLosses = 0;
                    fifthMartingaleBaseBet = 0;
                }
                updateBetDisplay();
            }
        }
    }

    function getBalance() {
        // Read balance from the coin toggle button
        const coinToggle = document.querySelector('[data-testid="coin-toggle"]');
        if (coinToggle) {
            // Get the balance text (like "1.19000000")
            const balanceSpan = coinToggle.querySelector('[data-ds-text="true"] span[data-ds-text="true"]');
            if (balanceSpan) {
                const balanceText = balanceSpan.textContent.trim();
                const balance = parseFloat(balanceText);
                if (!isNaN(balance)) {
                    return balance;
                }
            }

            // Fallback: look for any number in the button text
            const text = coinToggle.textContent;
            const match = text.match(/(\d+\.?\d*)/);
            if (match) {
                return parseFloat(match[1]);
            }
        }
        return null;
    }

    function hasInsufficientBalanceError(betAmount = null) {
        const bet = betAmount || currentBet;

        // Method 1: Compare balance to bet amount
        const balance = getBalance();
        if (balance !== null && bet > balance) {
            debugLog('BALANCE_CHECK', { balance, bet, insufficient: true });
            return true;
        }

        // Method 2: Check for error messages in the UI
        const sidebar = document.querySelector('.game-sidebar');
        if (sidebar) {
            const text = sidebar.textContent.toLowerCase();
            if (text.includes("can't bet more") || text.includes('insufficient') || text.includes('more than your balance')) {
                return true;
            }
        }

        // Method 3: Check for any error/warning elements
        const errorEl = document.querySelector('[class*="error"], [class*="warning"]');
        if (errorEl && errorEl.textContent.toLowerCase().includes('balance')) {
            return true;
        }

        return false;
    }

    // ============================================
    // MUTATION OBSERVER
    // ============================================

    function startObserver() {
        if (observer) return;

        const gameContainer = document.querySelector('[data-testid="game-blackjack"]') ||
                              document.querySelector('[data-testid="game-frame"]') ||
                              document.body;

        observer = new MutationObserver((mutations) => {
            // Debounce - only process once per batch
            clearTimeout(observer._timeout);
            observer._timeout = setTimeout(() => {
                if (isPlaying || isHandInProgress) {
                    handleGameState();
                }
            }, 100);
        });

        observer.observe(gameContainer, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['data-game-status', 'data-test-action-enabled', 'disabled', 'class']
        });

        debugLog('OBSERVER_STARTED');
    }

    function stopObserver() {
        if (observer) {
            observer.disconnect();
            observer = null;
            debugLog('OBSERVER_STOPPED');
        }
    }

    // ============================================
    // CONTROL FUNCTIONS
    // ============================================

    function startAutoPlay() {
        if (isPlaying) return;

        isPlaying = true;
        lastGameStatus = 'none';
        lastPlayerCards = [];
        handEndedAt = 0;

        debugLog('AUTOPLAY_START', { config: CONFIG });
        log('Auto-play started');

        const btn = document.getElementById('bjdom-play-btn');
        if (btn) btn.textContent = 'Stop';

        startObserver();
        startGameLoop();  // Start polling loop
        handleGameState(); // Initial check
    }

    function stopAutoPlay() {
        isPlaying = false;
        isHandInProgress = false;
        actionInProgress = false;
        // Reset betting systems on stop
        currentBet = CONFIG.betAmount;
        consecutiveLosses = 0;
        fifthMartingaleBaseBet = 0;
        updateBetDisplay();
        stopObserver();
        stopGameLoop();  // Stop polling loop

        debugLog('AUTOPLAY_STOP', { stats });
        log('Auto-play stopped');

        const btn = document.getElementById('bjdom-play-btn');
        if (btn) btn.textContent = 'Start Auto-Play';
    }

    async function playSingleHand() {
        if (isPlaying || isHandInProgress) {
            log('Cannot play - already in progress');
            return;
        }

        const actions = getAvailableActions();

        // Check if game needs action (resume existing hand)
        if (actions.hit || actions.stand) {
            log('Resuming active game...');
            isHandInProgress = true;
            lastPlayerCards = [];
            startObserver();
            startGameLoop();
            await handleGameState();
            return;
        }

        if (!actions.bet) {
            log('Cannot bet right now');
            return;
        }

        // Play single hand - NOT auto-play mode
        isPlaying = false;  // Ensure auto-play is off
        lastPlayerCards = [];
        lastGameStatus = 'none';
        handEndedAt = 0;
        startObserver();
        startGameLoop();
        await startNewHand();  // This sets isHandInProgress = true
    }

    async function resumeGame() {
        const actions = getAvailableActions();
        if (actions.hit || actions.stand) {
            log('Resuming game...');
            isHandInProgress = true;
            lastPlayerCards = [];
            startObserver();
            startGameLoop();
            await handleGameState();
        } else {
            log('No active game to resume');
        }
    }

    // ============================================
    // STATS & HELPERS
    // ============================================

    function updateStats(result, profit) {
        stats.hands++;
        stats.profit += profit;

        if (result === 'win' || result === 'blackjack') {
            stats.wins++;
            if (result === 'blackjack') stats.blackjacks++;
        } else if (result === 'lose' || result === 'bust') {
            stats.losses++;
        } else if (result === 'push' || result === 'draw') {
            stats.pushes++;
        }

        // Martingale betting system adjustment
        if (CONFIG.bettingSystem === 'martingale') {
            if (result === 'lose' || result === 'bust') {
                consecutiveLosses++;
                const nextBet = currentBet * 2;
                if (nextBet <= CONFIG.maxMartingaleBet) {
                    currentBet = nextBet;
                    debugLog('MARTINGALE', { action: 'double', nextBet: currentBet, consecutiveLosses });
                    log(`Martingale: Doubling bet to ${currentBet.toFixed(4)} (${consecutiveLosses} losses)`);
                } else {
                    currentBet = CONFIG.betAmount;
                    consecutiveLosses = 0;
                    debugLog('MARTINGALE', { action: 'reset_max', reason: 'exceeded max bet', maxBet: CONFIG.maxMartingaleBet });
                    log(`Martingale: Hit max bet limit, resetting to ${currentBet.toFixed(4)}`);
                }
            } else if (result === 'win' || result === 'blackjack') {
                currentBet = CONFIG.betAmount;
                consecutiveLosses = 0;
                debugLog('MARTINGALE', { action: 'reset_win', nextBet: currentBet });
                log(`Martingale: Win! Resetting bet to ${currentBet.toFixed(4)}`);
            }
            // Push: keep same bet
            updateBetDisplay();
        }

        // 1/5 Balance + Martingale betting system adjustment
        if (CONFIG.bettingSystem === 'fifthMartingale') {
            if (result === 'lose' || result === 'bust') {
                consecutiveLosses++;
                const nextBet = currentBet * 2;
                if (nextBet <= CONFIG.maxMartingaleBet) {
                    currentBet = nextBet;
                    debugLog('FIFTH_MARTINGALE', { action: 'double', nextBet: currentBet, consecutiveLosses, baseBet: fifthMartingaleBaseBet });
                    log(`1/5+Martingale: Doubling to ${currentBet.toFixed(4)} (${consecutiveLosses} losses)`);
                } else {
                    // Hit max, reset to current 1/5 balance
                    const balance = getBalance();
                    if (balance !== null && balance > 0) {
                        fifthMartingaleBaseBet = Math.floor((balance / 5) * 100000000) / 100000000;
                        currentBet = fifthMartingaleBaseBet;
                    } else {
                        currentBet = CONFIG.betAmount;
                    }
                    consecutiveLosses = 0;
                    debugLog('FIFTH_MARTINGALE', { action: 'reset_max', reason: 'exceeded max bet', newBase: currentBet });
                    log(`1/5+Martingale: Hit max, resetting to 1/5 balance: ${currentBet.toFixed(4)}`);
                }
            } else if (result === 'win' || result === 'blackjack') {
                // Win: reset to 1/5 of current balance
                consecutiveLosses = 0;
                debugLog('FIFTH_MARTINGALE', { action: 'reset_win', prevBet: currentBet });
                log(`1/5+Martingale: Win! Will recalculate 1/5 balance next hand`);
            }
            // Push: keep same bet
            updateBetDisplay();
        }

        updateUI();
    }

    function formatCards(cards) {
        return cards.map(c => `${c.rank}${c.suit || ''}`).join(' ');
    }

    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    function debugLog(type, data = {}) {
        if (CONFIG.debugLevel < 1) return;
        console.log(`[BJDOM:${type}]`, JSON.stringify({ t: Date.now(), hand: handNumber, ...data }));
    }

    function log(message) {
        const time = new Date().toLocaleTimeString();
        console.log(`[BlackjackDOM] ${time}: ${message}`);

        const logDiv = document.getElementById('bjdom-log');
        if (logDiv) {
            const entry = document.createElement('div');
            entry.textContent = `${time}: ${message}`;
            logDiv.insertBefore(entry, logDiv.firstChild);
            while (logDiv.children.length > 50) {
                logDiv.removeChild(logDiv.lastChild);
            }
        }
    }

    // ============================================
    // UI PANEL
    // ============================================

    function createUI() {
        const panel = document.createElement('div');
        panel.id = 'bjdom-panel';
        panel.innerHTML = `
            <style>
                #bjdom-panel {
                    position: fixed;
                    top: 80px;
                    right: 10px;
                    width: 280px;
                    background: linear-gradient(135deg, #1e3a5f 0%, #0d1b2a 100%);
                    border: 2px solid #3d5a80;
                    border-radius: 12px;
                    padding: 15px;
                    z-index: 99999;
                    font-family: 'Segoe UI', Arial, sans-serif;
                    color: #e0e1dd;
                    font-size: 13px;
                    box-shadow: 0 8px 32px rgba(0,0,0,0.7);
                }
                #bjdom-panel h3 {
                    margin: 0 0 12px 0;
                    color: #98c1d9;
                    font-size: 16px;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }
                #bjdom-panel .badge {
                    background: #ee6c4d;
                    color: #fff;
                    padding: 2px 8px;
                    border-radius: 4px;
                    font-size: 10px;
                    font-weight: bold;
                }
                #bjdom-panel .row {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin: 6px 0;
                }
                #bjdom-panel input, #bjdom-panel select {
                    background: #293241;
                    border: 1px solid #3d5a80;
                    color: #e0e1dd;
                    padding: 6px 10px;
                    border-radius: 6px;
                    width: 110px;
                }
                #bjdom-panel button {
                    background: linear-gradient(135deg, #98c1d9 0%, #3d5a80 100%);
                    color: #0d1b2a;
                    border: none;
                    padding: 10px 14px;
                    border-radius: 6px;
                    cursor: pointer;
                    font-weight: bold;
                    margin: 4px 4px 4px 0;
                    transition: all 0.15s;
                }
                #bjdom-panel button:hover {
                    transform: translateY(-1px);
                    box-shadow: 0 4px 12px rgba(152, 193, 217, 0.3);
                }
                #bjdom-panel button.secondary {
                    background: linear-gradient(135deg, #3d5a80 0%, #293241 100%);
                    color: #e0e1dd;
                }
                #bjdom-panel .stats {
                    background: rgba(0,0,0,0.3);
                    padding: 10px;
                    border-radius: 8px;
                    margin: 10px 0;
                }
                #bjdom-panel .profit-positive { color: #52b788; font-weight: bold; }
                #bjdom-panel .profit-negative { color: #e63946; font-weight: bold; }
                #bjdom-log {
                    max-height: 100px;
                    overflow-y: auto;
                    background: rgba(0,0,0,0.4);
                    padding: 8px;
                    border-radius: 6px;
                    font-size: 10px;
                    margin-top: 10px;
                }
                #bjdom-log div {
                    padding: 2px 0;
                    border-bottom: 1px solid rgba(255,255,255,0.1);
                }
                #bjdom-panel .minimize {
                    position: absolute;
                    top: 10px;
                    right: 15px;
                    cursor: pointer;
                    font-size: 20px;
                    opacity: 0.7;
                }
                .desc { font-size: 9px; color: #778da9; margin: 2px 0 6px 0; font-style: italic; }
            </style>
            <span class="minimize" id="bjdom-minimize">−</span>
            <h3>🎴 BJ DOM Bot <span class="badge">DOM-ONLY</span></h3>
            <div id="bjdom-content">
                <div class="row">
                    <label>Bet:</label>
                    <input type="number" id="bjdom-bet" value="${CONFIG.betAmount}" step="0.01" min="0.01">
                </div>
                <div class="row">
                    <label>Strategy:</label>
                    <select id="bjdom-strategy">
                        ${Object.entries(STRATEGIES).map(([k, v]) =>
                            `<option value="${k}" ${k === CONFIG.strategy ? 'selected' : ''}>${v.name}</option>`
                        ).join('')}
                    </select>
                </div>
                <div class="desc" id="bjdom-strategy-desc">${STRATEGIES[CONFIG.strategy].description}</div>
                <div class="row">
                    <label>Betting:</label>
                    <select id="bjdom-betting">
                        ${Object.entries(BETTING_SYSTEMS).map(([k, v]) =>
                            `<option value="${k}" ${k === CONFIG.bettingSystem ? 'selected' : ''}>${v.name}</option>`
                        ).join('')}
                    </select>
                </div>
                <div id="bjdom-current-bet" style="font-size:11px;color:#ffaa00;margin:5px 0;display:none;">
                    Next bet: ${CONFIG.betAmount.toFixed(4)}
                </div>

                <div class="stats">
                    <div class="row"><span>Hands:</span><span id="bjdom-stat-hands">0</span></div>
                    <div class="row"><span>W/L/P:</span><span id="bjdom-stat-wlp">0/0/0</span></div>
                    <div class="row"><span>Profit:</span><span id="bjdom-stat-profit">0.0000</span></div>
                </div>

                <div>
                    <button id="bjdom-play-btn">Start Auto-Play</button>
                    <button id="bjdom-single-btn" class="secondary">Play 1</button>
                    <button id="bjdom-resume-btn" class="secondary">Resume</button>
                </div>

                <div id="bjdom-log"></div>
            </div>
        `;

        document.body.appendChild(panel);

        // Event listeners
        document.getElementById('bjdom-play-btn').addEventListener('click', () => {
            if (isPlaying) {
                stopAutoPlay();
            } else {
                CONFIG.betAmount = parseFloat(document.getElementById('bjdom-bet').value);
                CONFIG.strategy = document.getElementById('bjdom-strategy').value;
                CONFIG.bettingSystem = document.getElementById('bjdom-betting').value;
                // Reset martingale state on start
                currentBet = CONFIG.betAmount;
                consecutiveLosses = 0;
                updateBetDisplay();
                startAutoPlay();
            }
        });

        document.getElementById('bjdom-single-btn').addEventListener('click', () => {
            CONFIG.betAmount = parseFloat(document.getElementById('bjdom-bet').value);
            CONFIG.strategy = document.getElementById('bjdom-strategy').value;
            playSingleHand();
        });

        document.getElementById('bjdom-resume-btn').addEventListener('click', () => {
            CONFIG.strategy = document.getElementById('bjdom-strategy').value;
            resumeGame();
        });

        document.getElementById('bjdom-strategy').addEventListener('change', (e) => {
            CONFIG.strategy = e.target.value;
            document.getElementById('bjdom-strategy-desc').textContent = STRATEGIES[CONFIG.strategy].description;
        });

        document.getElementById('bjdom-betting').addEventListener('change', (e) => {
            CONFIG.bettingSystem = e.target.value;
            currentBet = CONFIG.betAmount;
            consecutiveLosses = 0;
            fifthMartingaleBaseBet = 0;
            updateBetDisplay();
            debugLog('BETTING_CHANGED', { system: CONFIG.bettingSystem, description: BETTING_SYSTEMS[CONFIG.bettingSystem].description });
            log(`Betting: ${BETTING_SYSTEMS[CONFIG.bettingSystem]?.name || CONFIG.bettingSystem}`);
        });

        document.getElementById('bjdom-minimize').addEventListener('click', () => {
            const content = document.getElementById('bjdom-content');
            const btn = document.getElementById('bjdom-minimize');
            content.style.display = content.style.display === 'none' ? 'block' : 'none';
            btn.textContent = content.style.display === 'none' ? '+' : '−';
        });

        log('DOM Bot loaded - pure DOM observation!');
        console.log('[BJDOM] API: bjDOM.readState(), bjDOM.dumpState(), bjDOM.resume()');

        // Check for active game
        setTimeout(() => {
            const actions = getAvailableActions();
            if (actions.hit || actions.stand) {
                log('Active game detected! Click Resume.');
            }
        }, 500);
    }

    function updateUI() {
        const el = (id) => document.getElementById(id);
        if (el('bjdom-stat-hands')) el('bjdom-stat-hands').textContent = stats.hands;
        if (el('bjdom-stat-wlp')) el('bjdom-stat-wlp').textContent = `${stats.wins}/${stats.losses}/${stats.pushes}`;

        const profitEl = el('bjdom-stat-profit');
        if (profitEl) {
            profitEl.textContent = (stats.profit >= 0 ? '+' : '') + stats.profit.toFixed(4);
            profitEl.className = stats.profit >= 0 ? 'profit-positive' : 'profit-negative';
        }
    }

    function updateBetDisplay() {
        const currentBetDisplay = document.getElementById('bjdom-current-bet');
        if (CONFIG.bettingSystem === 'martingale') {
            if (currentBetDisplay) {
                currentBetDisplay.textContent = `Next bet: ${currentBet.toFixed(4)}`;
                currentBetDisplay.style.display = 'block';
            }
        } else if (CONFIG.bettingSystem === 'fifthBalance') {
            const balance = getBalance();
            if (currentBetDisplay) {
                if (balance !== null) {
                    const nextBet = Math.floor((balance / 5) * 100000000) / 100000000;
                    currentBetDisplay.textContent = `1/5 Balance: ${nextBet.toFixed(4)} (Bal: ${balance.toFixed(4)})`;
                } else {
                    currentBetDisplay.textContent = `1/5 Balance: (calculating...)`;
                }
                currentBetDisplay.style.display = 'block';
            }
        } else if (CONFIG.bettingSystem === 'fifthMartingale') {
            const balance = getBalance();
            if (currentBetDisplay) {
                if (consecutiveLosses > 0) {
                    currentBetDisplay.textContent = `1/5+M: ${currentBet.toFixed(4)} (${consecutiveLosses} loss${consecutiveLosses > 1 ? 'es' : ''})`;
                } else if (balance !== null) {
                    const nextBet = Math.floor((balance / 5) * 100000000) / 100000000;
                    currentBetDisplay.textContent = `1/5+M: ${nextBet.toFixed(4)} (Bal: ${balance.toFixed(4)})`;
                } else {
                    currentBetDisplay.textContent = `1/5+M: ${currentBet.toFixed(4)}`;
                }
                currentBetDisplay.style.display = 'block';
            }
        } else {
            if (currentBetDisplay) currentBetDisplay.style.display = 'none';
        }
    }

    // ============================================
    // DEBUG API
    // ============================================

    window.bjDOM = {
        getStats: () => ({
            ...stats,
            winRate: stats.hands ? ((stats.wins/stats.hands)*100).toFixed(1) + '%' : '0%',
            avgProfit: stats.hands > 0 ? (stats.profit / stats.hands).toFixed(8) : '0',
            currentHand: handNumber,
            currentBet: currentBet,
            consecutiveLosses: consecutiveLosses,
            bettingSystem: CONFIG.bettingSystem
        }),
        getConfig: () => CONFIG,
        setStrategy: (s) => {
            if (STRATEGIES[s]) {
                CONFIG.strategy = s;
                const sel = document.getElementById('bjdom-strategy');
                if (sel) sel.value = s;
                return `Strategy: ${STRATEGIES[s].name}`;
            }
            return `Unknown. Available: ${Object.keys(STRATEGIES).join(', ')}`;
        },

        readState: () => ({
            gameStatus: getGameStatus(),
            playerCards: readPlayerCards(),
            dealerCards: readDealerCards(),
            playerValue: readHandValue('player'),
            dealerValue: readHandValue('dealer'),
            actions: getAvailableActions(),
            resultClass: getResultClass(),
            isSplit: isSplitGame(),
            splitHands: getSplitHandCount()
        }),

        resume: resumeGame,

        clickHit: () => clickAction('hit'),
        clickStand: () => clickAction('stand'),
        clickDouble: () => clickAction('double'),
        clickSplit: () => clickAction('split'),
        isSplitGame,
        getSplitHandCount,
        getSplitResults,
        getActiveHand: getActivePlayerHand,
        clickInsurance: () => clickAction('insurance'),
        clickNoInsurance: () => clickAction('noInsurance'),
        clickBet: () => clickButton('[data-testid="bet-button"]'),
        isInsuranceOffered,

        dumpState: () => {
            console.log('=== BJDOM State Dump ===');
            console.log('Stats:', stats);
            console.log('Config:', CONFIG);
            console.log('Flags:', {
                isPlaying,
                isHandInProgress,
                actionInProgress,
                handNumber,
                lastGameStatus,
                handEndedAt,
                timeSinceEnd: Date.now() - handEndedAt,
                gameLoopRunning: !!gameLoopInterval,
                observerRunning: !!observer,
                currentBet,
                consecutiveLosses
            });
            console.log('Game Status:', getGameStatus());
            console.log('Player Cards:', readPlayerCards());
            console.log('Dealer Cards:', readDealerCards());
            console.log('Available Actions:', getAvailableActions());
        },

        // Force start next hand (for debugging)
        forceNextHand: async () => {
            if (isHandInProgress) {
                log('Hand in progress, cannot force');
                return;
            }
            isPlaying = true;
            lastGameStatus = 'none';
            handEndedAt = 0;
            startGameLoop();
            await startNewHand();
        },

        // Reset martingale to base bet
        resetMartingale: () => {
            currentBet = CONFIG.betAmount;
            consecutiveLosses = 0;
            fifthMartingaleBaseBet = 0;
            updateBetDisplay();
            debugLog('MARTINGALE_RESET', { baseBet: CONFIG.betAmount });
            return `Betting reset. Next bet: ${currentBet}`;
        },

        hasInsufficientBalance: hasInsufficientBalanceError,
        getBalance,

        getBettingSystems: () => BETTING_SYSTEMS,

        setBettingSystem: (system) => {
            if (BETTING_SYSTEMS[system]) {
                CONFIG.bettingSystem = system;
                const select = document.getElementById('bjdom-betting');
                if (select) select.value = system;
                currentBet = CONFIG.betAmount;
                consecutiveLosses = 0;
                fifthMartingaleBaseBet = 0;
                updateBetDisplay();
                debugLog('BETTING_CHANGED', { system, description: BETTING_SYSTEMS[system].description });
                return `Betting system set to: ${BETTING_SYSTEMS[system].name}`;
            }
            return `Unknown system. Available: ${Object.keys(BETTING_SYSTEMS).join(', ')}`;
        }
    };

    // ============================================
    // INIT
    // ============================================

    function init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => setTimeout(createUI, 1000));
        } else {
            setTimeout(createUI, 1000);
        }
    }

    init();
})();
