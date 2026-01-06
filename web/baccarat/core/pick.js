// ==UserScript==
// @name         pick
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Table selection rules for baccarat betting
// @author       You
// @match        *://client.pragmaticplaylive.net/*
// @match        *://*.stake.com/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    // ═══════════════════════════════════════════════════════════════════════
    // SELECTION RULES - Customize these to change table picking behavior
    // ═══════════════════════════════════════════════════════════════════════

    const Rules = {
        // Minimum rounds before table is eligible
        MIN_ROUNDS: 20,

        // Maximum P/B difference (absolute)
        MAX_PB_DIFF: 3,

        // Must be open for betting
        REQUIRE_CAN_BET: true,

        // Ratio threshold (|P-B|/total) - lower = more balanced
        MAX_RATIO: 0.15,

        // Minimum total games for ratio to matter
        RATIO_MIN_GAMES: 30,

        // Streak detection
        MAX_STREAK: 6,          // Avoid tables with streaks longer than this
        MIN_STREAK_FOR_BET: 3,  // Bet against streak if >= this length
    };

    // ═══════════════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    // Calculate P/B ratio (lower = more balanced)
    const calcRatio = (t) => {
        if (!t || !t.total || t.total === 0) return 999;
        const diff = Math.abs((t.P || 0) - (t.B || 0));
        return diff / t.total;
    };

    // Get P/B/T sequence from pp API
    const getSequence = (t) => {
        if (!window.pp) return [];
        if (typeof t === 'number' || typeof t === 'string') {
            return window.pp.pbt(t) || [];
        }
        return window.pp.pbt(t?.uid || t?.id) || [];
    };

    // Detect current streak at end of sequence
    // Returns { side: 'P'|'B'|'T'|null, length: N }
    const detectStreak = (seq) => {
        if (!seq || seq.length === 0) return { side: null, length: 0 };
        const last = seq[seq.length - 1];
        let count = 0;
        for (let i = seq.length - 1; i >= 0; i--) {
            if (seq[i] === last) count++;
            else break;
        }
        return { side: last, length: count };
    };

    // Count consecutive same results from end
    const getStreakLength = (t) => {
        const seq = getSequence(t);
        return detectStreak(seq).length;
    };

    // Get the dominant side (which has more wins)
    const getDominant = (t) => {
        if (!t) return null;
        if ((t.P || 0) > (t.B || 0)) return 'P';
        if ((t.B || 0) > (t.P || 0)) return 'B';
        return null; // tied
    };

    // Get the underdog side (fewer wins)
    const getUnderdog = (t) => {
        const dom = getDominant(t);
        if (dom === 'P') return 'B';
        if (dom === 'B') return 'P';
        return null;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // FILTER FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    // Basic eligibility check
    const isEligible = (t) => {
        if (!t) return false;
        const total = t.total || 0;
        const diff = Math.abs((t.P || 0) - (t.B || 0));

        // Minimum rounds
        if (total < Rules.MIN_ROUNDS) return false;

        // P/B difference check
        if (diff > Rules.MAX_PB_DIFF) return false;

        // Must be open for betting
        if (Rules.REQUIRE_CAN_BET && t.canBet !== true) return false;

        // Ratio check (only if enough games)
        if (total >= Rules.RATIO_MIN_GAMES) {
            const ratio = calcRatio(t);
            if (ratio > Rules.MAX_RATIO) return false;
        }

        return true;
    };

    // Check if table has a streak worth betting against
    const hasActionableStreak = (t) => {
        const streak = detectStreak(getSequence(t));
        return streak.length >= Rules.MIN_STREAK_FOR_BET && streak.side !== 'T';
    };

    // ═══════════════════════════════════════════════════════════════════════
    // SELECTION FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    // Get all eligible tables
    const getEligible = () => {
        if (!window.pp) return [];
        return [...Object.values(window.pp.tables())]
            .filter(isEligible)
            .map(t => ({
                ...t,
                ratio: calcRatio(t),
                streak: detectStreak(getSequence(t)),
                sequence: getSequence(t).slice(-10).join('')
            }));
    };

    // Get tables sorted by ratio (most balanced first)
    const getByRatio = () => {
        return getEligible().sort((a, b) => a.ratio - b.ratio);
    };

    // Get tables with actionable streaks
    const getStreaky = () => {
        return getEligible()
            .filter(hasActionableStreak)
            .sort((a, b) => b.streak.length - a.streak.length);
    };

    // Get random eligible table
    const getRandom = () => {
        const eligible = getEligible();
        if (eligible.length === 0) return null;
        return eligible[Math.floor(Math.random() * eligible.length)];
    };

    // Get best table by custom scoring
    // Lower score = better
    const getBest = () => {
        const eligible = getEligible();
        if (eligible.length === 0) return null;

        return eligible.reduce((best, t) => {
            // Score: ratio (lower is better) + streak penalty
            const score = t.ratio + (t.streak.length > Rules.MAX_STREAK ? 1 : 0);
            const bestScore = best.ratio + (best.streak.length > Rules.MAX_STREAK ? 1 : 0);
            return score < bestScore ? t : best;
        });
    };

    // Suggest which side to bet on for a table
    const suggestSide = (t) => {
        if (!t) return null;

        // If there's a streak, bet against it
        const streak = detectStreak(getSequence(t));
        if (streak.length >= Rules.MIN_STREAK_FOR_BET && streak.side !== 'T') {
            return streak.side === 'P' ? 'B' : 'P';
        }

        // Otherwise bet on underdog (fewer wins catches up)
        const underdog = getUnderdog(t);
        if (underdog) return underdog;

        // Fallback: random
        return Math.random() < 0.5 ? 'P' : 'B';
    };

    // ═══════════════════════════════════════════════════════════════════════
    // API
    // ═══════════════════════════════════════════════════════════════════════

    window.pick = {
        // Rules (can be modified at runtime)
        rules: Rules,

        // Calculations
        ratio: calcRatio,
        streak: (t) => detectStreak(getSequence(t)),
        sequence: getSequence,
        dominant: getDominant,
        underdog: getUnderdog,

        // Filters
        isEligible,
        hasStreak: hasActionableStreak,

        // Selection
        all: getEligible,           // All eligible tables
        byRatio: getByRatio,        // Sorted by ratio (best first)
        streaky: getStreaky,        // Tables with streaks
        random: getRandom,          // Random eligible table
        best: getBest,              // Best table by scoring
        suggest: suggestSide,       // Suggest P or B for table

        // Quick pick: returns {table, side} or null
        pick: () => {
            const table = getBest();
            if (!table) return null;
            return { table, side: suggestSide(table) };
        },

        // Print status
        status: () => {
            const eligible = getEligible();
            console.log(`\n═══ PICK STATUS (${eligible.length} eligible) ═══\n`);
            console.log(`Rules: min=${Rules.MIN_ROUNDS} maxDiff=${Rules.MAX_PB_DIFF} maxRatio=${Rules.MAX_RATIO}`);
            eligible.slice(0, 15).forEach(t => {
                const bet = t.canBet ? '✓' : ' ';
                const sug = suggestSide(t);
                console.log(
                    `#${String(t.uid).padStart(2)}${bet} ${(t.name || t.id).slice(0,16).padEnd(16)} ` +
                    `P:${String(t.P||0).padStart(2)} B:${String(t.B||0).padStart(2)} ` +
                    `r:${t.ratio.toFixed(2)} s:${t.streak.length}${t.streak.side||'-'} → ${sug} ` +
                    `[${t.sequence}]`
                );
            });
        }
    };

    // Wait for pp API
    const waitForPP = () => new Promise(resolve => {
        const check = () => window.pp ? resolve() : setTimeout(check, 100);
        check();
    });

    waitForPP().then(() => {
        console.log('[Pick] v1.0 | Table selection rules');
        console.log('[Pick] API: pick.status() pick.pick() pick.all() pick.suggest(t)');
    });

})();

/*
╔══════════════════════════════════════════════════════════════════════════════╗
║                        TABLE PICKER API v1.0                                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  REQUIRES: socks.js (provides pp API with table data)                        ║
║                                                                              ║
║  RULES (pick.rules - modify at runtime)                                      ║
║  ─────────────────────────────────────                                       ║
║  MIN_ROUNDS: 20          Minimum games before eligible                       ║
║  MAX_PB_DIFF: 3          Maximum |P-B| difference                            ║
║  REQUIRE_CAN_BET: true   Must be open for betting                            ║
║  MAX_RATIO: 0.15         Maximum ratio for eligibility                       ║
║  RATIO_MIN_GAMES: 30     Min games for ratio check                           ║
║  MAX_STREAK: 6           Avoid streaks longer than this                      ║
║  MIN_STREAK_FOR_BET: 3   Bet against streak if >= this                       ║
║                                                                              ║
║  SELECTION                                                                   ║
║  ─────────                                                                   ║
║  pick.pick()             Quick pick: {table, side} or null                   ║
║  pick.all()              All eligible tables                                 ║
║  pick.byRatio()          Sorted by ratio (best first)                        ║
║  pick.streaky()          Tables with actionable streaks                      ║
║  pick.random()           Random eligible table                               ║
║  pick.best()             Best table by scoring                               ║
║  pick.suggest(t)         Suggest 'P' or 'B' for table                        ║
║                                                                              ║
║  ANALYSIS                                                                    ║
║  ────────                                                                    ║
║  pick.ratio(t)           Calculate P/B ratio                                 ║
║  pick.streak(t)          Get streak {side, length}                           ║
║  pick.sequence(t)        Get P/B/T sequence array                            ║
║  pick.dominant(t)        Get dominant side 'P'|'B'|null                      ║
║  pick.underdog(t)        Get underdog side                                   ║
║  pick.isEligible(t)      Check if table passes rules                         ║
║  pick.hasStreak(t)       Check if table has actionable streak                ║
║                                                                              ║
║  STATUS                                                                      ║
║  ──────                                                                      ║
║  pick.status()           Print all eligible tables with analysis             ║
║                                                                              ║
║  CUSTOMIZING RULES                                                           ║
║  ─────────────────                                                           ║
║  pick.rules.MIN_ROUNDS = 30     // Change minimum rounds                     ║
║  pick.rules.MAX_PB_DIFF = 5     // Allow bigger difference                   ║
║  pick.rules.MAX_RATIO = 0.20    // More lenient ratio                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
*/

