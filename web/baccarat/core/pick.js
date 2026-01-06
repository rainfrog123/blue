// ==UserScript==
// @name         pick
// @namespace    http://tampermonkey.net/
// @version      2.1
// @description  Martingale table scoring for baccarat - soft scoring system
// @author       You
// @match        *://client.pragmaticplaylive.net/*
// @match        *://*.stake.com/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    // ═══════════════════════════════════════════════════════════════════════
    // SCORING SYSTEM
    // ═══════════════════════════════════════════════════════════════════════
    //
    // HARD PASS: fail any → score = 0 (completely reject)
    // SOFT SCORING: everything else affects score
    //   - Higher score = better for Martingale
    //   - Lower score = more risky
    //   - Eligible threshold = configurable minimum score
    //
    // Score range: 0 - 100
    //   0     = REJECTED (hard pass failed)
    //   1-29  = POOR (high risk)
    //   30-49 = FAIR (acceptable risk)
    //   50-69 = GOOD (favorable)
    //   70-89 = GREAT (very favorable)
    //   90+   = EXCELLENT (ideal)

    const Config = {
        // Minimum score to be eligible for play
        MIN_ELIGIBLE_SCORE: 30,

        // ─────────────────────────────────────────────────────────────────────
        // HARD PASS (fail ONE = score 0, reject completely)
        // These are non-negotiable Martingale killers
        // ─────────────────────────────────────────────────────────────────────
        HARD_MIN_TOTAL: 30,           // Too early - not enough data
        HARD_MAX_CHOP_IN_10: 7,       // Pure chop = Martingale death
        HARD_MAX_TIE_RATIO: 0.15,     // Extreme tie pollution
    };

    // ═══════════════════════════════════════════════════════════════════════
    // SCORING WEIGHTS
    // ═══════════════════════════════════════════════════════════════════════
    //
    // Each category contributes to the total score
    // Positive = adds points, Negative = subtracts points

    const Weights = {
        // ─────────────────────────────────────────────────────────────────────
        // HISTORY DEPTH (max +20)
        // ─────────────────────────────────────────────────────────────────────
        HISTORY: {
            BASE: 5,                   // >= 30 hands (minimum)
            LEVEL_40: 10,              // >= 40 hands
            LEVEL_50: 15,              // >= 50 hands
            LEVEL_60: 20,              // >= 60 hands (ideal)
        },

        // ─────────────────────────────────────────────────────────────────────
        // P/B RATIO (max +25, can go negative)
        // Ratio = |P-B| / total
        // ─────────────────────────────────────────────────────────────────────
        RATIO: {
            IDEAL_MIN: 0.08,           // Ideal range start
            IDEAL_MAX: 0.18,           // Ideal range end
            SAFE_MIN: 0.05,            // Safe zone start
            SAFE_MAX: 0.25,            // Safe zone end

            IDEAL: 25,                 // In ideal range
            SAFE: 15,                  // In safe zone (not ideal)
            RISKY_LOW: 5,              // Too balanced (likely chop)
            RISKY_HIGH: 0,             // Too skewed (one-sided run)
            EXTREME: -10,              // Extremely skewed (> 0.35)
        },

        // ─────────────────────────────────────────────────────────────────────
        // TIE RATIO (max +15, can go negative)
        // ─────────────────────────────────────────────────────────────────────
        TIES: {
            EXCELLENT: 0.04,           // < 4% ties
            GOOD: 0.08,                // < 8% ties
            OK: 0.12,                  // < 12% ties

            EXCELLENT_PTS: 15,
            GOOD_PTS: 10,
            OK_PTS: 5,
            BAD_PTS: -5,               // > 12% ties
        },

        // ─────────────────────────────────────────────────────────────────────
        // STREAK PATTERNS (max +20)
        // ─────────────────────────────────────────────────────────────────────
        STREAK: {
            // Evidence of streaks in last 20
            HAS_DOUBLE: 10,            // Has BB or PP
            HAS_TRIPLE: 15,            // Has BBB or PPP
            NO_PATTERN: -5,            // No streak evidence at all

            // Current streak bonus
            PER_LENGTH: 2,             // Points per streak length
            MAX_CURRENT: 10,           // Cap on current streak bonus
        },

        // ─────────────────────────────────────────────────────────────────────
        // ALTERNATION PENALTY (can go negative)
        // ─────────────────────────────────────────────────────────────────────
        ALTERNATION: {
            // Alternations in last 10
            LOW: 3,                    // <= 3 alternations (good)
            MED: 5,                    // <= 5 alternations (ok)

            LOW_PTS: 10,
            MED_PTS: 5,
            HIGH_PTS: 0,               // 6 alternations
            EXTREME_PTS: -10,          // 7+ but not hard fail

            // Pure alternation in last 6
            PURE_ALT_PENALTY: -15,
        },

        // ─────────────────────────────────────────────────────────────────────
        // BETTING STATUS (max +10)
        // ─────────────────────────────────────────────────────────────────────
        CAN_BET: {
            OPEN: 10,
            CLOSED: -5,
        },
    };

    // ═══════════════════════════════════════════════════════════════════════
    // HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    const getSequence = (t) => {
        if (!window.pp) return [];
        const id = t?.uid || t?.gameId || t?.id || t;
        return window.pp.pbt(id) || [];
    };

    const calcRatio = (t) => {
        if (!t || !t.total || t.total === 0) return 999;
        return Math.abs((t.P || 0) - (t.B || 0)) / t.total;
    };

    const calcTieRatio = (t) => {
        if (!t || !t.total || t.total === 0) return 999;
        return (t.T || 0) / t.total;
    };

    const countAlternations = (seq) => {
        if (!seq || seq.length < 2) return 0;
        let alt = 0;
        for (let i = 1; i < seq.length; i++) {
            if (seq[i] !== seq[i-1] && seq[i] !== 'T' && seq[i-1] !== 'T') {
                alt++;
            }
        }
        return alt;
    };

    const isPureAlternation = (seq) => {
        if (!seq || seq.length < 4) return false;
        const filtered = seq.filter(x => x !== 'T');
        if (filtered.length < 4) return false;
        for (let i = 1; i < filtered.length; i++) {
            if (filtered[i] === filtered[i-1]) return false;
        }
        return true;
    };

    const hasDoubleStreak = (seq) => {
        const str = seq.join('');
        return /BB|PP/.test(str);
    };

    const hasTripleStreak = (seq) => {
        const str = seq.join('');
        return /BBB|PPP/.test(str);
    };

    const detectStreak = (seq) => {
        if (!seq || seq.length === 0) return { side: null, length: 0 };
        const last = seq[seq.length - 1];
        if (last === 'T') return { side: 'T', length: 1 };
        let count = 0;
        for (let i = seq.length - 1; i >= 0; i--) {
            if (seq[i] === last) count++;
            else if (seq[i] !== 'T') break;
        }
        return { side: last, length: count };
    };

    // ═══════════════════════════════════════════════════════════════════════
    // SCORING ENGINE
    // ═══════════════════════════════════════════════════════════════════════

    const scoreTable = (t) => {
        if (!t) return { score: 0, eligible: false, breakdown: {}, reasons: ['no-table'] };

        const breakdown = {};
        const reasons = [];
        let totalScore = 0;

        const seq = getSequence(t);
        const total = t.total || 0;
        const ratio = calcRatio(t);
        const tieRatio = calcTieRatio(t);
        const last10 = seq.slice(-10);
        const last20 = seq.slice(-20);
        const last6 = seq.slice(-6);
        const altIn10 = countAlternations(last10);
        const streak = detectStreak(seq);

        // ─────────────────────────────────────────────────────────────────────
        // HARD PASS CHECKS
        // ─────────────────────────────────────────────────────────────────────

        // Check 1: Too early
        if (total < Config.HARD_MIN_TOTAL) {
            reasons.push(`HARD: too-early (${total} < ${Config.HARD_MIN_TOTAL})`);
            return { score: 0, eligible: false, breakdown: {}, reasons };
        }

        // Check 2: Extreme chop
        if (altIn10 >= Config.HARD_MAX_CHOP_IN_10) {
            reasons.push(`HARD: extreme-chop (${altIn10} alt in 10)`);
            return { score: 0, eligible: false, breakdown: {}, reasons };
        }

        // Check 3: Extreme tie pollution
        if (tieRatio > Config.HARD_MAX_TIE_RATIO) {
            reasons.push(`HARD: tie-pollution (${(tieRatio*100).toFixed(1)}% > ${Config.HARD_MAX_TIE_RATIO*100}%)`);
            return { score: 0, eligible: false, breakdown: {}, reasons };
        }

        // ─────────────────────────────────────────────────────────────────────
        // SOFT SCORING
        // ─────────────────────────────────────────────────────────────────────

        // HISTORY DEPTH
        if (total >= 60) {
            breakdown.history = Weights.HISTORY.LEVEL_60;
        } else if (total >= 50) {
            breakdown.history = Weights.HISTORY.LEVEL_50;
        } else if (total >= 40) {
            breakdown.history = Weights.HISTORY.LEVEL_40;
        } else {
            breakdown.history = Weights.HISTORY.BASE;
        }
        totalScore += breakdown.history;

        // P/B RATIO
        if (ratio >= Weights.RATIO.IDEAL_MIN && ratio <= Weights.RATIO.IDEAL_MAX) {
            breakdown.ratio = Weights.RATIO.IDEAL;
        } else if (ratio >= Weights.RATIO.SAFE_MIN && ratio <= Weights.RATIO.SAFE_MAX) {
            breakdown.ratio = Weights.RATIO.SAFE;
        } else if (ratio < Weights.RATIO.SAFE_MIN) {
            breakdown.ratio = Weights.RATIO.RISKY_LOW;
            reasons.push(`ratio too low: ${ratio.toFixed(3)}`);
        } else if (ratio > 0.35) {
            breakdown.ratio = Weights.RATIO.EXTREME;
            reasons.push(`ratio extreme: ${ratio.toFixed(3)}`);
        } else {
            breakdown.ratio = Weights.RATIO.RISKY_HIGH;
            reasons.push(`ratio high: ${ratio.toFixed(3)}`);
        }
        totalScore += breakdown.ratio;

        // TIE RATIO
        if (tieRatio < Weights.TIES.EXCELLENT) {
            breakdown.ties = Weights.TIES.EXCELLENT_PTS;
        } else if (tieRatio < Weights.TIES.GOOD) {
            breakdown.ties = Weights.TIES.GOOD_PTS;
        } else if (tieRatio < Weights.TIES.OK) {
            breakdown.ties = Weights.TIES.OK_PTS;
        } else {
            breakdown.ties = Weights.TIES.BAD_PTS;
            reasons.push(`ties: ${(tieRatio*100).toFixed(1)}%`);
        }
        totalScore += breakdown.ties;

        // STREAK PATTERNS
        breakdown.streakPattern = 0;
        if (hasTripleStreak(last20)) {
            breakdown.streakPattern = Weights.STREAK.HAS_TRIPLE;
        } else if (hasDoubleStreak(last20)) {
            breakdown.streakPattern = Weights.STREAK.HAS_DOUBLE;
        } else {
            breakdown.streakPattern = Weights.STREAK.NO_PATTERN;
            reasons.push('no streak pattern in 20');
        }
        totalScore += breakdown.streakPattern;

        // CURRENT STREAK BONUS
        breakdown.currentStreak = 0;
        if (streak.side && streak.side !== 'T' && streak.length >= 2) {
            breakdown.currentStreak = Math.min(
                streak.length * Weights.STREAK.PER_LENGTH,
                Weights.STREAK.MAX_CURRENT
            );
        }
        totalScore += breakdown.currentStreak;

        // ALTERNATION
        if (altIn10 <= Weights.ALTERNATION.LOW) {
            breakdown.alternation = Weights.ALTERNATION.LOW_PTS;
        } else if (altIn10 <= Weights.ALTERNATION.MED) {
            breakdown.alternation = Weights.ALTERNATION.MED_PTS;
        } else if (altIn10 === 6) {
            breakdown.alternation = Weights.ALTERNATION.HIGH_PTS;
            reasons.push('high alternation: 6');
        } else {
            breakdown.alternation = Weights.ALTERNATION.EXTREME_PTS;
            reasons.push(`extreme alternation: ${altIn10}`);
        }
        totalScore += breakdown.alternation;

        // PURE ALTERNATION PENALTY
        breakdown.pureAlt = 0;
        if (last6.length >= 4 && isPureAlternation(last6)) {
            breakdown.pureAlt = Weights.ALTERNATION.PURE_ALT_PENALTY;
            reasons.push('pure alternation in last 6');
        }
        totalScore += breakdown.pureAlt;

        // CAN BET
        if (t.canBet === true) {
            breakdown.canBet = Weights.CAN_BET.OPEN;
        } else {
            breakdown.canBet = Weights.CAN_BET.CLOSED;
            reasons.push('betting closed');
        }
        totalScore += breakdown.canBet;

        // ─────────────────────────────────────────────────────────────────────
        // FINAL SCORE
        // ─────────────────────────────────────────────────────────────────────

        const finalScore = Math.max(1, Math.min(100, totalScore));
        const eligible = finalScore >= Config.MIN_ELIGIBLE_SCORE;

        return {
            score: finalScore,
            eligible,
            breakdown,
            reasons: eligible ? [] : reasons,
            warnings: eligible ? reasons : []
        };
    };

    // ═══════════════════════════════════════════════════════════════════════
    // SELECTION FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    const getAllScored = () => {
        if (!window.pp) return [];
        const tables = Object.values(window.pp.tables());
        return tables.map(t => {
            const result = scoreTable(t);
            const seq = getSequence(t);
            return {
                ...t,
                ...result,
                ratio: calcRatio(t),
                tieRatio: calcTieRatio(t),
                streak: detectStreak(seq),
                last10: seq.slice(-10).join(''),
                altIn10: countAlternations(seq.slice(-10))
            };
        });
    };

    const getEligible = () => {
        return getAllScored()
            .filter(t => t.eligible)
            .sort((a, b) => b.score - a.score);
    };

    const getAll = () => {
        return getAllScored()
            .filter(t => t.score > 0)
            .sort((a, b) => b.score - a.score);
    };

    const getBest = () => {
        const eligible = getEligible();
        return eligible[0] || null;
    };

    const pick = () => {
        const table = getBest();
        if (!table) return null;
        return { table, score: table.score };
    };

    // ═══════════════════════════════════════════════════════════════════════
    // DISPLAY HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    const scoreLabel = (s) => {
        if (s === 0) return 'REJECT';
        if (s < 30) return 'POOR';
        if (s < 50) return 'FAIR';
        if (s < 70) return 'GOOD';
        if (s < 90) return 'GREAT';
        return 'IDEAL';
    };

    const scoreColor = (s) => {
        if (s === 0) return '🔴';
        if (s < 30) return '🟠';
        if (s < 50) return '🟡';
        if (s < 70) return '🟢';
        return '💚';
    };

    // ═══════════════════════════════════════════════════════════════════════
    // API
    // ═══════════════════════════════════════════════════════════════════════

    window.pick = {
        // Config
        config: Config,
        weights: Weights,

        // Scoring
        score: scoreTable,
        scoreAll: getAllScored,
        label: scoreLabel,

        // Selection
        eligible: getEligible,
        all: getAll,
        best: getBest,
        pick,

        // Helpers
        ratio: calcRatio,
        tieRatio: calcTieRatio,
        streak: (t) => detectStreak(getSequence(t)),
        alternations: (t) => countAlternations(getSequence(t).slice(-10)),

        // Status display
        status: () => {
            const all = getAllScored().filter(t => t.total >= 20);
            const eligible = all.filter(t => t.eligible);
            const rejected = all.filter(t => t.score === 0);
            const poor = all.filter(t => t.score > 0 && t.score < Config.MIN_ELIGIBLE_SCORE);

            console.log(`
╔══════════════════════════════════════════════════════════════╗
║     MARTINGALE SCORES (${eligible.length} eligible / ${all.length} total)              ║
╠══════════════════════════════════════════════════════════════╣`);

            // Show all tables with scores
            all.slice(0, 15).forEach((t, i) => {
                const name = (t.name || t.gameId || '?').slice(0, 14).padEnd(14);
                const icon = scoreColor(t.score);
                const bet = t.canBet ? '✓' : ' ';
                const str = t.streak.length > 1 ? `${t.streak.length}${t.streak.side}` : '--';
                const label = scoreLabel(t.score).padEnd(6);
                console.log(
                    `║ ${icon}${bet} ${name} ` +
                    `${String(t.score).padStart(2)} ${label} ` +
                    `P:${String(t.P||0).padStart(2)} B:${String(t.B||0).padStart(2)} ` +
                    `r:${t.ratio.toFixed(2)} a:${t.altIn10} ${str.padEnd(3)}`
                );
            });

            console.log('╠══════════════════════════════════════════════════════════════╣');
            console.log(`║  ${eligible.length} ELIGIBLE (≥${Config.MIN_ELIGIBLE_SCORE})  |  ${poor.length} POOR  |  ${rejected.length} REJECTED              ║`);
            console.log('╚══════════════════════════════════════════════════════════════╝');
        },

        // Detailed check
        check: (uidOrId) => {
            const t = window.pp?.get(uidOrId);
            if (!t) {
                console.log('Table not found');
                return null;
            }

            const result = scoreTable(t);
            const seq = getSequence(t);
            const streak = detectStreak(seq);

            console.log(`
╔══════════════════════════════════════════════════════════════╗
║  ${(t.name || t.gameId || '?').slice(0, 50).padEnd(50)}        ║
╠══════════════════════════════════════════════════════════════╣
║  SCORE: ${String(result.score).padStart(3)} / 100   ${scoreColor(result.score)} ${scoreLabel(result.score).padEnd(6)}   Eligible: ${result.eligible ? 'YES' : 'NO '}      ║
╠══════════════════════════════════════════════════════════════╣
║  P: ${String(t.P||0).padStart(2)}  B: ${String(t.B||0).padStart(2)}  T: ${String(t.T||0).padStart(2)}  Total: ${String(t.total||0).padStart(3)}                        ║
║  Ratio: ${calcRatio(t).toFixed(3)}   Ties: ${(calcTieRatio(t)*100).toFixed(1)}%   Alt: ${countAlternations(seq.slice(-10))}           ║
║  Streak: ${streak.length}${streak.side || '-'}   Last10: ${seq.slice(-10).join('').padEnd(10)}                  ║
╠══════════════════════════════════════════════════════════════╣
║  BREAKDOWN:                                                  ║`);

            Object.entries(result.breakdown).forEach(([k, v]) => {
                const sign = v >= 0 ? '+' : '';
                console.log(`║    ${k.padEnd(15)} ${sign}${v}`.padEnd(63) + '║');
            });

            if (result.reasons.length > 0 || result.warnings?.length > 0) {
                console.log('╠══════════════════════════════════════════════════════════════╣');
                const issues = [...(result.reasons || []), ...(result.warnings || [])];
                issues.forEach(r => {
                    console.log(`║  ⚠ ${r}`.padEnd(63) + '║');
                });
            }

            console.log('╚══════════════════════════════════════════════════════════════╝');
            return result;
        },

        // Help
        help: () => {
            console.log(`
╔══════════════════════════════════════════════════════════════╗
║              MARTINGALE PICKER v2.1 - HELP                   ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  SCORE RANGES                                                ║
║  ────────────                                                ║
║  0      = REJECTED (hard pass failed)                        ║
║  1-29   = POOR (high risk, not eligible)                     ║
║  30-49  = FAIR (acceptable, eligible)                        ║
║  50-69  = GOOD (favorable)                                   ║
║  70-89  = GREAT (very favorable)                             ║
║  90+    = IDEAL (best conditions)                            ║
║                                                              ║
║  HARD PASS (instant reject)                                  ║
║  ──────────────────────────                                  ║
║  • total < 30 (not enough data)                              ║
║  • alternations ≥ 7 in last 10 (extreme chop)                ║
║  • ties > 15% (extreme pollution)                            ║
║                                                              ║
║  SCORING FACTORS                                             ║
║  ───────────────                                             ║
║  history    +5 to +20   (more hands = better)                ║
║  ratio      -10 to +25  (0.08-0.18 ideal)                    ║
║  ties       -5 to +15   (fewer = better)                     ║
║  streaks    -5 to +15   (evidence of runs)                   ║
║  current    +0 to +10   (active streak bonus)                ║
║  alternation -10 to +10 (fewer = better)                     ║
║  pureAlt    -15 or 0    (BPBPBP penalty)                     ║
║  canBet     -5 or +10   (betting status)                     ║
║                                                              ║
║  COMMANDS                                                    ║
║  ────────                                                    ║
║  pick.status()      Show all tables with scores              ║
║  pick.check(1)      Detailed breakdown for table             ║
║  pick.eligible()    Get eligible tables (sorted)             ║
║  pick.all()         Get all non-rejected tables              ║
║  pick.best()        Get highest scoring table                ║
║  pick.pick()        Get {table, score} for play.js           ║
║                                                              ║
║  CONFIG                                                      ║
║  ──────                                                      ║
║  pick.config.MIN_ELIGIBLE_SCORE = 30   // Threshold          ║
║  pick.weights.RATIO.IDEAL = 25         // Adjust weights     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
`);
        }
    };

    // ═══════════════════════════════════════════════════════════════════════
    // INITIALIZATION
    // ═══════════════════════════════════════════════════════════════════════

    const waitForPP = () => new Promise(resolve => {
        const check = () => window.pp ? resolve() : setTimeout(check, 100);
        check();
    });

    waitForPP().then(() => {
        console.log('[Pick] v2.1 | Soft scoring system');
        console.log('[Pick] Commands: pick.status() pick.check(uid) pick.help()');
    });

})();
