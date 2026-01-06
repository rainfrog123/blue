// ==UserScript==
// @name         pick
// @namespace    http://tampermonkey.net/
// @version      2.0
// @description  Martingale table scoring and selection for baccarat
// @author       You
// @match        *://client.pragmaticplaylive.net/*
// @match        *://*.stake.com/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    // ═══════════════════════════════════════════════════════════════════════
    // MARTINGALE SCORING RULES
    // ═══════════════════════════════════════════════════════════════════════
    //
    // A "good enough" table = variance is smooth enough that 1-2-4 Martingale
    // has a reasonable chance to complete without 3 losses in a row.
    //
    // HARD PASS: fail ANY → score = 0 (reject)
    // MUST-HAVE: fail ANY → score = 0 (reject)
    // BONUS: add points for favorable conditions

    const Rules = {
        // ─────────────────────────────────────────────────────────────────────
        // HARD PASS (fail one = instant reject)
        // ─────────────────────────────────────────────────────────────────────
        HARD_MIN_TOTAL: 30,           // Rule 1: Too early if < 30
        HARD_MAX_TIE_RATIO: 0.12,     // Rule 2: Tie pollution if T/total > 12%
        HARD_MAX_CHOP_IN_10: 7,       // Rule 3: Max alternations in last 10
        HARD_REJECT_SPEED: true,      // Rule 4: Reject Speed Baccarat tables

        // ─────────────────────────────────────────────────────────────────────
        // MUST-HAVE (all must pass)
        // ─────────────────────────────────────────────────────────────────────
        MUST_MIN_TOTAL: 40,           // Rule 6: Enough history
        MUST_RATIO_MIN: 0.05,         // Rule 7: Ratio floor (avoid disguised chop)
        MUST_RATIO_MAX: 0.25,         // Rule 7: Ratio ceiling (avoid extreme run)
        MUST_HAVE_STREAK: true,       // Rule 8: Must see BB/BBB/PP/PPP in last 20
        MUST_NO_FLIP_IN_6: true,      // Rule 9: Last 6 can't be pure alternation
        MUST_CAN_BET: true,           // Rule 10: Must be open for betting

        // ─────────────────────────────────────────────────────────────────────
        // BONUS SCORING (higher = better)
        // ─────────────────────────────────────────────────────────────────────
        BONUS_IDEAL_TOTAL: 60,        // Bonus if total >= this
        BONUS_IDEAL_RATIO_MIN: 0.08,  // Ideal ratio range
        BONUS_IDEAL_RATIO_MAX: 0.18,
        BONUS_STREAK_LEN: 3,          // Bonus if current streak >= this
        BONUS_LOW_TIES: 0.06,         // Bonus if tie ratio < this
    };

    // ═══════════════════════════════════════════════════════════════════════
    // HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    // Get P/B/T sequence from pp API
    const getSequence = (t) => {
        if (!window.pp) return [];
        const id = t?.uid || t?.gameId || t?.id || t;
        return window.pp.pbt(id) || [];
    };

    // Calculate ratio: |P-B| / total
    const calcRatio = (t) => {
        if (!t || !t.total || t.total === 0) return 999;
        return Math.abs((t.P || 0) - (t.B || 0)) / t.total;
    };

    // Calculate tie ratio: T / total
    const calcTieRatio = (t) => {
        if (!t || !t.total || t.total === 0) return 999;
        return (t.T || 0) / t.total;
    };

    // Count alternations in sequence (PBPBPB = 5 alternations)
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

    // Check if sequence is pure alternation (BPBPBP)
    const isPureAlternation = (seq) => {
        if (!seq || seq.length < 2) return false;
        const filtered = seq.filter(x => x !== 'T');
        if (filtered.length < 2) return false;
        for (let i = 1; i < filtered.length; i++) {
            if (filtered[i] === filtered[i-1]) return false;
        }
        return true;
    };

    // Check for streak patterns (BB, BBB, PP, PPP) in sequence
    const hasStreakPattern = (seq) => {
        if (!seq || seq.length < 2) return false;
        const str = seq.join('');
        return /BB|PP/.test(str);
    };

    // Get current streak at end of sequence
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

    // Check if table name suggests Speed Baccarat
    const isSpeedTable = (t) => {
        const name = (t?.name || t?.tableName || '').toLowerCase();
        return name.includes('speed');
    };

    // ═══════════════════════════════════════════════════════════════════════
    // SCORING FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    // Check HARD PASS rules - any fail = immediate reject
    const checkHardPass = (t) => {
        const reasons = [];

        // Rule 1: Too early
        if ((t.total || 0) < Rules.HARD_MIN_TOTAL) {
            reasons.push(`too-early:${t.total}<${Rules.HARD_MIN_TOTAL}`);
        }

        // Rule 2: Tie pollution
        const tieRatio = calcTieRatio(t);
        if (tieRatio > Rules.HARD_MAX_TIE_RATIO) {
            reasons.push(`tie-pollution:${(tieRatio*100).toFixed(1)}%>${Rules.HARD_MAX_TIE_RATIO*100}%`);
        }

        // Rule 3: Chop in last 10
        const seq = getSequence(t);
        const last10 = seq.slice(-10);
        const altIn10 = countAlternations(last10);
        if (altIn10 >= Rules.HARD_MAX_CHOP_IN_10) {
            reasons.push(`chop:${altIn10}alt/${Rules.HARD_MAX_CHOP_IN_10}max`);
        }

        // Rule 4: Speed Baccarat
        if (Rules.HARD_REJECT_SPEED && isSpeedTable(t)) {
            reasons.push('speed-table');
        }

        return { pass: reasons.length === 0, reasons };
    };

    // Check MUST-HAVE rules - all must pass
    const checkMustHave = (t) => {
        const reasons = [];
        const seq = getSequence(t);

        // Rule 6: Enough history
        if ((t.total || 0) < Rules.MUST_MIN_TOTAL) {
            reasons.push(`low-history:${t.total}<${Rules.MUST_MIN_TOTAL}`);
        }

        // Rule 7: Ratio in safe zone
        const ratio = calcRatio(t);
        if (ratio < Rules.MUST_RATIO_MIN) {
            reasons.push(`ratio-low:${ratio.toFixed(3)}<${Rules.MUST_RATIO_MIN}`);
        }
        if (ratio > Rules.MUST_RATIO_MAX) {
            reasons.push(`ratio-high:${ratio.toFixed(3)}>${Rules.MUST_RATIO_MAX}`);
        }

        // Rule 8: Streak evidence in last 20
        if (Rules.MUST_HAVE_STREAK) {
            const last20 = seq.slice(-20);
            if (!hasStreakPattern(last20)) {
                reasons.push('no-streak-pattern');
            }
        }

        // Rule 9: No immediate flip (pure alternation in last 6)
        if (Rules.MUST_NO_FLIP_IN_6) {
            const last6 = seq.slice(-6);
            if (last6.length >= 6 && isPureAlternation(last6)) {
                reasons.push('pure-alternation-in-6');
            }
        }

        // Rule 10: Betting window calm
        if (Rules.MUST_CAN_BET && t.canBet !== true) {
            reasons.push('not-open');
        }

        return { pass: reasons.length === 0, reasons };
    };

    // Calculate bonus score (higher = better)
    const calcBonusScore = (t) => {
        let score = 0;
        const seq = getSequence(t);

        // Bonus: More history
        if ((t.total || 0) >= Rules.BONUS_IDEAL_TOTAL) {
            score += 10;
        }

        // Bonus: Ideal ratio range
        const ratio = calcRatio(t);
        if (ratio >= Rules.BONUS_IDEAL_RATIO_MIN && ratio <= Rules.BONUS_IDEAL_RATIO_MAX) {
            score += 15;
        }

        // Bonus: Current streak
        const streak = detectStreak(seq);
        if (streak.length >= Rules.BONUS_STREAK_LEN && streak.side !== 'T') {
            score += streak.length * 5; // 5 points per streak length
        }

        // Bonus: Low ties
        const tieRatio = calcTieRatio(t);
        if (tieRatio < Rules.BONUS_LOW_TIES) {
            score += 10;
        }

        // Bonus: Not too choppy in last 10
        const last10 = seq.slice(-10);
        const altIn10 = countAlternations(last10);
        if (altIn10 <= 4) {
            score += 10;
        }

        return score;
    };

    // Main scoring function
    // Returns: { score: 0-100, eligible: bool, hardPass: {}, mustHave: {}, breakdown: {} }
    const scoreTable = (t) => {
        if (!t) return { score: 0, eligible: false, reasons: ['no-table'] };

        // Hard pass check
        const hard = checkHardPass(t);
        if (!hard.pass) {
            return {
                score: 0,
                eligible: false,
                hardPass: hard,
                mustHave: { pass: false, reasons: ['skipped'] },
                reasons: hard.reasons
            };
        }

        // Must-have check
        const must = checkMustHave(t);
        if (!must.pass) {
            return {
                score: 0,
                eligible: false,
                hardPass: hard,
                mustHave: must,
                reasons: must.reasons
            };
        }

        // Calculate bonus score
        const bonus = calcBonusScore(t);
        const baseScore = 50; // Base score for passing all checks
        const finalScore = Math.min(100, baseScore + bonus);

        return {
            score: finalScore,
            eligible: true,
            hardPass: hard,
            mustHave: must,
            bonus,
            reasons: []
        };
    };

    // ═══════════════════════════════════════════════════════════════════════
    // SELECTION FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    // Get all tables with scores
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
                last10: seq.slice(-10).join('')
            };
        });
    };

    // Get eligible tables sorted by score (best first)
    const getEligible = () => {
        return getAllScored()
            .filter(t => t.eligible)
            .sort((a, b) => b.score - a.score);
    };

    // Get best table
    const getBest = () => {
        const eligible = getEligible();
        return eligible[0] || null;
    };

    // Quick pick for play.js
    const pick = () => {
        const table = getBest();
        if (!table) return null;
        return { table, score: table.score };
    };

    // ═══════════════════════════════════════════════════════════════════════
    // API
    // ═══════════════════════════════════════════════════════════════════════

    window.pick = {
        // Rules (modifiable at runtime)
        rules: Rules,

        // Scoring
        score: scoreTable,
        scoreAll: getAllScored,

        // Selection
        eligible: getEligible,
        all: getEligible, // Alias
        best: getBest,
        pick,

        // Helpers
        ratio: calcRatio,
        tieRatio: calcTieRatio,
        streak: (t) => detectStreak(getSequence(t)),
        alternations: (t) => countAlternations(getSequence(t).slice(-10)),
        hasStreak: (t) => hasStreakPattern(getSequence(t).slice(-20)),
        isSpeed: isSpeedTable,

        // Status display
        status: () => {
            const all = getAllScored();
            const eligible = all.filter(t => t.eligible);
            const rejected = all.filter(t => !t.eligible && t.total >= 20);

            console.log(`
╔══════════════════════════════════════════════════════════════╗
║            MARTINGALE TABLE SCORES (${eligible.length}/${all.length} eligible)            ║
╠══════════════════════════════════════════════════════════════╣`);

            if (eligible.length === 0) {
                console.log('║  No eligible tables found                                    ║');
            } else {
                eligible.slice(0, 10).forEach((t, i) => {
                    const name = (t.name || t.gameId || '?').slice(0, 16).padEnd(16);
                    const bet = t.canBet ? '✓' : ' ';
                    const str = t.streak.length > 1 ? `${t.streak.length}${t.streak.side}` : '--';
                    console.log(
                        `║ ${String(i+1).padStart(2)}.${bet} ${name} ` +
                        `S:${String(t.score).padStart(2)} ` +
                        `P:${String(t.P||0).padStart(2)} B:${String(t.B||0).padStart(2)} ` +
                        `r:${t.ratio.toFixed(2)} ${str.padEnd(3)} [${t.last10}]`
                    );
                });
            }

            console.log('╠══════════════════════════════════════════════════════════════╣');
            console.log('║  REJECTED (top reasons):                                     ║');

            // Show rejection reasons summary
            const reasonCounts = {};
            rejected.forEach(t => {
                t.reasons.forEach(r => {
                    const key = r.split(':')[0];
                    reasonCounts[key] = (reasonCounts[key] || 0) + 1;
                });
            });
            Object.entries(reasonCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5)
                .forEach(([reason, count]) => {
                    console.log(`║  • ${reason}: ${count} tables`.padEnd(63) + '║');
                });

            console.log('╚══════════════════════════════════════════════════════════════╝');
        },

        // Quick single-table check
        check: (uidOrId) => {
            const t = window.pp?.get(uidOrId);
            if (!t) {
                console.log('Table not found');
                return null;
            }

            const result = scoreTable(t);
            const seq = getSequence(t);

            console.log(`
╔══════════════════════════════════════════════════════════════╗
║  TABLE: ${(t.name || t.gameId || '?').slice(0, 40).padEnd(40)}        ║
╠══════════════════════════════════════════════════════════════╣
║  Score: ${String(result.score).padStart(3)} / 100    Eligible: ${result.eligible ? 'YES ✓' : 'NO ✗'}                    ║
║  P: ${String(t.P||0).padStart(2)}  B: ${String(t.B||0).padStart(2)}  T: ${String(t.T||0).padStart(2)}  Total: ${String(t.total||0).padStart(3)}                        ║
║  Ratio: ${calcRatio(t).toFixed(3)}   Tie%: ${(calcTieRatio(t)*100).toFixed(1)}%                              ║
║  Last 10: ${seq.slice(-10).join('').padEnd(10)}                                      ║
╠══════════════════════════════════════════════════════════════╣`);

            if (!result.eligible) {
                console.log('║  REJECTED:                                                   ║');
                result.reasons.forEach(r => {
                    console.log(`║  ✗ ${r}`.padEnd(63) + '║');
                });
            } else {
                console.log('║  PASSED ALL CHECKS                                           ║');
                console.log(`║  Bonus score: +${result.bonus}`.padEnd(63) + '║');
            }

            console.log('╚══════════════════════════════════════════════════════════════╝');
            return result;
        },

        // Help
        help: () => {
            console.log(`
╔══════════════════════════════════════════════════════════════╗
║              MARTINGALE PICKER v2.0 - HELP                   ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  SCORING SYSTEM                                              ║
║  ──────────────                                              ║
║  Score 0 = REJECTED (fails hard pass or must-have rules)     ║
║  Score 50+ = ELIGIBLE (passes all checks + bonus)            ║
║  Score 100 = IDEAL (all bonuses)                             ║
║                                                              ║
║  HARD PASS RULES (fail ONE = reject)                         ║
║  • total < 30 (too early)                                    ║
║  • ties > 12% (tie pollution)                                ║
║  • alternations ≥ 7 in last 10 (chop)                        ║
║  • Speed Baccarat table                                      ║
║                                                              ║
║  MUST-HAVE RULES (ALL must pass)                             ║
║  • total ≥ 40 (enough history)                               ║
║  • 0.05 ≤ ratio ≤ 0.25 (safe zone)                           ║
║  • BB/PP pattern in last 20 (streak evidence)                ║
║  • last 6 not pure alternation                               ║
║  • canBet = true                                             ║
║                                                              ║
║  COMMANDS                                                    ║
║  ────────                                                    ║
║  pick.status()      Show all scored tables                   ║
║  pick.check(1)      Check specific table                     ║
║  pick.eligible()    Get eligible tables (sorted)             ║
║  pick.best()        Get best table                           ║
║  pick.pick()        Get {table, score} for play.js           ║
║  pick.score(t)      Score a table object                     ║
║                                                              ║
║  CUSTOMIZE                                                   ║
║  ─────────                                                   ║
║  pick.rules.MUST_MIN_TOTAL = 50    // Stricter history       ║
║  pick.rules.HARD_REJECT_SPEED = false  // Allow speed        ║
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
        console.log('[Pick] v2.0 | Martingale table scoring');
        console.log('[Pick] Commands: pick.status() pick.check(uid) pick.help()');
    });

})();
