// ==UserScript==
// @name         pick
// @namespace    http://tampermonkey.net/
// @version      3.0
// @description  Martingale table scoring - redesigned from real data analysis
// @author       You
// @match        *://client.pragmaticplaylive.net/*
// @match        *://*.stake.com/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    // ═══════════════════════════════════════════════════════════════════════
    // SCORING SYSTEM v3.0 - Based on Real Data Analysis
    // ═══════════════════════════════════════════════════════════════════════
    //
    // Martingale needs: 
    //   ✓ Streaky patterns (not choppy)
    //   ✓ Balanced P/B ratio
    //   ✓ Low tie interference
    //   ✓ Enough history
    //
    // Score 0-100, higher = better for Martingale
    // Minimum eligible: 35

    const Config = {
        MIN_ELIGIBLE_SCORE: 35,
        HARD_MIN_TOTAL: 30,
        HARD_MAX_CHOP_12: 9,      // 9+ alternations in 12 = pure chop
    };

    // ═══════════════════════════════════════════════════════════════════════
    // HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    const getSequence = (t) => {
        if (!window.pp) return [];
        const id = t?.uid || t?.gameId || t?.id || t;
        return window.pp.pbt(id) || [];
    };

    // Count alternations (P→B or B→P transitions, ignoring T)
    const countAlternations = (seq) => {
        const filtered = seq.filter(x => x !== 'T');
        if (filtered.length < 2) return 0;
        let alt = 0;
        for (let i = 1; i < filtered.length; i++) {
            if (filtered[i] !== filtered[i-1]) alt++;
        }
        return alt;
    };

    // Find longest streak in sequence
    const longestStreak = (seq) => {
        if (!seq || seq.length === 0) return { side: null, length: 0 };
        let maxLen = 1, maxSide = seq[0];
        let curLen = 1, curSide = seq[0];
        
        for (let i = 1; i < seq.length; i++) {
            if (seq[i] === curSide || seq[i] === 'T') {
                if (seq[i] !== 'T') curLen++;
            } else {
                if (curLen > maxLen) { maxLen = curLen; maxSide = curSide; }
                curLen = 1;
                curSide = seq[i];
            }
        }
        if (curLen > maxLen) { maxLen = curLen; maxSide = curSide; }
        return { side: maxSide, length: maxLen };
    };

    // Current streak at end
    const currentStreak = (seq) => {
        if (!seq || seq.length === 0) return { side: null, length: 0 };
        const filtered = seq.filter(x => x !== 'T');
        if (filtered.length === 0) return { side: null, length: 0 };
        const last = filtered[filtered.length - 1];
        let count = 0;
        for (let i = filtered.length - 1; i >= 0; i--) {
            if (filtered[i] === last) count++;
            else break;
        }
        return { side: last, length: count };
    };

    // Count pattern occurrences
    const countPattern = (seq, pattern) => {
        const str = seq.join('');
        let count = 0, idx = 0;
        while ((idx = str.indexOf(pattern, idx)) !== -1) { count++; idx++; }
        return count;
    };

    // Check if last N is pure alternation
    const isPureAlt = (seq) => {
        const filtered = seq.filter(x => x !== 'T');
        if (filtered.length < 4) return false;
        for (let i = 1; i < filtered.length; i++) {
            if (filtered[i] === filtered[i-1]) return false;
        }
        return true;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // SCORING ENGINE
    // ═══════════════════════════════════════════════════════════════════════

    const scoreTable = (t) => {
        if (!t) return { score: 0, eligible: false, reasons: ['no-table'] };

        const seq = getSequence(t);
        const total = t.total || 0;
        const P = t.P || 0;
        const B = t.B || 0;
        const T = t.T || 0;

        const breakdown = {};
        const notes = [];

        // ─────────────────────────────────────────────────────────────────────
        // HARD PASS
        // ─────────────────────────────────────────────────────────────────────

        if (total < Config.HARD_MIN_TOTAL) {
            return { score: 0, eligible: false, reasons: [`too-early: ${total} < ${Config.HARD_MIN_TOTAL}`], breakdown: {} };
        }

        const last12 = seq.slice(-12);
        const altIn12 = countAlternations(last12);
        if (altIn12 >= Config.HARD_MAX_CHOP_12) {
            return { score: 0, eligible: false, reasons: [`extreme-chop: ${altIn12}/11 in last 12`], breakdown: {} };
        }

        // ─────────────────────────────────────────────────────────────────────
        // 1. HISTORY DEPTH (0-15 pts)
        // ─────────────────────────────────────────────────────────────────────
        if (total >= 60) breakdown.history = 15;
        else if (total >= 50) breakdown.history = 12;
        else if (total >= 40) breakdown.history = 8;
        else breakdown.history = 4;

        // ─────────────────────────────────────────────────────────────────────
        // 2. P/B BALANCE (0-20 pts)
        // ─────────────────────────────────────────────────────────────────────
        const ratio = Math.abs(P - B) / total;
        if (ratio <= 0.05) {
            breakdown.balance = 12; // Suspiciously balanced
            notes.push('very-balanced');
        } else if (ratio <= 0.12) {
            breakdown.balance = 20; // Ideal
        } else if (ratio <= 0.20) {
            breakdown.balance = 15; // Good
        } else if (ratio <= 0.30) {
            breakdown.balance = 8;  // Skewed
            notes.push('skewed-ratio');
        } else {
            breakdown.balance = 0;  // Very skewed
            notes.push('very-skewed');
        }

        // ─────────────────────────────────────────────────────────────────────
        // 3. TIE RATIO (-10 to +12 pts)
        // ─────────────────────────────────────────────────────────────────────
        const tieRatio = T / total;
        if (tieRatio < 0.05) breakdown.ties = 12;
        else if (tieRatio < 0.08) breakdown.ties = 8;
        else if (tieRatio < 0.12) breakdown.ties = 4;
        else if (tieRatio < 0.15) breakdown.ties = 0;
        else {
            breakdown.ties = -10;
            notes.push(`high-ties: ${(tieRatio*100).toFixed(0)}%`);
        }

        // ─────────────────────────────────────────────────────────────────────
        // 4. STREAK QUALITY - Last 20 (0-25 pts)
        // ─────────────────────────────────────────────────────────────────────
        const last20 = seq.slice(-20);
        const hasBBB = countPattern(last20, 'BBB') > 0;
        const hasPPP = countPattern(last20, 'PPP') > 0;
        const hasBB = countPattern(last20, 'BB') > 0;
        const hasPP = countPattern(last20, 'PP') > 0;

        breakdown.streakQuality = 0;
        if (hasBBB || hasPPP) {
            breakdown.streakQuality = 18;
        } else if (hasBB && hasPP) {
            breakdown.streakQuality = 14;
        } else if (hasBB || hasPP) {
            breakdown.streakQuality = 8;
        } else {
            notes.push('no-streak-pattern');
        }

        // Bonus for longest streak
        const longest = longestStreak(seq);
        const streakBonus = Math.min(7, longest.length - 1);
        breakdown.streakQuality += Math.max(0, streakBonus);

        // ─────────────────────────────────────────────────────────────────────
        // 5. CHOP PENALTY - Last 12 (-15 to +15 pts)
        // ─────────────────────────────────────────────────────────────────────
        // altIn12 already calculated
        if (altIn12 <= 4) {
            breakdown.chop = 15;  // Streaky, great
        } else if (altIn12 <= 6) {
            breakdown.chop = 10;  // Some structure
        } else if (altIn12 <= 7) {
            breakdown.chop = 5;   // Borderline
        } else if (altIn12 <= 8) {
            breakdown.chop = -5;  // Choppy
            notes.push('choppy-recent');
        } else {
            breakdown.chop = -15; // Very choppy (shouldn't reach here due to hard pass)
        }

        // ─────────────────────────────────────────────────────────────────────
        // 6. RECENT TREND - Last 6 (-8 to +10 pts)
        // ─────────────────────────────────────────────────────────────────────
        const last6 = seq.slice(-6);
        if (isPureAlt(last6)) {
            breakdown.recent = -8;
            notes.push('pure-alt-in-6');
        } else if (countPattern(last6, 'BBB') > 0 || countPattern(last6, 'PPP') > 0) {
            breakdown.recent = 10; // Strong streak recently
        } else if (countPattern(last6, 'BB') > 0 || countPattern(last6, 'PP') > 0) {
            breakdown.recent = 6;
        } else {
            breakdown.recent = 2;
        }

        // ─────────────────────────────────────────────────────────────────────
        // 7. CURRENT STREAK BONUS (0-8 pts)
        // ─────────────────────────────────────────────────────────────────────
        const curStreak = currentStreak(seq);
        if (curStreak.length >= 4) {
            breakdown.currentStreak = 8;
        } else if (curStreak.length >= 3) {
            breakdown.currentStreak = 5;
        } else if (curStreak.length >= 2) {
            breakdown.currentStreak = 2;
        } else {
            breakdown.currentStreak = 0;
        }

        // ─────────────────────────────────────────────────────────────────────
        // 8. CAN BET (0-5 pts)
        // ─────────────────────────────────────────────────────────────────────
        breakdown.canBet = t.canBet === true ? 5 : 0;

        // ─────────────────────────────────────────────────────────────────────
        // FINAL SCORE
        // ─────────────────────────────────────────────────────────────────────
        let totalScore = Object.values(breakdown).reduce((a, b) => a + b, 0);
        totalScore = Math.max(1, Math.min(100, totalScore));

        const eligible = totalScore >= Config.MIN_ELIGIBLE_SCORE;

        return {
            score: totalScore,
            eligible,
            breakdown,
            notes,
            reasons: eligible ? [] : notes
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
            const total = t.total || 0;
            const ratio = total > 0 ? Math.abs((t.P||0) - (t.B||0)) / total : 0;
            const tieRatio = total > 0 ? (t.T||0) / total : 0;
            return {
                ...t,
                ...result,
                ratio,  // Keep as number for calculations
                ratioStr: ratio.toFixed(3),  // String for display
                tieRatio,  // Keep as number
                tieRatioStr: (tieRatio * 100).toFixed(1) + '%',  // String for display
                streak: currentStreak(seq),
                longest: longestStreak(seq),
                altIn12: countAlternations(seq.slice(-12)),
                last12: seq.slice(-12).join('')
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

    const getBest = () => getEligible()[0] || null;

    const pick = () => {
        const table = getBest();
        if (!table) return null;
        return { table, score: table.score };
    };

    // Get top N tables
    const topN = (n = 5) => getEligible().slice(0, n);

    // ═══════════════════════════════════════════════════════════════════════
    // DISPLAY
    // ═══════════════════════════════════════════════════════════════════════

    const scoreLabel = (s) => {
        if (s === 0) return 'REJECT';
        if (s < 35) return 'POOR';
        if (s < 50) return 'FAIR';
        if (s < 65) return 'GOOD';
        if (s < 80) return 'GREAT';
        return 'IDEAL';
    };

    const scoreIcon = (s) => {
        if (s === 0) return '🔴';
        if (s < 35) return '🟠';
        if (s < 50) return '🟡';
        if (s < 65) return '🟢';
        return '💚';
    };

    // ═══════════════════════════════════════════════════════════════════════
    // API
    // ═══════════════════════════════════════════════════════════════════════

    window.pick = {
        config: Config,
        
        // Scoring
        score: scoreTable,
        scoreAll: getAllScored,
        
        // Selection
        eligible: getEligible,
        all: getAll,
        best: getBest,
        pick,
        top: topN,

        // Analysis helpers
        streak: (t) => currentStreak(getSequence(t)),
        longest: (t) => longestStreak(getSequence(t)),
        chop: (t) => countAlternations(getSequence(t).slice(-12)),

        // Status - show all tables ranked
        status: () => {
            const all = getAll();
            const eligible = all.filter(t => t.eligible);

            console.log(`
╔══════════════════════════════════════════════════════════════════════╗
║           MARTINGALE PICKS v3.0 (${eligible.length} eligible / ${all.length} scored)              ║
╠══════════════════════════════════════════════════════════════════════╣`);

            all.slice(0, 20).forEach((t, i) => {
                const icon = scoreIcon(t.score);
                const bet = t.canBet ? '✓' : ' ';
                const name = (t.name || '?').slice(0, 18).padEnd(18);
                const label = scoreLabel(t.score).padEnd(6);
                const str = t.streak.length > 1 ? `${t.streak.length}${t.streak.side}` : '--';
                console.log(
                    `║ ${icon}${bet} ${String(t.score).padStart(2)} ${label} ${name} ` +
                    `P:${String(t.P||0).padStart(2)} B:${String(t.B||0).padStart(2)} ` +
                    `a:${t.altIn12} ${str.padEnd(3)} ${t.last12.slice(-10)}`
                );
            });

            console.log('╠══════════════════════════════════════════════════════════════════════╣');
            console.log(`║  Top pick: ${getBest()?.name || 'None'} (score: ${getBest()?.score || 0})`.padEnd(71) + '║');
            console.log('╚══════════════════════════════════════════════════════════════════════╝');
        },

        // Detailed check for single table
        check: (uidOrId) => {
            const t = window.pp?.get(uidOrId);
            if (!t) { console.log('Table not found'); return null; }

            const result = scoreTable(t);
            const seq = getSequence(t);
            const cur = currentStreak(seq);
            const long = longestStreak(seq);
            const alt12 = countAlternations(seq.slice(-12));

            console.log(`
╔══════════════════════════════════════════════════════════════════════╗
║  ${(t.name || t.gameId || '?').slice(0, 50).padEnd(50)}                  ║
╠══════════════════════════════════════════════════════════════════════╣
║  SCORE: ${String(result.score).padStart(2)} / 100  ${scoreIcon(result.score)} ${scoreLabel(result.score).padEnd(6)}   Eligible: ${result.eligible ? 'YES ✓' : 'NO ✗'}             ║
╠══════════════════════════════════════════════════════════════════════╣
║  P: ${String(t.P||0).padStart(2)}  B: ${String(t.B||0).padStart(2)}  T: ${String(t.T||0).padStart(2)}  Total: ${String(t.total||0).padStart(3)}                               ║
║  Ratio: ${(Math.abs((t.P||0)-(t.B||0))/(t.total||1)).toFixed(3)}   Ties: ${((t.T||0)/(t.total||1)*100).toFixed(1)}%                                   ║
║  Alt in 12: ${alt12}   Current streak: ${cur.length}${cur.side||'-'}   Longest: ${long.length}${long.side||'-'}             ║
║  Last 12: ${seq.slice(-12).join('').padEnd(12)}                                          ║
╠══════════════════════════════════════════════════════════════════════╣
║  BREAKDOWN:                                                          ║`);

            Object.entries(result.breakdown).forEach(([k, v]) => {
                const sign = v >= 0 ? '+' : '';
                console.log(`║    ${k.padEnd(14)} ${sign}${String(v).padStart(3)}`.padEnd(71) + '║');
            });

            if (result.notes.length > 0) {
                console.log('╠══════════════════════════════════════════════════════════════════════╣');
                result.notes.forEach(n => {
                    console.log(`║  ⚠ ${n}`.padEnd(71) + '║');
                });
            }

            console.log('╚══════════════════════════════════════════════════════════════════════╝');
            return result;
        },

        // Quick summary
        summary: () => {
            const top = topN(5);
            console.log('\n═══ TOP 5 MARTINGALE PICKS ═══\n');
            top.forEach((t, i) => {
                const cur = t.streak;
                console.log(
                    `${i+1}. ${scoreIcon(t.score)} ${t.name} | Score: ${t.score} | ` +
                    `P:${t.P} B:${t.B} | Streak: ${cur.length}${cur.side||''} | ` +
                    `Last: ${t.last12.slice(-8)}`
                );
            });
            console.log('');
        },

        help: () => {
            console.log(`
╔══════════════════════════════════════════════════════════════════════╗
║                    MARTINGALE PICKER v3.0                            ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  SCORING (0-100, need 35+ to be eligible)                            ║
║  ────────────────────────────────────────                            ║
║  history       0-15    More rounds = more reliable                   ║
║  balance       0-20    P/B ratio (0.05-0.12 ideal)                   ║
║  ties        -10-12    Lower tie % = better                          ║
║  streakQuality 0-25    BBB/PPP patterns in last 20                   ║
║  chop        -15-15    Fewer alternations = better                   ║
║  recent       -8-10    Last 6 pattern quality                        ║
║  currentStreak 0-8     Active streak bonus                           ║
║  canBet        0-5     Betting open bonus                            ║
║                                                                      ║
║  HARD PASS (score = 0)                                               ║
║  • total < 30                                                        ║
║  • 9+ alternations in last 12 (extreme chop)                         ║
║                                                                      ║
║  COMMANDS                                                            ║
║  ────────                                                            ║
║  pick.status()      All tables ranked by score                       ║
║  pick.summary()     Quick top 5 list                                 ║
║  pick.check(1)      Detailed breakdown for table                     ║
║  pick.top(5)        Get top N eligible tables                        ║
║  pick.best()        Get single best table                            ║
║  pick.eligible()    All eligible tables                              ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
`);
        }
    };

    // ═══════════════════════════════════════════════════════════════════════
    // INIT
    // ═══════════════════════════════════════════════════════════════════════

    const waitForPP = () => new Promise(resolve => {
        const check = () => window.pp ? resolve() : setTimeout(check, 100);
        check();
    });

    waitForPP().then(() => {
        console.log('[Pick] v3.0 | Redesigned from real data');
        console.log('[Pick] Commands: pick.status() pick.summary() pick.check(uid)');
    });

})();
