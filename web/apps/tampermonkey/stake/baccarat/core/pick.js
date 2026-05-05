// ==UserScript==
// @name         pick
// @namespace    http://tampermonkey.net/
// @version      3.2
// @description  Table scoring - finds random/fair tables (high chop, balanced P/B, low ties)
// @author       You
// @match        *://client.pragmaticplaylive.net/*
// @match        *://*.stake.com/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    // ═══════════════════════════════════════════════════════════════════════
    // SCORING SYSTEM v3.2 - Randomness-Based Selection
    // ═══════════════════════════════════════════════════════════════════════
    //
    // Goal: Find tables that behave like TRUE RANDOM coin flips
    //   ✓ High alternation/chop (random P↔B switches)
    //   ✓ Balanced P/B ratio (~50/50)
    //   ✓ Low tie interference
    //   ✓ No suspicious long streaks
    //   ✓ Enough history to judge
    //
    // Score 0-100, higher = more random = better
    // Minimum eligible: 35

    const Config = {
        MIN_ELIGIBLE_SCORE: 35,
        HARD_MIN_TOTAL: 30,
        HARD_MIN_CHOP_12: 3,      // 3 or fewer alternations in 12 = too streaky, suspicious
    };

    // ═══════════════════════════════════════════════════════════════════════
    // HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    const getSequence = (t) => {
        if (!window.pp) return [];
        const id = t?.uid || t?.gameId || t?.id || t;
        return window.pp.pbt(id) || [];
    };

    const getLive = (t) => {
        if (!window.pp) return null;
        const id = t?.uid || t?.gameId || t?.id || t;
        return window.pp.live(id) || null;
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
        if (altIn12 <= Config.HARD_MIN_CHOP_12) {
            return { score: 0, eligible: false, reasons: [`too-streaky: only ${altIn12}/11 alternations (suspicious)`], breakdown: {} };
        }

        // ─────────────────────────────────────────────────────────────────────
        // 1. HISTORY DEPTH (0-15 pts)
        // ─────────────────────────────────────────────────────────────────────
        if (total >= 60) breakdown.history = 15;
        else if (total >= 50) breakdown.history = 12;
        else if (total >= 40) breakdown.history = 8;
        else breakdown.history = 4;

        // ─────────────────────────────────────────────────────────────────────
        // 2. P/B BALANCE (-10 to 40 pts) - CRITICAL FACTOR
        // ─────────────────────────────────────────────────────────────────────
        const ratio = Math.abs(P - B) / total;
        if (ratio <= 0.03) {
            breakdown.balance = 40; // Near perfect balance
        } else if (ratio <= 0.06) {
            breakdown.balance = 36; // Excellent
        } else if (ratio <= 0.10) {
            breakdown.balance = 30; // Very good
        } else if (ratio <= 0.15) {
            breakdown.balance = 22; // Good
        } else if (ratio <= 0.20) {
            breakdown.balance = 12; // Acceptable
            notes.push('slightly-skewed');
        } else if (ratio <= 0.28) {
            breakdown.balance = 4;  // Skewed
            notes.push('skewed-ratio');
        } else {
            breakdown.balance = -10; // Very skewed, heavy penalty
            notes.push('very-skewed');
        }

        // ─────────────────────────────────────────────────────────────────────
        // 3. TIE RATIO (-25 to +30 pts) - CRITICAL FACTOR
        // ─────────────────────────────────────────────────────────────────────
        const tieRatio = T / total;
        if (tieRatio < 0.03) breakdown.ties = 30;       // Excellent, very few ties
        else if (tieRatio < 0.05) breakdown.ties = 25;  // Great
        else if (tieRatio < 0.07) breakdown.ties = 18;  // Good
        else if (tieRatio < 0.09) breakdown.ties = 12;  // Acceptable
        else if (tieRatio < 0.11) breakdown.ties = 6;   // Borderline
        else if (tieRatio < 0.13) breakdown.ties = 0;   // Neutral
        else if (tieRatio < 0.16) {
            breakdown.ties = -12;
            notes.push(`elevated-ties: ${(tieRatio*100).toFixed(0)}%`);
        } else {
            breakdown.ties = -25;  // Heavy penalty for high ties
            notes.push(`high-ties: ${(tieRatio*100).toFixed(0)}%`);
        }

        // ─────────────────────────────────────────────────────────────────────
        // 4. PATTERN QUALITY - Last 20 (0-25 pts)
        // Prefer balanced mix of short runs, penalize long streaks
        // ─────────────────────────────────────────────────────────────────────
        const last20 = seq.slice(-20);
        const alt20 = countAlternations(last20);
        const longest = longestStreak(last20);
        
        // Ideal: ~9-11 alternations in 20 hands (random)
        breakdown.patternQuality = 0;
        if (alt20 >= 12) {
            breakdown.patternQuality = 20; // Very random
        } else if (alt20 >= 9) {
            breakdown.patternQuality = 16; // Good randomness
        } else if (alt20 >= 7) {
            breakdown.patternQuality = 10; // Acceptable
        } else if (alt20 >= 5) {
            breakdown.patternQuality = 4;  // Low randomness
        } else {
            breakdown.patternQuality = -5; // Too streaky
            notes.push('low-randomness-20');
        }

        // Penalty for very long streaks (suspicious)
        if (longest.length >= 6) {
            breakdown.patternQuality -= 10;
            notes.push(`suspicious-streak: ${longest.length}${longest.side}`);
        } else if (longest.length >= 5) {
            breakdown.patternQuality -= 5;
        }

        // ─────────────────────────────────────────────────────────────────────
        // 5. RANDOMNESS SCORE - Last 12 (-15 to +15 pts)
        // More alternations = more random = better (true 50/50 game)
        // ─────────────────────────────────────────────────────────────────────
        // altIn12 already calculated (max possible = 11)
        // Ideal random: ~5-6 alternations in 12 hands
        if (altIn12 >= 8) {
            breakdown.randomness = 15;  // Very random, excellent
        } else if (altIn12 >= 6) {
            breakdown.randomness = 12;  // Good randomness
        } else if (altIn12 >= 5) {
            breakdown.randomness = 8;   // Acceptable
        } else if (altIn12 >= 4) {
            breakdown.randomness = 2;   // Low randomness
            notes.push('low-randomness');
        } else {
            breakdown.randomness = -15; // Too streaky, suspicious
            notes.push('suspicious-streaks');
        }

        // ─────────────────────────────────────────────────────────────────────
        // 6. RECENT TREND - Last 6 (-8 to +10 pts)
        // Prefer mixed/random patterns, penalize long streaks
        // ─────────────────────────────────────────────────────────────────────
        const last6 = seq.slice(-6);
        const alt6 = countAlternations(last6);
        if (alt6 >= 4) {
            breakdown.recent = 10; // Very mixed, random
        } else if (alt6 >= 3) {
            breakdown.recent = 6;  // Good mix
        } else if (alt6 >= 2) {
            breakdown.recent = 2;  // Some mix
        } else if (countPattern(last6, 'BBBB') > 0 || countPattern(last6, 'PPPP') > 0) {
            breakdown.recent = -8; // Long streak, suspicious
            notes.push('long-streak-in-6');
        } else {
            breakdown.recent = 0;
        }

        // ─────────────────────────────────────────────────────────────────────
        // 7. CURRENT STREAK (-5 to +5 pts)
        // Short streaks normal, long streaks suspicious
        // ─────────────────────────────────────────────────────────────────────
        const curStreak = currentStreak(seq);
        if (curStreak.length >= 5) {
            breakdown.currentStreak = -5; // Very long, suspicious
        } else if (curStreak.length >= 4) {
            breakdown.currentStreak = -2; // Getting long
        } else if (curStreak.length <= 2) {
            breakdown.currentStreak = 5;  // Normal/short, good
        } else {
            breakdown.currentStreak = 2;  // 3 in a row, acceptable
        }

        // ─────────────────────────────────────────────────────────────────────
        // 8. LIVE STATE / CAN BET (0-5 pts)
        // ─────────────────────────────────────────────────────────────────────
        const live = getLive(t);
        const isBlockedNow = !!(live?.dealing || live?.shuffling || live?.betsClosingSoon);
        breakdown.canBet = t.canBet === true && !isBlockedNow ? 5 : 0;
        if (isBlockedNow) notes.push('bet-window-transition');

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
            const live = getLive(t);
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
                live,
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

    // Compact live state flags:
    // D=dealing, S=shuffling, C=closing soon, V=voip active, K=card stream present
    const liveFlags = (live) => {
        if (!live) return '-----';
        return [
            live.dealing ? 'D' : '-',
            live.shuffling?.active ? 'S' : '-',
            live.betsClosingSoon ? 'C' : '-',
            live.voip ? 'V' : '-',
            (live.card || live.cardInc) ? 'K' : '-'
        ].join('');
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
║           TABLE PICKER v3.2 (${eligible.length} eligible / ${all.length} scored)                  ║
╠══════════════════════════════════════════════════════════════════════╣`);

            all.slice(0, 20).forEach((t, i) => {
                const icon = scoreIcon(t.score);
                const blocked = !!(t.live?.dealing || t.live?.shuffling || t.live?.betsClosingSoon);
                const bet = t.canBet && !blocked ? '✓' : ' ';
                const name = (t.name || '?').slice(0, 18).padEnd(18);
                const label = scoreLabel(t.score).padEnd(6);
                const str = t.streak.length > 1 ? `${t.streak.length}${t.streak.side}` : '--';
                const lf = liveFlags(t.live);
                console.log(
                    `║ ${icon}${bet} ${String(t.score).padStart(2)} ${label} ${name} ` +
                    `P:${String(t.P||0).padStart(2)} B:${String(t.B||0).padStart(2)} ` +
                    `a:${t.altIn12} ${str.padEnd(3)} ${lf} ${t.last12.slice(-10)}`
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
                const lf = liveFlags(t.live);
                console.log(
                    `${i+1}. ${scoreIcon(t.score)} ${t.name} | Score: ${t.score} | ` +
                    `P:${t.P} B:${t.B} | Streak: ${cur.length}${cur.side||''} | ` +
                    `Live:${lf} | Last: ${t.last12.slice(-8)}`
                );
            });
            console.log('');
        },

        live: (uidOrId) => window.pp?.live(uidOrId) || null,

        help: () => {
            console.log(`
╔══════════════════════════════════════════════════════════════════════╗
║                    TABLE PICKER v3.2 (Randomness)                    ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  SCORING (0-100, need 35+ to be eligible)                            ║
║  ────────────────────────────────────────                            ║
║  history       0-15    More rounds = more reliable                   ║
║  balance    -10-40    ★★ P/B equality (≤0.06 = 36+)                  ║
║  ties       -25-30    ★★ Low ties (<5% = 25+)                        ║
║  patternQuality-15-20  ★ Randomness in last 20                       ║
║  randomness  -15-15    ★ More alternations = better                  ║
║  recent       -8-10    Last 6 randomness                             ║
║  currentStreak -5-5    Short streaks good, long bad                  ║
║  canBet        0-5     Betting open bonus                            ║
║                                                                      ║
║  HARD PASS (score = 0)                                               ║
║  • total < 30                                                        ║
║  • ≤3 alternations in last 12 (too streaky, suspicious)              ║
║                                                                      ║
║  COMMANDS                                                            ║
║  ────────                                                            ║
║  pick.status()      All tables ranked by score                       ║
║  pick.summary()     Quick top 5 list                                 ║
║  pick.check(1)      Detailed breakdown for table                     ║
║  pick.live(1)       Show grouped live stream from pp.live()          ║
║  Live flags in status/summary: D=dealing S=shuffle C=closing V=voip K=card ║
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
        console.log('[Pick] v3.2 | Randomness + live-state awareness');
        console.log('[Pick] Commands: pick.status() pick.summary() pick.check(uid) pick.live(uid)');
    });

})();
