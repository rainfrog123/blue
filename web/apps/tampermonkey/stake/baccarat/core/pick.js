// ==UserScript==
// @name         pick
// @namespace    http://tampermonkey.net/
// @version      4.0.5
// @description  Table filter — PP ping-pong depth + fairness firewall (tie/PB/crowd). multibaccarat page only.
// @author       You
// @match        *://client.pragmaticplaylive.net/desktop/multibaccarat*
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    /**
     * v4.0 — "Absurdity firewall" + chop signal from PP payloads
     * Prefer: goodroadLive / goodRoadsDepthMap playerPingPongDepth & bankerPingPongDepth
     * Prefer: betstats playerpercentage / bankerpercentage (crowd)
     * Fallback: shallow alternations in last-12 when depths missing (labelled in diagnostics)
     */

    const Config = {
        MIN_TOTAL: 30,              // Ghost tables — not enough rounds
        MAX_TIE_RATIO: 0.12,        // ~12%+ ties ⇒ reject ("tie storm")
        MAX_PB_GAP_RATIO: 0.10,     // |P-B|/total > 10% ⇒ reject ("gravity")
        MAX_CROWD_PCT: 85,          // Either side ≥ 85% ⇒ reject (percent units 0..100)

        REQUIRE_BETSTATS_FOR_CROWD: false,

        MIN_EFFECTIVE_DEPTH: 0,     // Extra gate: chop depth gate (PP uses max of both depths); 0 = off

        // Display score clamps
        DISPLAY_SCORE_ELIGIBLE_MIN: 50,
        DISPLAY_SCORE_ELIGIBLE_MAX: 100,
    };

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

    const n = (v) => {
        if (v == null || v === '') return null;
        const x = typeof v === 'number' ? v : parseFloat(String(v).replace(/%/g, ''));
        return Number.isFinite(x) ? x : null;
    };

    /** If value looks like ratio 0..1 convert to percentage for crowd compare */
    const asPercentMaybe = (v) => {
        const x = n(v);
        if (x == null) return null;
        if (x > 0 && x <= 1) return x * 100;
        return x;
    };

    const countAlternations = (seq) => {
        const filtered = (seq || []).filter(x => x !== 'T');
        if (filtered.length < 2) return 0;
        let alt = 0;
        for (let i = 1; i < filtered.length; i++) {
            if (filtered[i] !== filtered[i - 1]) alt++;
        }
        return alt;
    };

    const walkForCrowdPct = (obj, maxDepth = 6) => {
        let player = null;
        let banker = null;
        const visit = (o, d) => {
            if (!o || typeof o !== 'object' || d > maxDepth) return;
            if (Array.isArray(o)) {
                for (const it of o) visit(it, d + 1);
                return;
            }
            for (const [key, val] of Object.entries(o)) {
                const kl = key.toLowerCase().replace(/\s+/g, '');
                if (/^playerperc/.test(kl) || kl === 'playerpercentage' || kl === 'pctplayer') {
                    const p = asPercentMaybe(val);
                    if (p != null) player = player == null ? p : Math.max(player, p);
                }
                if (/^bankerperc/.test(kl) || kl === 'bankerpercentage' || kl === 'pctbanker') {
                    const b = asPercentMaybe(val);
                    if (b != null) banker = banker == null ? b : Math.max(banker, b);
                }
                if (val != null && typeof val === 'object') visit(val, d + 1);
            }
        };
        visit(obj, 0);
        return { player, banker };
    };

    /** Pull ping-pong depth from known maps or deep-scan goodroad payload */
    const extractPingPongDepths = (t) => {
        let pp = 0;
        let bp = 0;
        let source = '';

        // Game WS goodroad — same as working play.js / console snippet (parseInt on top-level keys)
        const gl = t?.goodroadLive;
        if (gl && typeof gl === 'object') {
            const a = parseInt(gl.playerPingPongDepth || 0, 10);
            const b = parseInt(gl.bankerPingPongDepth || 0, 10);
            pp = Number.isFinite(a) ? a : 0;
            bp = Number.isFinite(b) ? b : 0;
            source = 'goodroadLive';
        }

        const takeMap = (m, label) => {
            if (!m || typeof m !== 'object') return;
            const a = n(m.playerPingPongDepth ?? m.playerpingpongdepth);
            const b = n(m.bankerPingPongDepth ?? m.bankerpingpongdepth);
            if (a != null) {
                pp = Math.max(pp, a);
                if (!source) source = label;
            }
            if (b != null) {
                bp = Math.max(bp, b);
                if (!source) source = label;
            }
        };

        takeMap(t?.goodRoadsDepthMap, 'goodRoadsDepthMap');

        const deepPing = (root, label) => {
            if (!root || typeof root !== 'object') return;
            const scan = (o, depth) => {
                if (!o || typeof o !== 'object' || depth > 5) return;
                for (const [k, v] of Object.entries(o)) {
                    const kl = k.toLowerCase();
                    if (/pingpong.*depth|ping_pong.*depth/.test(kl) ||
                        (/pingpong/.test(kl) && /depth/.test(kl))) {
                        const num = n(v);
                        if (num != null) {
                            if (/player/.test(kl)) pp = Math.max(pp, num);
                            else if (/banker/.test(kl)) bp = Math.max(bp, num);
                            else if (pp === 0 && bp === 0) {
                                pp = num;
                                source = source || label + '-ambiguous';
                            }
                        }
                    } else if (v != null && typeof v === 'object') scan(v, depth + 1);
                }
            };
            scan(root, 0);
            if ((pp > 0 || bp > 0) && !source) source = label;
        };

        if (pp === 0 && bp === 0) deepPing(t?.goodroadLive, 'goodroadLive-scan');

        const effective = Math.max(pp, bp);
        const depthSource = effective > 0 ? (source || 'payload') : 'none';

        return { pp, bp, effective, depthSource };
    };

    const scoreTable = (t) => {
        if (!t) {
            return {
                score: 0,
                eligible: false,
                reasons: ['no-table'],
                breakdown: {},
                firewall: {},
                diagnostics: {},
            };
        }

        const total = t.total ?? 0;
        const P = t.P ?? 0;
        const B = t.B ?? 0;
        const Tie = t.T ?? 0;
        const pbGapRatio = total > 0 ? Math.abs(P - B) / total : 1;
        const tieRatio = total > 0 ? Tie / total : 0;

        const firewall = [];

        // --- HARD REJECT ---
        if (total < Config.MIN_TOTAL) {
            firewall.push(`ghost: total=${total}<${Config.MIN_TOTAL}`);
            return mkReject(firewall, { total, P, B, Tie, pbGapRatio, tieRatio }, t);
        }

        if (tieRatio > Config.MAX_TIE_RATIO + 1e-9) {
            firewall.push(`tie-storm: ${(tieRatio * 100).toFixed(1)}% (> ${Config.MAX_TIE_RATIO * 100}%)`);
        }

        if (pbGapRatio > Config.MAX_PB_GAP_RATIO + 1e-9) {
            firewall.push(`gravity: |P−B|/total=${(pbGapRatio * 100).toFixed(1)}% (> ${Config.MAX_PB_GAP_RATIO * 100}%)`);
        }

        const bs = t.betstats;
        let crowd = { playerPct: null, bankerPct: null };
        if (bs && typeof bs === 'object') {
            crowd = walkForCrowdPct(bs);
            const extremes = [];
            if (crowd.playerPct != null && crowd.playerPct >= Config.MAX_CROWD_PCT + 1e-9)
                extremes.push(`playerPct=${crowd.playerPct.toFixed(1)}%`);
            if (crowd.bankerPct != null && crowd.bankerPct >= Config.MAX_CROWD_PCT + 1e-9)
                extremes.push(`bankerPct=${crowd.bankerPct.toFixed(1)}%`);
            if (extremes.length) {
                firewall.push(`crowd: ${extremes.join(', ')} (≥ ${Config.MAX_CROWD_PCT}%)`);
            }
        } else if (Config.REQUIRE_BETSTATS_FOR_CROWD) {
            firewall.push('crowd: no betstats payload');
        }

        const seq12 = countAlternations(getSequence(t).slice(-12));
        const depthInfo = extractPingPongDepths(t);

        if (Config.MIN_EFFECTIVE_DEPTH > 0 && depthInfo.effective < Config.MIN_EFFECTIVE_DEPTH) {
            firewall.push(`chop-too-low: maxDepth=${depthInfo.effective} (< ${Config.MIN_EFFECTIVE_DEPTH})`);
        }

        if (firewall.length) return mkReject(firewall, { total, P, B, Tie, pbGapRatio, tieRatio }, t, seq12, depthInfo, crowd);

        const notes = [];

        let chopContribution = depthInfo.effective;
        let chopFallback = false;
        if (depthInfo.effective === 0 && seq12 > 0) {
            chopContribution = seq12 / 11;
            chopFallback = true;
            notes.push('depth from last-12 alts (no PP depth yet)');
        }

        const tieQuality = Math.max(0, 25 - tieRatio * 200);
        const balanceQuality = Math.max(0, 55 - pbGapRatio * 200);
        const chopQuality = Math.min(40, chopContribution * (chopFallback ? 6 : 8));
        const historyQuality = Math.min(15, (total / 60) * 15);

        let displayScore =
            chopQuality +
            tieQuality +
            balanceQuality +
            historyQuality;

        displayScore = Math.round(
            Math.max(
                Config.DISPLAY_SCORE_ELIGIBLE_MIN,
                Math.min(Config.DISPLAY_SCORE_ELIGIBLE_MAX, displayScore)
            )
        );

        let canBetBonus = 0;
        // If stream says bets open, do not penalize for dealing/shuffle flags (PP often overlaps phases)
        if (t.canBet === true) canBetBonus = 5;
        displayScore = Math.round(Math.min(100, displayScore + canBetBonus));

        return {
            score: displayScore,
            eligible: true,
            firewall: [],
            reasons: [],
            notes,
            breakdown: {
                chop: Math.round(chopQuality),
                balance: Math.round(balanceQuality),
                ties: Math.round(tieQuality),
                history: Math.round(historyQuality),
                canBet: canBetBonus,
            },
            diagnostics: {
                pbGapRatio,
                tieRatio,
                seqAlternations12: seq12,
                chopFallback,
                ...depthInfo,
                crowd,
            },
        };

        function mkReject(fw, sums, tbl, sq = 0, dpt = {}, cr = {}) {
            return {
                score: 0,
                eligible: false,
                reasons: [...fw],
                firewall: [...fw],
                notes: fw,
                breakdown: {},
                diagnostics: {
                    total: sums.total,
                    P: sums.P,
                    B: sums.B,
                    T: sums.Tie,
                    pbGapRatio: sums.pbGapRatio,
                    tieRatio: sums.tieRatio,
                    seqAlternations12: sq,
                    ...(dpt && typeof dpt === 'object' ? dpt : {}),
                    crowd: cr,
                    name: tbl.name,
                    gameId: tbl.gameId,
                },
            };
        }
    };

    const comparator = (a, b) => {
        const ae = a.diagnostics?.effective ?? Math.max(a.diagnostics?.pp ?? 0, a.diagnostics?.bp ?? 0);
        const be = b.diagnostics?.effective ?? Math.max(b.diagnostics?.pp ?? 0, b.diagnostics?.bp ?? 0);
        if (be !== ae) return be - ae;

        const ar = Math.abs(a.P - a.B) / (a.total || 1);
        const br = Math.abs(b.P - b.B) / (b.total || 1);
        if (ar !== br) return ar - br;

        const at = (a.T || 0) / (a.total || 1);
        const bt = (b.T || 0) / (b.total || 1);
        if (at !== bt) return at - bt;

        return (b.total || 0) - (a.total || 0);
    };

    const getAllScored = () => {
        if (!window.pp) return [];
        const tables = Object.values(window.pp.tables());
        return tables.map(t => {
            const result = scoreTable(t);
            const seq = getSequence(t);
            const live = getLive(t);
            const total = t.total || 0;
            const ratio = total > 0 ? Math.abs((t.P || 0) - (t.B || 0)) / total : 0;
            const tieRatio = total > 0 ? (t.T || 0) / total : 0;
            const diagnostics = result.diagnostics || {};
            const currentStreak = (() => {
                const fx = seq.filter(x => x !== 'T');
                if (!fx.length) return { side: null, length: 0 };
                const last = fx[fx.length - 1];
                let len = 0;
                for (let i = fx.length - 1; i >= 0; i--) {
                    if (fx[i] !== last) break;
                    len++;
                }
                return { side: last, length: len };
            })();
            const streak = currentStreak;
            return {
                ...t,
                ...result,
                ratio,
                ratioStr: ratio.toFixed(3),
                tieRatio,
                tieRatioStr: `${(tieRatio * 100).toFixed(1)}%`,
                live,
                streak,
                last12: seq.slice(-12).join(''),
                altIn12: countAlternations(seq.slice(-12)),
                pingPong: {
                    pp: diagnostics.pp ?? null,
                    bp: diagnostics.bp ?? null,
                    effective: diagnostics.effective ?? 0,
                    source: diagnostics.depthSource,
                },
            };
        }).sort(comparator);
    };

    const getEligible = () => getAllScored().filter(x => x.eligible);

    /** Everything sorted (eligible + rejected — rejected score 0) */
    const getRankedAll = () => getAllScored();

    const getBest = () => getEligible()[0] || null;

    const pick = () => {
        const table = getBest();
        if (!table) return null;
        return { table, score: table.score };
    };

    const topN = (n = 5) => getEligible().slice(0, n);

    const scoreLabel = (s, eligible) => {
        if (!eligible) return 'REJECT';
        if (s < 58) return 'FAIR';
        if (s < 68) return 'GOOD';
        if (s < 80) return 'GREAT';
        return 'IDEAL';
    };

    const scoreIcon = (s, eligible) => {
        if (!eligible) return '🔴';
        if (s < 58) return '🟡';
        if (s < 68) return '🟢';
        if (s < 80) return '💚';
        return '⭐️';
    };

    const liveFlags = (live) => {
        if (!live) return '-----';
        return [
            live.dealing ? 'D' : '-',
            live.shuffling?.active ? 'S' : '-',
            live.betsClosingSoon ? 'C' : '-',
            live.voip ? 'V' : '-',
            (live.card || live.cardInc) ? 'K' : '-',
        ].join('');
    };

    /** Console display only — raw `name` from API may use underscores */
    const displayTableName = (s) => String(s ?? '').replace(/_/g, ' ');

    window.pick = {
        config: Config,

        score: scoreTable,
        scoreAll: getAllScored,

        eligible: getEligible,
        all: getRankedAll,
        ranked: getRankedAll,
        best: getBest,
        pick,
        top: topN,

        chop: (t) => extractPingPongDepths(t).effective || countAlternations(getSequence(t).slice(-12)),

        status: () => {
            const all = getRankedAll();
            const eligible = all.filter(t => t.eligible);
            const line = () => `${'═'.repeat(74)}`;

            console.log(`
${line()}
║ TABLE PICKER v4 (${eligible.length} eligible / ${all.length} total) ${' '.repeat(Math.max(0, 74 - 44))} ║
${line()}
  Sort: PingPong depth (PP) ↑  →  balance |P−B|/total ↑  →  tie % ↑`);

            eligible.slice(0, 22).forEach((t) => {
                const icon = scoreIcon(t.score, true);
                const bet = t.canBet ? '✓' : ' ';
                const name = displayTableName(t.name || '?').slice(0, 16).padEnd(16);
                const chop = `${t.pingPong.effective}`.padStart(3);
                const gap = `${(Math.abs((t.P || 0) - (t.B || 0)) / (t.total || 1) * 100).toFixed(0)}%`;
                console.log(`${icon}${bet} s:${String(t.score).padStart(3)} chop:${chop} gap:${gap.padStart(4)} ` +
                    `T%:${parseFloat(String(t.tieRatioStr).replace('%', '')).toFixed(0).padStart(2)}% ` +
                    `${name} #${t.uid} ${liveFlags(t.live)}`);
            });
            const bestPick = getBest();
            console.log(`${line()}
  Best: ${bestPick ? displayTableName(bestPick.name) : '(none)'} · pick.best() · pick.summary()
${line()}
`);
        },

        check: (uidOrId) => {
            const t = window.pp?.get(uidOrId);
            if (!t) {
                console.log('Table not found');
                return null;
            }

            const r = scoreTable(t);
            const d = r.diagnostics || {};
            console.log(`
┌────────────────────────────────────────────────────────────
│ ${displayTableName(t.name || t.gameId).slice(0, 54)}
│ id ${t.uid} · game ${(t.gameId || '').slice(0, 32)}
├────────────────────────────────────────────────────────────
│ PASS firewall: ${r.eligible ? 'YES ✓' : 'NO ✗'}   display score: ${r.score}
└────────────────────────────────────────────────────────────`);

            console.log(`  Shoe   P:${t.P} B:${t.B} T:${t.T} total:${t.total}`);
            console.log(`  |P−B|/total: ${((d.pbGapRatio ?? 0) * 100).toFixed(2)}%  (reject if > ${Config.MAX_PB_GAP_RATIO * 100}%)`);
            console.log(`  ties/total:   ${((d.tieRatio ?? 0) * 100).toFixed(2)}%  (reject if > ${Config.MAX_TIE_RATIO * 100}%)`);
            console.log(`  Chop depth   PP:${d.pp ?? '—'}  BP:${d.bp ?? '—'}  max:${d.effective ?? 0}  [${d.depthSource}]`);
            const cr = d.crowd || {};
            console.log(`  Crowd pct    Player:${cr.playerPct != null ? `${cr.playerPct.toFixed(1)}%` : '—'}  Banker:${cr.bankerPct != null ? `${cr.bankerPct.toFixed(1)}%` : '—'}  (reject ≥${Config.MAX_CROWD_PCT}% on loaded side)`);
            console.log(`  Alt last-12: ${countAlternations(getSequence(t).slice(-12))} (fallback when depths missing)`);

            if (r.firewall?.length) {
                console.log('  REASONS:', r.firewall.join(' · '));
            }
            return r;
        },

        summary: () => {
            const rows = topN(5);
            console.log('\n═══ TOP 5 (eligible) ═══\n');
            rows.forEach((t, i) => {
                const chop = `${t.pingPong.effective}`.padStart(2);
                const gap = `${(Math.abs((t.P || 0) - (t.B || 0)) / (t.total || 1) * 100).toFixed(0)}%`;
                console.log(
                    `${i + 1}. ${scoreIcon(t.score, true)} ${displayTableName(t.name || '').slice(0, 26).padEnd(26)} chop:${chop} gap:${gap} ` +
                        `tie:${parseFloat(String(t.tieRatioStr).replace('%', '')).toFixed(0)}% uid:${t.uid}`
                );
            });
            console.log('');
        },

        live: (uidOrId) => window.pp?.live(uidOrId) || null,

        help: () => {
            console.log(`
╔════════════════════════════════════════════════════════════════════╗
║  pick v4 — firewall + PingPong depth (goodroadLive / lobby map)          ║
╠════════════════════════════════════════════════════════════════════╣
║  HARD REJECT                                                          ║
║  • total < ${Config.MIN_TOTAL}                                                         ║
║  • T/total > ${Config.MAX_TIE_RATIO * 100}% (tie storm)                                  ║
║  • |P−B|/total > ${Config.MAX_PB_GAP_RATIO * 100}% (gravity)                              ║
║  • betstats: playerPct or bankerPct ≥ ${Config.MAX_CROWD_PCT}% (crowd herd)                       ║
║                                                                       ║
║  SORT (eligible rows)                                                  ║
║  • max(playerPingPongDepth, bankerPingPongDepth) ↑ first              ║
║  • then |P−B|/total lower better                                      ║
║  • fallback chop signal: alternations in last 12                      ║
║                                                                       ║
║  COMMANDS pick.status · pick.summary · pick.check(uid) · pick.best() ║
╚════════════════════════════════════════════════════════════════════╝
`);
        },
    };

    const waitForPP = () => new Promise(resolve => {
        const check = () => window.pp ? resolve() : setTimeout(check, 100);
        check();
    });

    waitForPP().then(() => {
        console.log('[Pick] v4.0 | Firewall + PP ping-pong depth + crowd (betstats)');
        console.log('[Pick] pick.help() · pick.status()');
    });

})();
