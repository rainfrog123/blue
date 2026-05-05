// ==UserScript==
// @name         PP WebSocket Interceptor
// @namespace    http://tampermonkey.net/
// @version      3.2
// @description  Intercept Pragmatic Play baccarat WebSocket (lobby + game)
// @author       You
// @match        *://client.pragmaticplaylive.net/*
// @match        *://*.stake.com/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    const tables = new Map();           // gameId -> tableData
    const configs = new Map();          // gameId -> raw tableconfig
    const uidMap = new Map();           // uid -> gameId
    const idToUid = new Map();          // gameId -> uid
    const gameToLobby = new Map();      // gameId -> lobbyId (operator_game_id)
    const lobbyToGame = new Map();      // lobbyId -> gameId
    let nextUid = 1;
    let tablesOrder = [];
    let globalStats = null;
    let lastPlayersCount = null;
    let msgCount = 0;
    let lastSeq = 0;
    let suppressGoodRoadWarnings = true;

    const _consoleWarn = console.warn.__ppOriginalWarn || console.warn.bind(console);
    const isGoodRoadTablesOrderWarning = (args) => {
        const line = args.map((x) => {
            if (typeof x === 'string') return x;
            if (x && typeof x.message === 'string') return x.message;
            return '';
        }).join(' ');
        return line.includes('is not in tablesOrder') &&
               line.includes('GoodRoadGameCommunicationProcessor');
    };

    const ppWarnProxy = (...args) => {
        if (suppressGoodRoadWarnings && isGoodRoadTablesOrderWarning(args)) return;
        _consoleWarn(...args);
    };
    ppWarnProxy.__ppOriginalWarn = _consoleWarn;
    console.warn = ppWarnProxy;

    const bumpSeq = (seq) => {
        if (seq == null || seq === '') return;
        const n = typeof seq === 'string' ? parseInt(seq, 10) : seq;
        if (!Number.isFinite(n)) return;
        if (n > lastSeq) lastSeq = n;
    };

    const resolveGameId = (tableOrLobbyId) => {
        if (tableOrLobbyId == null) return null;
        const s = String(tableOrLobbyId);
        return lobbyToGame.get(s) || s;
    };

    function patchTable(gameId, partial, bumpUpdates = true) {
        const gid = resolveGameId(gameId);
        if (!gid) return;

        const uid = assignUid(gid);
        const prev = tables.get(gid) || {};
        tables.set(gid, {
            ...prev,
            id: gid,
            gameId: gid,
            uid: prev.uid || uid,
            ...partial,
            updated: Date.now(),
            updates: bumpUpdates ? (prev.updates || 0) + 1 : (prev.updates || 0)
        });
    }

    // Assign simple numeric UID to table
    const assignUid = (gameId, forceUid = null) => {
        if (forceUid !== null) {
            // Reassign existing UID to new gameId
            const oldGameId = uidMap.get(forceUid);
            if (oldGameId && oldGameId !== gameId) {
                idToUid.delete(oldGameId);
            }
            uidMap.set(forceUid, gameId);
            idToUid.set(gameId, forceUid);
            return forceUid;
        }
        if (!idToUid.has(gameId)) {
            const uid = nextUid++;
            uidMap.set(uid, gameId);
            idToUid.set(gameId, uid);
        }
        return idToUid.get(gameId);
    };

    // Resolve uid, gameId, or lobbyId to gameId
    const resolveId = (uidOrId) => {
        if (typeof uidOrId === 'number') {
            // Could be UID or numeric lobby ID
            if (uidMap.has(uidOrId)) return uidMap.get(uidOrId);
            // Try as lobbyId string
            const strId = String(uidOrId);
            if (lobbyToGame.has(strId)) return lobbyToGame.get(strId);
            return null;
        }
        // String ID - could be gameId or lobbyId
        if (typeof uidOrId === 'string') {
            if (tables.has(uidOrId)) return uidOrId;
            if (lobbyToGame.has(uidOrId)) return lobbyToGame.get(uidOrId);
        }
        return uidOrId;
    };

    // Hook WebSocket
    const _WS = window.WebSocket;
    window.WebSocket = function(url, proto) {
        const ws = proto ? new _WS(url, proto) : new _WS(url);
        console.log('[PP] WS:', url);
        hookWS(ws, url);
        return ws;
    };
    window.WebSocket.prototype = _WS.prototype;
    window.WebSocket.CONNECTING = 0;
    window.WebSocket.OPEN = 1;
    window.WebSocket.CLOSING = 2;
    window.WebSocket.CLOSED = 3;

    function gameIdFromWsUrl(url) {
        if (!url || typeof url !== 'string') return null;
        try {
            const u = new URL(url.replace(/^ws/i, 'http'));
            const t = u.searchParams.get('tableId');
            return t ? decodeURIComponent(t) : null;
        } catch (_) {
            const m = url.match(/[?&]tableId=([^&]+)/i);
            return m ? decodeURIComponent(m[1]) : null;
        }
    }

    function hookWS(ws, url) {
        const ctxGameId = gameIdFromWsUrl(url);
        ws.addEventListener('message', (e) => {
            try {
                const msg = JSON.parse(e.data);
                msgCount++;
                handleMessage(msg, ctxGameId);
            } catch(err) {}
        });
    }

    function handleMessage(msg, ctxGameId) {
        if (msg.seq) bumpSeq(msg.seq);

        // === LOBBY WEBSOCKET FORMAT (dga.pragmaticplaylive.net) ===
        if (msg.globalStats) {
            globalStats = msg.globalStats;
        }

        if (msg.playersCount) {
            const pc = msg.playersCount;
            lastPlayersCount = {
                total_seated_players: pc.total_seated_players,
                seq: pc.seq
            };
            bumpSeq(pc.seq);
        }

        if (msg.tableKey) {
            tablesOrder = msg.tableKey;
        }

        if (msg.tableId) {
            if (msg.baccaratShoeSummary || msg.tableName) {
                updateFromLobby(msg);
            } else if (msg.totalSeatedPlayers !== undefined) {
                updateLobbyDelta(msg);
            } else if (msg.statistics !== undefined || msg.gameResult !== undefined ||
                       msg.goodRoadsMap !== undefined || msg.goodRoadsDepthMap !== undefined) {
                updateFromLobbyPartial(msg);
            }
        }

        // === GAME WEBSOCKET FORMAT (gs*.pragmaticplaylive.net/game) ===
        if (msg.tablesorder) {
            tablesOrder = msg.tablesorder;
            bumpSeq(msg.seq);
        }

        if (msg.tableconfig) {
            updateFromConfig(msg.tableconfig);
            bumpSeq(msg.tableconfig.seq);
        }

        if (msg.statistic) {
            updateFromStatistic(msg.statistic);
            bumpSeq(msg.statistic.seq);
        }

        if (msg.statisticLA) {
            updateFromStatisticLA(msg.statisticLA);
            bumpSeq(msg.statisticLA.seq);
        }

        if (msg.betsopen) {
            bumpSeq(msg.betsopen.seq);
            updateBetStatus(msg.betsopen.table, true, msg.betsopen.game, msg.betsopen.seq);
        }

        if (msg.betsclosed) {
            bumpSeq(msg.betsclosed.seq);
            updateBetStatus(msg.betsclosed.table, false, msg.betsclosed.game, msg.betsclosed.seq);
        }

        if (msg.ShoeSummary) mergeShoeSummary(msg.ShoeSummary);
        if (msg.goodroad) mergeGoodroad(msg.goodroad);
        if (msg.game) mergeGameMeta(msg.game);
        if (msg.timer) mergeTimer(msg.timer);
        if (msg.dealer) mergeDealer(msg.dealer, ctxGameId);
        if (msg.table && typeof msg.table === 'object' && 'value' in msg.table) {
            mergeTableMeta(msg.table, ctxGameId);
        }
        if (msg.subscribe) mergeSubscribe(msg.subscribe);
        if (msg.betstats) mergeBetstats(msg.betstats);
        if (msg.disablesidebets) mergeDisableSidebets(msg.disablesidebets);
        if (msg.gameresult) mergeGameresultPayload(msg.gameresult);
        if (msg.winners) mergeWinnersPayload(msg.winners);
        if (msg.betsclosingsoon) mergeBetsClosingSoon(msg.betsclosingsoon);
        if (msg.startDealing) mergeStartDealing(msg.startDealing);
        if (msg.startshuffling) mergeShuffling(msg.startshuffling, 'start');
        if (msg.endshuffling) mergeShuffling(msg.endshuffling, 'end');
        if (msg.currentShoe) mergeCurrentShoe(msg.currentShoe, ctxGameId);
        if (msg.voip_cc) mergeVoip(msg.voip_cc, ctxGameId);
        if (msg.pong) {
            bumpSeq(msg.pong.seq);
            mergePong(msg.pong, ctxGameId);
        }
        if (msg.seat) mergeSeat(msg.seat);
        if (msg.card) mergeCard(msg.card);
        if (msg.cardinc) mergeCardInc(msg.cardinc);
    }

    function updateFromLobbyPartial(msg) {
        const lobbyId = msg.tableId;
        let gameId = lobbyToGame.get(lobbyId);
        if (!gameId) gameId = lobbyId;

        const uid = assignUid(gameId);
        const prev = tables.get(gameId) || {};
        const next = {
            ...prev,
            id: gameId,
            gameId,
            lobbyId,
            uid,
            updated: Date.now(),
            updates: (prev.updates || 0) + 1,
            source: 'lobby-partial'
        };

        if (msg.statistics !== undefined) next.bigRoad = msg.statistics;
        if (msg.gameResult !== undefined) next.games = msg.gameResult;
        if (msg.goodRoadsMap !== undefined) next.roads = msg.goodRoadsMap;
        if (msg.goodRoadsDepthMap !== undefined) next.goodRoadsDepthMap = msg.goodRoadsDepthMap;
        if (msg.grTableCount !== undefined) next.grTableCount = msg.grTableCount;
        if (msg.shuffle !== undefined) next.shuffle = msg.shuffle;

        tables.set(gameId, next);
        bumpSeq(msg.seq);
    }

    function mergeShoeSummary(s) {
        if (!s?.table) return;
        bumpSeq(s.seq);
        const gid = resolveGameId(s.table);
        const prev = tables.get(gid) || {};
        patchTable(s.table, {
            P: s.playerWinCounter != null ? +s.playerWinCounter : (prev.P ?? 0),
            B: s.bankerWinCounter != null ? +s.bankerWinCounter : (prev.B ?? 0),
            T: s.tieCounter != null ? +s.tieCounter : (prev.T ?? 0),
            PP: s.playerPairCounter != null ? +s.playerPairCounter : (prev.PP ?? 0),
            BP: s.bankerPairCounter != null ? +s.bankerPairCounter : (prev.BP ?? 0),
            total: s.totalGames != null ? +s.totalGames : (prev.total ?? 0),
            seq: s.seq,
            source: 'game-shoe'
        });
    }

    function mergeGoodroad(g) {
        const tid = g.sourcetableId || g.table;
        if (!tid) return;
        bumpSeq(g.seq);
        patchTable(tid, { goodroadLive: g }, false);
    }

    function mergeGameMeta(g) {
        if (!g?.table) return;
        bumpSeq(g.seq);
        patchTable(g.table, {
            currentGame: g.id,
            gameClock: g.value,
            gameStartTime: g.starttime,
            seq: g.seq
        }, false);
    }

    function mergeTimer(t) {
        if (!t?.table) return;
        bumpSeq(t.seq);
        patchTable(t.table, { bettingTimer: t.value, timerGameId: t.id, seq: t.seq }, false);
    }

    function mergeDealer(d, ctxGameId) {
        if (!d) return;
        const gameId = ctxGameId || [...tables.entries()].find(([, row]) => row.dealerId === d.id)?.[0];
        if (!gameId) return;
        bumpSeq(d.seq);
        patchTable(gameId, { dealer: d.value, dealerId: d.id, seq: d.seq }, false);
    }

    function mergeTableMeta(t, ctxGameId) {
        bumpSeq(t.seq);
        const gameId = ctxGameId;
        if (!gameId) return;
        patchTable(gameId, {
            tableLabel: t.value,
            tableOpenTime: t.openTime,
            tableNewTable: t.newTable,
            tableMetaSeq: t.seq
        }, false);
    }

    function mergeSubscribe(s) {
        if (!s?.table) return;
        bumpSeq(s.seq);
        patchTable(s.table, { subscribeChannel: s.channel, subscribeStatus: s.status }, false);
    }

    function mergeBetstats(b) {
        if (!b?.table) return;
        bumpSeq(b.seq);
        patchTable(b.table, { betstats: b }, false);
    }

    function mergeDisableSidebets(d) {
        const gid = d.tableId;
        if (!gid) return;
        bumpSeq(d.seq);
        patchTable(gid, { disabledSidebets: d.value, seq: d.seq }, false);
    }

    function mergeGameresultPayload(g) {
        if (!g?.table) return;
        bumpSeq(g.seq);
        patchTable(g.table, { lastGameresult: g }, true);
    }

    function mergeWinnersPayload(w) {
        if (!w?.table) return;
        bumpSeq(w.seq);
        patchTable(w.table, { lastWinners: w }, true);
    }

    function mergeBetsClosingSoon(b) {
        if (!b?.table) return;
        bumpSeq(b.seq);
        patchTable(b.table, {
            betsClosingSoon: true,
            betsClosingSoonGame: b.game,
            seq: b.seq
        }, false);
    }

    function mergeStartDealing(s) {
        if (!s?.table) return;
        bumpSeq(s.seq);
        patchTable(s.table, { dealing: true, dealingGame: s.game, seq: s.seq }, false);
    }

    function mergeShuffling(s, phase) {
        if (!s?.table) return;
        bumpSeq(s.seq);
        patchTable(s.table, { shuffling: phase === 'start', shuffleGame: s.game || '', seq: s.seq }, false);
    }

    function mergeCurrentShoe(c, ctxGameId) {
        bumpSeq(c.seq);
        const gameId = ctxGameId;
        if (!gameId) return;
        patchTable(gameId, { currentShoe: c }, false);
    }

    function mergeVoip(v, ctxGameId) {
        bumpSeq(v.seq);
        const gameId = v.table || ctxGameId;
        if (!gameId) return;
        patchTable(gameId, { voip: true, seq: v.seq }, false);
    }

    function mergePong(p, ctxGameId) {
        const gameId = ctxGameId;
        if (!gameId) return;
        patchTable(gameId, { lastPong: p }, false);
    }

    function mergeSeat(s) {
        const tid = s.table_id || s.tableId;
        if (!tid) return;
        bumpSeq(s.seq);
        patchTable(tid, { lastSeatEvent: s }, false);
    }

    function mergeCard(c) {
        if (!c?.table) return;
        bumpSeq(c.seq);
        patchTable(c.table, { lastCard: c, seq: c.seq }, false);
    }

    function mergeCardInc(c) {
        if (!c?.table) return;
        bumpSeq(c.seq);
        patchTable(c.table, { lastCardInc: c, seq: c.seq }, false);
    }

    // Lobby delta: just tableId + player count update
    function updateLobbyDelta(msg) {
        const lobbyId = msg.tableId;
        let gameId = lobbyToGame.get(lobbyId) || lobbyId;

        // Only update if table already exists
        const prev = tables.get(gameId);
        if (!prev) return;

        tables.set(gameId, {
            ...prev,
            players: msg.totalSeatedPlayers ?? prev.players ?? 0,
            updated: Date.now()
        });
    }

    // Lobby format: {tableId, baccaratShoeSummary, gameResult, statistics...}
    // tableId here is the LOBBY ID (like "422")
    function updateFromLobby(msg) {
        const lobbyId = msg.tableId;
        // Check if we have a mapping to gameId
        let gameId = lobbyToGame.get(lobbyId);

        // If no mapping yet, use lobbyId as the key (will be merged later)
        if (!gameId) {
            gameId = lobbyId;
        }

        const uid = assignUid(gameId);
        const prev = tables.get(gameId) || {};

        tables.set(gameId, {
            ...prev,
            id: gameId,
            gameId: gameId,
            lobbyId: lobbyId,
            uid,
            name: msg.tableName || prev.name || '',
            type: msg.tableType || prev.type || '',
            subtype: msg.tableSubtype || prev.subtype || '',
            dealer: msg.dealer?.name || prev.dealer || '',
            minBet: msg.tableLimits?.minBet ?? prev.minBet ?? 0,
            maxBet: msg.tableLimits?.maxBet ?? prev.maxBet ?? 0,
            players: msg.totalSeatedPlayers ?? prev.players ?? 0,
            P: msg.baccaratShoeSummary?.playerWinCounter != null ? +msg.baccaratShoeSummary.playerWinCounter : (prev.P ?? 0),
            B: msg.baccaratShoeSummary?.bankerWinCounter != null ? +msg.baccaratShoeSummary.bankerWinCounter : (prev.B ?? 0),
            T: msg.baccaratShoeSummary?.tieCounter != null ? +msg.baccaratShoeSummary.tieCounter : (prev.T ?? 0),
            PP: msg.baccaratShoeSummary?.playerPairCounter != null ? +msg.baccaratShoeSummary.playerPairCounter : (prev.PP ?? 0),
            BP: msg.baccaratShoeSummary?.bankerPairCounter != null ? +msg.baccaratShoeSummary.bankerPairCounter : (prev.BP ?? 0),
            total: msg.baccaratShoeSummary?.totalGames != null ? +msg.baccaratShoeSummary.totalGames : (prev.total ?? 0),
            roads: msg.goodRoadsMap || prev.roads || {},
            bigRoad: msg.statistics || prev.bigRoad || '',
            games: msg.gameResult || prev.games || [],
            open: msg.tableOpen ?? prev.open ?? true,
            updated: Date.now(),
            updates: (prev.updates || 0) + 1,
            source: 'lobby'
        });
    }

    // Game format: tableconfig
    // Contains both tableId (gameId) and operator_game_id (lobbyId)
    function updateFromConfig(cfg) {
        const gameId = cfg.tableId;
        const lobbyId = cfg.operator_game_id;
        if (!gameId) return;

        let existingUid = null;

        // Create gameId <-> lobbyId mapping
        if (lobbyId) {
            gameToLobby.set(gameId, lobbyId);
            lobbyToGame.set(lobbyId, gameId);

            // Migrate any existing data from lobbyId key to gameId key
            if (tables.has(lobbyId) && lobbyId !== gameId) {
                const lobbyData = tables.get(lobbyId);
                existingUid = lobbyData.uid; // Preserve the original UID
                const gameData = tables.get(gameId) || {};
                tables.set(gameId, { ...lobbyData, ...gameData, id: gameId, gameId, lobbyId });
                tables.delete(lobbyId);
            }
        }

        // Use existing UID from migrated data, or assign new one
        const uid = existingUid ? assignUid(gameId, existingUid) : assignUid(gameId);
        configs.set(gameId, cfg);
        const prev = tables.get(gameId) || {};

        tables.set(gameId, {
            ...prev,
            id: gameId,
            gameId,
            lobbyId: lobbyId || prev.lobbyId || '',
            uid,
            name: cfg.table_name || prev.name || '',
            type: cfg.table_type || prev.type || '',
            category: cfg.table_category || prev.category || '',
            minBet: parseFloat(cfg.table_bet_min_limit) || prev.minBet || 0,
            maxBet: parseFloat(cfg.table_bet_max_limit) || prev.maxBet || 0,
            bettingTime: parseInt(cfg.betting_time) || prev.bettingTime || 15,
            open: cfg.table_closed !== 'true',
            mtbGroupId: cfg.mtb_groupId || prev.mtbGroupId || '',
            updated: Date.now(),
            source: 'game'
        });
    }

    // Game format: statistic (full road data)
    function updateFromStatistic(stat) {
        const gameId = stat.table;
        if (!gameId) return;

        const uid = assignUid(gameId);
        let data = {};
        try {
            data = JSON.parse(stat.value);
        } catch(e) { return; }

        const prev = tables.get(gameId) || {};

        tables.set(gameId, {
            ...prev,
            id: gameId,
            gameId,
            uid,
            P: data.playerWinCounter ?? prev.P ?? 0,
            B: data.bankerWinCounter ?? prev.B ?? 0,
            T: data.tieCounter ?? prev.T ?? 0,
            PP: data.playerPairCounter ?? prev.PP ?? 0,
            BP: data.bankerPairCounter ?? prev.BP ?? 0,
            total: (data.playerWinCounter || 0) + (data.bankerWinCounter || 0) + (data.tieCounter || 0),
            bigRoad: data.bigRoad || prev.bigRoad || [],
            beadPlate: data.beadPlate || prev.beadPlate || [],
            bigEyeBoy: data.bigEyeBoy || prev.bigEyeBoy || [],
            smallRoad: data.smallRoad || prev.smallRoad || [],
            cockroachPig: data.cockroachPig || prev.cockroachPig || [],
            playerEnhance: data.playerEnhancement || prev.playerEnhance || null,
            bankerEnhance: data.bankerEnhancement || prev.bankerEnhance || null,
            seq: stat.seq || prev.seq || 0,
            updated: Date.now(),
            updates: (prev.updates || 0) + 1,
            source: 'game'
        });
    }

    // Bet status: betsopen / betsclosed
    function updateBetStatus(tableId, canBet, gameRoundId, seq) {
        const gameId = tableId;
        if (!gameId) return;

        const apply = (flag) => {
            const prev = tables.get(gameId) || {};
            tables.set(gameId, {
                ...prev,
                id: gameId,
                gameId,
                uid: prev.uid || assignUid(gameId),
                canBet: flag,
                currentGame: gameRoundId,
                betStatusTime: Date.now(),
                seq: seq || prev.seq || 0
            });
        };

        if (canBet) {
            // Delay to account for UI rendering
            setTimeout(() => apply(true), 2000);
        } else {
            apply(false);
        }
    }

    // Game format: statisticLA (last action - incremental)
    function updateFromStatisticLA(stat) {
        const gameId = stat.table;
        if (!gameId) return;

        const uid = assignUid(gameId);
        let data = {};
        try {
            data = JSON.parse(stat.value);
        } catch(e) { return; }

        const prev = tables.get(gameId) || {};

        // LA format uses short keys: bwc, pwc, tc, bpc, ppc
        tables.set(gameId, {
            ...prev,
            id: gameId,
            gameId,
            uid,
            P: data.pwc ?? prev.P ?? 0,
            B: data.bwc ?? prev.B ?? 0,
            T: data.tc ?? prev.T ?? 0,
            PP: data.ppc ?? prev.PP ?? 0,
            BP: data.bpc ?? prev.BP ?? 0,
            total: (data.pwc ?? prev.P ?? 0) + (data.bwc ?? prev.B ?? 0) + (data.tc ?? prev.T ?? 0),
            lastBR: data.br || prev.lastBR,      // last big road position
            lastBP: data.bp || prev.lastBP,      // last bead plate position
            lastBEB: data.beb || prev.lastBEB,   // last big eye boy
            lastSR: data.sr || prev.lastSR,      // last small road
            lastCP: data.cp || prev.lastCP,      // last cockroach pig
            playerEnhance: data.pE || prev.playerEnhance || null,
            bankerEnhance: data.bE || prev.bankerEnhance || null,
            seq: stat.seq || prev.seq || 0,
            updated: Date.now(),
            updates: (prev.updates || 0) + 1,
            source: 'game-la'
        });
    }

    // Calculate P/B ratio for filtering
    const calcRatio = (t) => {
        if (!t || !t.total || t.total === 0) return 999;
        const diff = Math.abs((t.P || 0) - (t.B || 0));
        return diff / t.total;
    };

    // Extract P/B/T sequence from table data
    // Returns array like ['P','B','B','T','P',...] in chronological order (oldest first)
    const getPBTSequence = (t) => {
        if (!t) return [];

        // Method 1: From beadPlate (game WebSocket) - most reliable
        // beadPlate is 2D: [[col0row0, col0row1,...], [col1row0,...], ...]
        // Fills column by column (top to bottom in each column, then next column)
        // First char: R=Banker (red), B=Player (blue), G=Tie (green)
        if (t.beadPlate && Array.isArray(t.beadPlate)) {
            const seq = [];
            const numRows = t.beadPlate[0]?.length || 6;
            // Read column by column, top to bottom in each column
            for (let col = 0; col < t.beadPlate.length; col++) {
                for (let row = 0; row < numRows; row++) {
                    const cell = t.beadPlate[col]?.[row];
                    if (cell && cell !== '---') {
                        const c = cell.charAt(0);
                        if (c === 'R') seq.push('B');      // Red = Banker
                        else if (c === 'B') seq.push('P'); // Blue = Player
                        else if (c === 'G') seq.push('T'); // Green = Tie
                    }
                }
            }
            return seq;
        }

        // Method 2: From gameResult (lobby WebSocket)
        // gameResult is array of {winner: "BANKER_WIN" | "PLAYER_WIN" | "TIE", ...}
        if (t.games && Array.isArray(t.games)) {
            return t.games.map(g => {
                if (g.winner === 'PLAYER_WIN') return 'P';
                if (g.winner === 'BANKER_WIN') return 'B';
                if (g.winner === 'TIE') return 'T';
                return '?';
            }).filter(x => x !== '?');
        }

        // Method 3: From bigRoad string (lobby format) - parse the string
        if (t.bigRoad && typeof t.bigRoad === 'string') {
            try {
                const road = JSON.parse(t.bigRoad);
                if (Array.isArray(road)) {
                    const seq = [];
                    for (let col = 0; col < road.length; col++) {
                        for (let row = 0; row < road[col].length; row++) {
                            const cell = road[col][row];
                            if (cell && cell !== '---') {
                                const c = cell.charAt(0);
                                if (c === 'P') seq.push('P');
                                else if (c === 'B') seq.push('B');
                                // Ties are embedded in P/B cells with numbers
                            }
                        }
                    }
                    return seq;
                }
            } catch (e) {}
        }

        return [];
    };

    /** Latest live-stream payloads merged onto a table row (card, timer, goodroad, …). */
    const buildLiveSnapshot = (t) => {
        const out = {};
        if (t.lastCard) out.card = t.lastCard;
        if (t.lastCardInc) out.cardInc = t.lastCardInc;
        if (t.bettingTimer != null && t.bettingTimer !== '' || t.timerGameId) {
            out.timer = { value: t.bettingTimer, gameId: t.timerGameId };
        }
        if (t.goodroadLive) out.goodroad = t.goodroadLive;
        if (t.currentGame != null && t.currentGame !== '' || t.gameClock != null && t.gameClock !== '' || t.gameStartTime) {
            out.game = { id: t.currentGame, clock: t.gameClock, startTime: t.gameStartTime };
        }
        if (t.lastGameresult) out.gameresult = t.lastGameresult;
        if (t.lastWinners) out.winners = t.lastWinners;
        if (t.betstats) out.betstats = t.betstats;
        if (t.disabledSidebets != null && t.disabledSidebets !== '') {
            out.disabledSidebets = t.disabledSidebets;
        }
        if (t.betsClosingSoon) {
            out.betsClosingSoon = { game: t.betsClosingSoonGame };
        }
        if (t.dealing) {
            out.dealing = { game: t.dealingGame };
        }
        if (t.shuffling || (t.shuffleGame !== undefined && t.shuffleGame !== '')) {
            out.shuffling = { active: !!t.shuffling, game: t.shuffleGame };
        }
        if (t.subscribeChannel || t.subscribeStatus) {
            out.subscribe = { channel: t.subscribeChannel, status: t.subscribeStatus };
        }
        if (t.lastSeatEvent) out.seat = t.lastSeatEvent;
        if (t.lastPong) out.pong = t.lastPong;
        if (t.voip) out.voip = true;
        if (t.currentShoe) out.shoe = t.currentShoe;
        if (t.tableLabel != null && t.tableLabel !== '' || t.tableOpenTime || t.tableNewTable != null) {
            out.tableMeta = {
                label: t.tableLabel,
                openTime: t.tableOpenTime,
                newTable: t.tableNewTable
            };
        }
        if (t.dealer || t.dealerId) {
            out.dealer = { name: t.dealer, id: t.dealerId };
        }
        return out;
    };

    const liveForId = (uidOrId) => {
        const id = resolveId(uidOrId);
        const t = id ? tables.get(id) : null;
        if (!t) return null;
        return buildLiveSnapshot(t);
    };

    // API
    window.pp = {
        tables: () => {
            const obj = {};
            for (const [id, t] of tables) {
                obj[id] = { ...t, ratio: calcRatio(t) };
            }
            return obj;
        },
        configs: () => Object.fromEntries(configs),
        get: (uidOrId) => {
            const id = resolveId(uidOrId);
            const t = id ? tables.get(id) : null;
            return t ? { ...t, ratio: calcRatio(t) } : null;
        },
        /** Grouped live-stream fields for one table (same ids as pp.get). Alias: lastEvents. */
        live: liveForId,
        lastEvents: liveForId,
        count: () => tables.size,
        msgs: () => msgCount,
        order: () => tablesOrder,
        stats: () => {
            const out = {};
            if (globalStats && typeof globalStats === 'object') Object.assign(out, globalStats);
            if (lastPlayersCount) out.lobbyPlayersCount = lastPlayersCount;
            return Object.keys(out).length ? out : null;
        },
        seq: () => lastSeq,
        setWarnFilter: (enabled = true) => {
            suppressGoodRoadWarnings = !!enabled;
            return suppressGoodRoadWarnings;
        },
        warnFilter: () => suppressGoodRoadWarnings,

        help: () => {
            const t = [
                '',
                '--- pp (Pragmatic Play WS) ---',
                '  pp.help()             print this cheat sheet',
                '  pp.status()           print tables summary',
                '  pp.tables()           { gameId -> row }',
                '  pp.get(id)            full row; id = uid | gameId | lobbyId',
                '  pp.live(id)           grouped live stream (same as lastEvents)',
                '  pp.lastEvents(id)     alias of pp.live',
                '  pp.list()             compact list (tables with total > 0)',
                '  pp.betting()          tables currently open for betting',
                '  pp.setWarnFilter(v)   toggle GoodRoad/tablesOrder warn suppression',
                '  pp.warnFilter()       current warn filter state (true/false)',
                '',
                '  pp.count()   pp.msgs()   pp.order()   pp.stats()   pp.seq()',
                '',
                '  pp.gameToLobby(g)     pp.lobbyToGame(l)',
                '  pp.road(id)   pp.pbt(id)   pp.pbtStr(id)   pp.lastN(id, n)',
                '  pp.sequences()        pp.seqAll()',
                '  pp.configs()          raw tableconfig map',
                '  pp.export()           pp.clear()',
                ''
            ].join('\n');
            console.log(t);
        },

        // ID mapping functions
        gameToLobby: (gameId) => gameToLobby.get(gameId) || null,
        lobbyToGame: (lobbyId) => lobbyToGame.get(String(lobbyId)) || null,

        list: () => [...tables.values()]
            .filter(t => t.total > 0)
            .sort((a, b) => a.uid - b.uid)
            .map(t => {
                const seq = getPBTSequence(t);
                return {
                    uid: t.uid,
                    id: t.id,
                    gameId: t.gameId,
                    lobbyId: t.lobbyId,
                    name: t.name,
                    P: t.P,
                    B: t.B,
                    T: t.T,
                    total: t.total,
                    canBet: t.canBet,
                    ratio: calcRatio(t),
                    upd: t.updates,
                    last10: seq.slice(-10).join('')
                };
            }),

        // Get tables that can currently bet
        betting: () => [...tables.values()]
            .filter(t => t.canBet === true && t.total >= 20)
            .sort((a, b) => calcRatio(a) - calcRatio(b))
            .map(t => ({
                uid: t.uid,
                gameId: t.gameId,
                name: t.name,
                P: t.P,
                B: t.B,
                T: t.T,
                ratio: calcRatio(t)
            })),

        status: () => {
            const active = [...tables.values()].filter(t => t.total > 0);
            console.log(`\n═══ PP TABLES (${active.length}) | msgs:${msgCount} | seq:${lastSeq} ═══\n`);
            active
                .sort((a, b) => a.uid - b.uid)
                .forEach(t => {
                    const bet = t.canBet ? '✓' : ' ';
                    const seq = getPBTSequence(t).slice(-8).join('');
                    console.log(
                        `#${String(t.uid).padStart(2)}${bet} ${(t.name || t.gameId || '?').slice(0,18).padEnd(18)} ` +
                        `P:${String(t.P||0).padStart(2)} B:${String(t.B||0).padStart(2)} T:${t.T||0} ` +
                        `(${String(t.total||0).padStart(2)}) ${seq.padEnd(8)}`
                    );
                });
        },

        road: (uidOrId) => {
            const id = resolveId(uidOrId);
            const t = id ? tables.get(id) : null;
            return t?.bigRoad || null;
        },

        // Get P/B/T sequence for a table
        // Returns array like ['P','B','B','T','P',...] in chronological order
        pbt: (uidOrId) => {
            const id = resolveId(uidOrId);
            const t = id ? tables.get(id) : null;
            return getPBTSequence(t);
        },

        // Get P/B/T sequence as string (e.g., "PBBPTBPBBB")
        pbtStr: (uidOrId) => {
            const id = resolveId(uidOrId);
            const t = id ? tables.get(id) : null;
            return getPBTSequence(t).join('');
        },

        // Get last N results for a table
        lastN: (uidOrId, n = 10) => {
            const id = resolveId(uidOrId);
            const t = id ? tables.get(id) : null;
            const seq = getPBTSequence(t);
            return seq.slice(-n);
        },

        // List all tables with full sequences
        sequences: () => [...tables.values()]
            .filter(t => t.total > 0)
            .sort((a, b) => a.uid - b.uid)
            .map(t => {
                const seq = getPBTSequence(t);
                return {
                    uid: t.uid,
                    name: t.name || t.gameId,
                    total: t.total,
                    P: t.P,
                    B: t.B,
                    T: t.T,
                    sequence: seq,
                    sequenceStr: seq.join('')
                };
            }),

        // Print all tables with full sequences
        seqAll: () => {
            console.log(`\n═══ ALL TABLE SEQUENCES (${tables.size} tables) ═══\n`);
            [...tables.values()]
                .filter(t => t.total > 0)
                .sort((a, b) => a.uid - b.uid)
                .forEach(t => {
                    const seq = getPBTSequence(t);
                    const name = (t.name || t.gameId || '?').slice(0, 20).padEnd(20);
                    console.log(`#${String(t.uid).padStart(2)} ${name} (${t.total})`);
                    console.log(`    ${seq.join('')}`);
                    console.log('');
                });
        },

        export: () => JSON.stringify(Object.fromEntries(tables), null, 2),
        clear: () => {
            tables.clear();
            configs.clear();
            uidMap.clear();
            idToUid.clear();
            gameToLobby.clear();
            lobbyToGame.clear();
            nextUid = 1;
            msgCount = 0;
            lastSeq = 0;
            tablesOrder = [];
            globalStats = null;
            lastPlayersCount = null;
        }
    };

    console.log('[PP] v3.2 | Full PP message types + lobby partial + WS URL context');
    console.log('[PP] API: pp.help() pp.status() pp.get(1) pp.live(1) …');
})();

/*
╔══════════════════════════════════════════════════════════════════════════════╗
║                     PP WEBSOCKET INTERCEPTOR API v3.2                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Intercepts Pragmatic Play WebSocket data from lobby + multiplay game.       ║
║  Data is available via window.pp API.                                        ║
║                                                                              ║
║  UPDATES IN v3.2:                                                            ║
║  - pp.help() lists all public methods in the console                          ║
║  - All PP game/lobby frame types from capture: ShoeSummary, goodroad, game,  ║
║    timer, dealer, table meta, subscribe, betstats, sidebets, gameresult,     ║
║    winners, dealing/shuffle/seat/pong/voip, card + cardinc, playersCount       ║
║  - Lobby tableId partial updates (statistics/gameResult/roads without name)   ║
║  - WS URL tableId context for dealer/table/shoe/pong when frame omits table  ║
║  - pp.stats() adds lobbyPlayersCount; clear() resets global lobby stats       ║
║  - pp.live(id) / pp.lastEvents(id) expose grouped live-stream snapshots      ║
║                                                                              ║
║  UPDATES IN v3.1:                                                            ║
║  ────────────────                                                            ║
║  - Fixed UID mapping during lobby→game table migration                       ║
║  - Added P/B/T sequence extraction: pp.pbt(), pp.pbtStr(), pp.lastN()        ║
║  - pp.status() and pp.list() now show last results                           ║
║  - Delta updates (player count only) now handled correctly                   ║
║                                                                              ║
║  QUICK START                                                                 ║
║  ───────────                                                                 ║
║  pp.help()                Print API cheat sheet in the console                 ║
║  pp.status()              Print all tables with stats and bet status         ║
║  pp.list()                Array with full table info                         ║
║  pp.betting()             Tables currently open for betting                  ║
║  pp.count()               Number of tables                                   ║
║  pp.msgs()                Total WebSocket messages received                  ║
║  pp.seq()                 Last sequence number                               ║
║                                                                              ║
║  TABLE DATA                                                                  ║
║  ──────────                                                                  ║
║  pp.tables()              All tables as object {gameId: tableData, ...}      ║
║  pp.get(1)                Get table by UID / gameId / lobbyId                 ║
║  pp.live(1)               Grouped live stream: card, timer, goodroad, …      ║
║  pp.lastEvents(1)         Same as pp.live                                    ║
║  pp.configs()             Raw tableconfig data from game WebSocket           ║
║  pp.order()               Table order array from WebSocket                   ║
║  pp.stats()               Global stats {playerCount: N}                      ║
║                                                                              ║
║  ID MAPPING                                                                  ║
║  ──────────                                                                  ║
║  pp.gameToLobby("cbcf..") Get lobbyId from gameId                           ║
║  pp.lobbyToGame("422")    Get gameId from lobbyId                           ║
║                                                                              ║
║  ROAD DATA                                                                   ║
║  ─────────                                                                   ║
║  pp.road(1)               Get bigRoad array by UID or ID                     ║
║  pp.pbt(1)                Get P/B/T sequence as array ['P','B','T',...]      ║
║  pp.pbtStr(1)             Get P/B/T sequence as string "PBTPBBPB..."         ║
║  pp.lastN(1, 10)          Get last N results for a table                     ║
║  pp.sequences()           All tables with full sequences as array            ║
║  pp.seqAll()              Print all tables with full sequences               ║
║                                                                              ║
║  EXPORT                                                                      ║
║  ──────                                                                      ║
║  pp.export()              JSON string of all table data                      ║
║  pp.clear()               Clear all stored data                              ║
║                                                                              ║
║  TABLE DATA STRUCTURE                                                        ║
║  ────────────────────                                                        ║
║  {                                                                           ║
║    uid: 1,                           // Simple numeric ID (1,2,3...)         ║
║    id: "cbcf6qas8fscb222",           // Same as gameId                       ║
║    gameId: "cbcf6qas8fscb222",       // Game table ID                        ║
║    lobbyId: "422",                   // Lobby/operator ID                    ║
║    name: "BACCARAT_3",               // Display name                         ║
║    type: "baccarat6",                // Table type                           ║
║    category: "Regular",              // Table category                       ║
║    minBet: 0.2, maxBet: 150000,      // Bet limits                          ║
║    bettingTime: 18,                  // Betting window in seconds            ║
║                                                                              ║
║    // Win counts                                                             ║
║    P: 17,                            // Player wins                          ║
║    B: 21,                            // Banker wins                          ║
║    T: 4,                             // Tie count                            ║
║    PP: 2,                            // Player pair count                    ║
║    BP: 4,                            // Banker pair count                    ║
║    total: 42,                        // Total rounds                         ║
║    ratio: 0.095,                     // |P-B|/total (lower = more balanced)  ║
║                                                                              ║
║    // Betting status                                                         ║
║    canBet: true,                     // Currently open for betting           ║
║    currentGame: "12057986217",       // Current game round ID                ║
║    betStatusTime: 1733500000000,     // Last bet status change               ║
║                                                                              ║
║    // Road data                                                              ║
║    bigRoad: [["PN0","---",...], ...],    // Big Road 2D array                ║
║    beadPlate: [...],                     // Bead Plate                       ║
║    bigEyeBoy: [...],                     // Big Eye Boy                      ║
║    smallRoad: [...],                     // Small Road                       ║
║    cockroachPig: [...],                  // Cockroach Pig                    ║
║    playerEnhance: {...},                 // Next Player prediction           ║
║    bankerEnhance: {...},                 // Next Banker prediction           ║
║                                                                              ║
║    // Meta                                                                   ║
║    open: true,                       // Table open                           ║
║    seq: 425,                         // Last message sequence                ║
║    updated: 1733500000000,           // Last update timestamp                ║
║    updates: 15,                      // Update count                         ║
║    source: "game"                    // Data source: lobby/game/game-la      ║
║  }                                                                           ║
║                                                                              ║
║  WEBSOCKET MESSAGE TYPES                                                     ║
║  ───────────────────────                                                     ║
║  LOBBY (dga.pragmaticplaylive.net/ws):                                       ║
║    {globalStats}           → pp.stats()                                      ║
║    {tableKey}              → pp.order()                                      ║
║    {tableId, baccaratShoeSummary, gameResult, ...}  → pp.get(id)             ║
║                                                                              ║
║  GAME (gs17.pragmaticplaylive.net/game):                                     ║
║    {tablesorder, seq}      → pp.order()                                      ║
║    {tableconfig}           → pp.configs(), maps gameId <-> lobbyId           ║
║    {statistic}             → pp.get(id) with full road data + counters       ║
║    {statisticLA}           → pp.get(id) incremental update                   ║
║    {betsopen}              → pp.get(id).canBet = true                        ║
║    {betsclosed}            → pp.get(id).canBet = false                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
*/
