// ==UserScript==
// @name         PP WebSocket Interceptor
// @namespace    http://tampermonkey.net/
// @version      3.1
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
    let msgCount = 0;
    let lastSeq = 0;

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

    function hookWS(ws, url) {
        ws.addEventListener('message', (e) => {
            try {
                const msg = JSON.parse(e.data);
                msgCount++;
                handleMessage(msg);
            } catch(err) {}
        });
    }

    function handleMessage(msg) {
        // Track sequence number if present
        if (msg.seq) lastSeq = msg.seq;

        // === LOBBY WEBSOCKET FORMAT (dga.pragmaticplaylive.net) ===
        // globalStats
        if (msg.globalStats) {
            globalStats = msg.globalStats;
        }

        // tableKey list (lobby uses numeric IDs like "422")
        if (msg.tableKey) {
            tablesOrder = msg.tableKey;
        }

        // Table data from lobby format
        // Full update: has baccaratShoeSummary with win counters
        // Basic update: just tableId with basic info (like multiplay lobby)
        if (msg.tableId) {
            if (msg.baccaratShoeSummary || msg.tableName) {
                updateFromLobby(msg);
            } else if (msg.totalSeatedPlayers !== undefined) {
                // Delta update - just player count, update if table exists
                updateLobbyDelta(msg);
            }
        }

        // === GAME WEBSOCKET FORMAT (gs17.pragmaticplaylive.net/game) ===
        // tablesorder (game uses long IDs like "cbcf6qas8fscb222")
        if (msg.tablesorder) {
            tablesOrder = msg.tablesorder;
            if (msg.seq) lastSeq = msg.seq;
        }

        // tableconfig (maps gameId to lobbyId via operator_game_id)
        if (msg.tableconfig) {
            updateFromConfig(msg.tableconfig);
            if (msg.tableconfig.seq) lastSeq = msg.tableconfig.seq;
        }

        // statistic (full road data + win counters)
        if (msg.statistic) {
            updateFromStatistic(msg.statistic);
            if (msg.statistic.seq) lastSeq = msg.statistic.seq;
        }

        // statisticLA (incremental update)
        if (msg.statisticLA) {
            updateFromStatisticLA(msg.statisticLA);
            if (msg.statisticLA.seq) lastSeq = msg.statisticLA.seq;
        }

        // betsopen - betting window opened
        if (msg.betsopen) {
            updateBetStatus(msg.betsopen.table, true, msg.betsopen.game, msg.betsopen.seq);
        }

        // betsclosed - betting window closed
        if (msg.betsclosed) {
            updateBetStatus(msg.betsclosed.table, false, msg.betsclosed.game, msg.betsclosed.seq);
        }
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
            P: +msg.baccaratShoeSummary?.playerWinCounter || prev.P || 0,
            B: +msg.baccaratShoeSummary?.bankerWinCounter || prev.B || 0,
            T: +msg.baccaratShoeSummary?.tieCounter || prev.T || 0,
            PP: +msg.baccaratShoeSummary?.playerPairCounter || prev.PP || 0,
            BP: +msg.baccaratShoeSummary?.bankerPairCounter || prev.BP || 0,
            total: +msg.baccaratShoeSummary?.totalGames || prev.total || 0,
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
            total: (data.pwc || prev.P || 0) + (data.bwc || prev.B || 0) + (data.tc || prev.T || 0),
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
        count: () => tables.size,
        msgs: () => msgCount,
        order: () => tablesOrder,
        stats: () => globalStats,
        seq: () => lastSeq,

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
        }
    };

    console.log('[PP] v3.1 | Fixed UID mapping + PBT sequence');
    console.log('[PP] API: pp.status() pp.list() pp.pbt(1) pp.pbtStr(1)');
})();

/*
╔══════════════════════════════════════════════════════════════════════════════╗
║                     PP WEBSOCKET INTERCEPTOR API v3.1                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Intercepts Pragmatic Play WebSocket data from lobby + multiplay game.       ║
║  Data is available via window.pp API.                                        ║
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
║  pp.get(1)                Get table by UID (number)                          ║
║  pp.get("cbcf...")        Get table by gameId (string)                       ║
║  pp.get("422")            Get table by lobbyId (string)                      ║
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
