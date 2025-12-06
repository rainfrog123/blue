// ==UserScript==
// @name         PP WebSocket Interceptor
// @namespace    http://tampermonkey.net/
// @version      2.1
// @description  Intercept Pragmatic Play baccarat WebSocket (lobby + game)
// @author       You
// @match        *://client.pragmaticplaylive.net/*
// @match        *://*.stake.com/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    const tables = new Map();      // originalId -> tableData
    const configs = new Map();
    const uidMap = new Map();       // uid -> originalId
    const idToUid = new Map();      // originalId -> uid
    let nextUid = 1;
    let tablesOrder = [];
    let globalStats = null;
    let msgCount = 0;
    
    // Assign simple numeric UID to table
    const assignUid = (originalId) => {
        if (!idToUid.has(originalId)) {
            const uid = nextUid++;
            uidMap.set(uid, originalId);
            idToUid.set(originalId, uid);
        }
        return idToUid.get(originalId);
    };
    
    // Resolve uid or originalId to originalId
    const resolveId = (uidOrId) => {
        if (typeof uidOrId === 'number') return uidMap.get(uidOrId) || null;
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
            } catch(e) {}
        });
    }

    function handleMessage(msg) {
        // === LOBBY WEBSOCKET FORMAT ===
        // globalStats
        if (msg.globalStats) {
            globalStats = msg.globalStats;
        }
        
        // tableKey list
        if (msg.tableKey) {
            tablesOrder = msg.tableKey;
        }
        
        // Table data with tableId (lobby format)
        if (msg.tableId && msg.baccaratShoeSummary) {
            updateFromLobby(msg);
        }
        
        // === GAME WEBSOCKET FORMAT ===
        // tablesorder
        if (msg.tablesorder) {
            tablesOrder = msg.tablesorder;
        }
        
        // tableconfig
        if (msg.tableconfig) {
            updateFromConfig(msg.tableconfig);
        }
        
        // statistic (full road data)
        if (msg.statistic) {
            updateFromStatistic(msg.statistic);
        }
        
        // statisticLA (last action - incremental)
        if (msg.statisticLA) {
            updateFromStatisticLA(msg.statisticLA);
        }
        
        // betsopen - betting window opened
        if (msg.betsopen) {
            updateBetStatus(msg.betsopen.table, true, msg.betsopen.game);
        }
        
        // betsclosed - betting window closed
        if (msg.betsclosed) {
            updateBetStatus(msg.betsclosed.table, false, msg.betsclosed.game);
        }
    }

    // Lobby format: {tableId, baccaratShoeSummary, gameResult, statistics...}
    function updateFromLobby(msg) {
        const id = msg.tableId;
        const uid = assignUid(id);
        const prev = tables.get(id) || {};
        
        tables.set(id, {
            ...prev,
            id,
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
    function updateFromConfig(cfg) {
        const id = cfg.tableId;
        if (!id) return;
        
        const uid = assignUid(id);
        configs.set(id, cfg);
        const prev = tables.get(id) || {};
        
        tables.set(id, {
            ...prev,
            id,
            uid,
            name: cfg.table_name || prev.name || '',
            type: cfg.table_type || prev.type || '',
            category: cfg.table_category || prev.category || '',
            minBet: parseFloat(cfg.table_bet_min_limit) || prev.minBet || 0,
            maxBet: parseFloat(cfg.table_bet_max_limit) || prev.maxBet || 0,
            open: cfg.table_closed !== 'true',
            updated: Date.now(),
            source: 'game'
        });
    }

    // Game format: statistic (full road)
    function updateFromStatistic(stat) {
        const id = stat.table;
        if (!id) return;
        
        const uid = assignUid(id);
        let data = {};
        try {
            data = JSON.parse(stat.value);
        } catch(e) { return; }
        
        const prev = tables.get(id) || {};
        
        tables.set(id, {
            ...prev,
            id,
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
            updated: Date.now(),
            updates: (prev.updates || 0) + 1,
            source: 'game'
        });
    }

    // Bet status: betsopen / betsclosed
    function updateBetStatus(tableId, canBet, gameId) {
        const id = tableId;
        if (!id) return;
        
        const prev = tables.get(id) || {};
        tables.set(id, {
            ...prev,
            id,
            uid: prev.uid || assignUid(id),
            canBet,
            currentGame: gameId,
            betStatusTime: Date.now()
        });
    }

    // Game format: statisticLA (last action)
    function updateFromStatisticLA(stat) {
        const id = stat.table;
        if (!id) return;
        
        const uid = assignUid(id);
        let data = {};
        try {
            data = JSON.parse(stat.value);
        } catch(e) { return; }
        
        const prev = tables.get(id) || {};
        
        // LA format uses short keys: bwc, pwc, tc, bpc, ppc
        tables.set(id, {
            ...prev,
            id,
            uid,
            P: data.pwc ?? prev.P ?? 0,
            B: data.bwc ?? prev.B ?? 0,
            T: data.tc ?? prev.T ?? 0,
            PP: data.ppc ?? prev.PP ?? 0,
            BP: data.bpc ?? prev.BP ?? 0,
            total: (data.pwc || 0) + (data.bwc || 0) + (data.tc || 0),
            lastBR: data.br || prev.lastBR,  // last big road position
            lastBP: data.bp || prev.lastBP,  // last bead plate position
            updated: Date.now(),
            updates: (prev.updates || 0) + 1,
            source: 'game-la'
        });
    }

    // API
    window.pp = {
        tables: () => Object.fromEntries(tables),
        configs: () => Object.fromEntries(configs),
        get: (uidOrId) => {
            const id = resolveId(uidOrId);
            return id ? tables.get(id) : null;
        },
        count: () => tables.size,
        msgs: () => msgCount,
        order: () => tablesOrder,
        stats: () => globalStats,
        
        list: () => [...tables.values()]
            .filter(t => t.total > 0)
            .sort((a, b) => a.uid - b.uid)
            .map(t => ({
                uid: t.uid, id: t.id, name: t.name, P: t.P, B: t.B, T: t.T,
                total: t.total, upd: t.updates
            })),
        
        status: () => {
            console.log(`\n═══ PP TABLES (${tables.size}) | msgs:${msgCount} ═══\n`);
            [...tables.values()]
                .filter(t => t.total > 0)
                .sort((a, b) => a.uid - b.uid)
                .slice(0, 30)
                .forEach(t => {
                    console.log(
                        `#${String(t.uid).padStart(2)}: ${t.name?.slice(0,24)?.padEnd(24) || '?'.padEnd(24)} ` +
                        `P:${String(t.P||0).padStart(2)} B:${String(t.B||0).padStart(2)} T:${t.T||0} ` +
                        `(${t.total||0}) #${t.updates||0}`
                    );
                });
        },
        
        road: (uidOrId) => {
            const id = resolveId(uidOrId);
            const t = id ? tables.get(id) : null;
            return t?.bigRoad || null;
        },
        
        export: () => JSON.stringify(Object.fromEntries(tables), null, 2),
        clear: () => { tables.clear(); configs.clear(); uidMap.clear(); idToUid.clear(); nextUid = 1; msgCount = 0; }
    };

    console.log('[PP] v2.1 | Handles lobby + game WebSocket');
    console.log('[PP] API: pp.status() pp.list() pp.get(1) pp.road(1)');
})();

/*
╔══════════════════════════════════════════════════════════════════════════════╗
║                     PP WEBSOCKET INTERCEPTOR API                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Intercepts Pragmatic Play WebSocket data from both lobby and game formats.  ║
║  Data is available via window.pp API.                                        ║
║                                                                              ║
║  QUICK START                                                                 ║
║  ───────────                                                                 ║
║  pp.status()              Print all tables with stats                        ║
║  pp.list()                Array [{uid, id, name, P, B, T, total}]            ║
║  pp.count()               Number of tables                                   ║
║  pp.msgs()                Total WebSocket messages received                  ║
║                                                                              ║
║  TABLE DATA                                                                  ║
║  ──────────                                                                  ║
║  pp.tables()              All tables as object {id: tableData, ...}          ║
║  pp.get(1)                Get table by UID (number) - simple 1,2,3...        ║
║  pp.get("2q57e43...")     Get table by original ID (string)                  ║
║  pp.configs()             Raw tableconfig data from game WebSocket           ║
║  pp.order()               Table order array from WebSocket                   ║
║  pp.stats()               Global stats {playerCount: N}                      ║
║                                                                              ║
║  ROAD DATA                                                                   ║
║  ─────────                                                                   ║
║  pp.road(1)               Get bigRoad array by UID or ID                     ║
║                                                                              ║
║  EXPORT                                                                      ║
║  ──────                                                                      ║
║  pp.export()              JSON string of all table data                      ║
║  pp.clear()               Clear all stored data                              ║
║                                                                              ║
║  TABLE DATA STRUCTURE                                                        ║
║  ────────────────────                                                        ║
║  {                                                                           ║
║    uid: 1,                       // Simple numeric ID (1,2,3...)             ║
║    id: "2q57e43m4ivqwaq3",       // Original table ID                        ║
║    name: "SPEED BACCARAT 1",     // Display name                             ║
║    type: "BACCARAT",             // Table type                               ║
║    subtype: "speedbaccarat",     // Table subtype                            ║
║    dealer: "Maria",              // Dealer name                              ║
║    minBet: 1, maxBet: 150000,    // Bet limits                               ║
║    players: 245,                 // Seated players                           ║
║                                                                              ║
║    // Win counts                                                             ║
║    P: 17,                        // Player wins                              ║
║    B: 21,                        // Banker wins                              ║
║    T: 4,                         // Tie count                                ║
║    PP: 2,                        // Player pair count                        ║
║    BP: 4,                        // Banker pair count                        ║
║    total: 42,                    // Total rounds                             ║
║                                                                              ║
║    // Road data (game WebSocket only)                                        ║
║    bigRoad: [["PN0","---",...], ...],    // Big Road 2D array                ║
║    beadPlate: [...],                     // Bead Plate                       ║
║    bigEyeBoy: [...],                     // Big Eye Boy                      ║
║    smallRoad: [...],                     // Small Road                       ║
║    cockroachPig: [...],                  // Cockroach Pig                    ║
║    playerEnhance: {...},                 // Next Player prediction           ║
║    bankerEnhance: {...},                 // Next Banker prediction           ║
║                                                                              ║
║    // Lobby data only                                                        ║
║    roads: {bankerStreak: true, ...},     // Active road patterns             ║
║    games: [{player:9, banker:1, winner:"PLAYER_WIN", ...}, ...],             ║
║                                                                              ║
║    // Meta                                                                   ║
║    open: true,                   // Table open for betting                   ║
║    updated: 1733500000000,       // Last update timestamp                    ║
║    updates: 15,                  // Update count                             ║
║    source: "game"                // Data source: lobby/game/game-la          ║
║  }                                                                           ║
║                                                                              ║
║  WEBSOCKET MESSAGE TYPES                                                     ║
║  ───────────────────────                                                     ║
║  LOBBY (dga.pragmaticplaylive.net):                                          ║
║    {globalStats}           → pp.stats()                                      ║
║    {tableKey}              → pp.order()                                      ║
║    {tableId, baccaratShoeSummary, gameResult, ...}  → pp.get(id)             ║
║                                                                              ║
║  GAME (client.pragmaticplaylive.net):                                        ║
║    {tablesorder}           → pp.order()                                      ║
║    {tableconfig}           → pp.configs(), pp.get(id)                        ║
║    {statistic}             → pp.get(id) with full road data                  ║
║    {statisticLA}           → pp.get(id) incremental update                   ║
║                                                                              ║
║  EXAMPLES                                                                    ║
║  ────────                                                                    ║
║  // Check if data is flowing                                                 ║
║  pp.msgs()  // Should increase over time                                     ║
║                                                                              ║
║  // Find tables with most rounds                                             ║
║  pp.list().sort((a,b) => b.total - a.total)                                  ║
║                                                                              ║
║  // Get tables where Banker is winning                                       ║
║  Object.values(pp.tables()).filter(t => t.B > t.P)                           ║
║                                                                              ║
║  // Export for analysis                                                      ║
║  copy(pp.export())  // Copy to clipboard in DevTools                         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
*/
