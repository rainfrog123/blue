const fs = require("fs");
const path = require("path");
const express = require("express");
const WebSocket = require("ws");
const Redis = require("ioredis");
const { Pool } = require("pg");

const CONFIG_PATH = process.env.CONFIG_PATH || path.join(__dirname, "../config/ws-config.json");
const REDIS_URL = process.env.REDIS_URL || "redis://127.0.0.1:6379";
const DATABASE_URL = process.env.DATABASE_URL || "postgresql://collector:collector@127.0.0.1:5432/baccarat";
const RECONNECT_DELAY_MS = Number(process.env.RECONNECT_DELAY_MS || 3000);
const WEB_PORT = Number(process.env.WEB_PORT || 8080);

const redis = new Redis(REDIS_URL);
const pgPool = new Pool({ connectionString: DATABASE_URL });
const tableSnapshots = new Map();
const tableRounds = new Map();
const gameToLobby = new Map();
const lobbyToGame = new Map();
let tableOrderCounter = 1;

function nowIso() {
  return new Date().toISOString();
}

function loadConfig() {
  const raw = fs.readFileSync(CONFIG_PATH, "utf8");
  return JSON.parse(raw);
}

function pickTableId(payload) {
  return (
    payload?.statistic?.table ||
    payload?.statisticLA?.table ||
    payload?.betsopen?.table ||
    payload?.betsclosed?.table ||
    payload?.ShoeSummary?.table ||
    payload?.goodroad?.sourcetableId ||
    payload?.goodroad?.table ||
    payload?.game?.table ||
    payload?.timer?.table ||
    payload?.subscribe?.table ||
    payload?.betstats?.table ||
    payload?.gameresult?.table ||
    payload?.winners?.table ||
    payload?.betsclosingsoon?.table ||
    payload?.startDealing?.table ||
    payload?.startshuffling?.table ||
    payload?.endshuffling?.table ||
    payload?.voip_cc?.table ||
    payload?.seat?.table_id ||
    payload?.seat?.tableId ||
    payload?.card?.table ||
    payload?.cardinc?.table ||
    payload?.tableId ||
    payload?.disablesidebets?.tableId ||
    null
  );
}

function asId(v) {
  if (v == null) return null;
  const s = String(v).trim();
  return s || null;
}

function resolveTableId(id) {
  const s = asId(id);
  if (!s) return null;
  return lobbyToGame.get(s) || s;
}

function mergeSnapshot(targetId, sourceId) {
  const target = tableSnapshots.get(targetId);
  const source = tableSnapshots.get(sourceId);
  if (!source) return;
  if (!target) {
    tableSnapshots.set(targetId, { ...source, tableId: targetId });
    tableSnapshots.delete(sourceId);
    return;
  }
  tableSnapshots.set(targetId, {
    ...source,
    ...target,
    tableId: targetId
  });
  tableSnapshots.delete(sourceId);
}

function registerTableMapping(gameIdRaw, lobbyIdRaw) {
  const gameId = asId(gameIdRaw);
  const lobbyId = asId(lobbyIdRaw);
  if (!gameId || !lobbyId) return;
  gameToLobby.set(gameId, lobbyId);
  lobbyToGame.set(lobbyId, gameId);
  if (gameId !== lobbyId) {
    mergeSnapshot(gameId, lobbyId);
  }
}

function pickEventType(payload) {
  const keys = Object.keys(payload || {});
  if (!keys.length) return null;
  if (payload.table && typeof payload.table === "object" && "value" in payload.table) return "table_meta";
  return keys[0];
}

function pickSeq(payload) {
  const evt = pickEventType(payload);
  if (!evt) return null;
  if (payload[evt] && typeof payload[evt] === "object" && payload[evt].seq != null) return Number(payload[evt].seq);
  if (payload.seq != null) return Number(payload.seq);
  return null;
}

async function writeFrameToDb(frame) {
  await pgPool.query(
    `INSERT INTO ws_frames
      (connection_name, direction, event_type, table_id, seq, payload_json, payload_text)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [
      frame.connectionName,
      frame.direction,
      frame.eventType,
      frame.tableId,
      frame.seq,
      frame.payloadJson,
      frame.payloadText
    ]
  );
}

async function updateRedisState(frame) {
  const now = nowIso();
  const p = redis.pipeline();
  p.hset("baccarat:state:global", {
    last_seen_at: now,
    last_connection: frame.connectionName,
    last_event_type: frame.eventType || "",
    last_seq: frame.seq != null ? String(frame.seq) : ""
  });

  if (frame.tableId) {
    const key = `baccarat:state:table:${frame.tableId}`;
    p.sadd("baccarat:tables", frame.tableId);
    p.hset(key, {
      table_id: frame.tableId,
      updated_at: now,
      last_event_type: frame.eventType || "",
      last_seq: frame.seq != null ? String(frame.seq) : "",
      last_payload: frame.payloadText
    });
  }

  const results = await p.exec();
  if (!results) return;
  for (const item of results) {
    if (Array.isArray(item) && item[0]) {
      throw item[0];
    }
  }
}

async function handleIncoming(connectionName, direction, rawText, logDirections) {
  let payloadJson = null;
  let eventType = null;
  let tableId = null;
  let seq = null;

  try {
    payloadJson = JSON.parse(rawText);
    if (payloadJson?.tableconfig) {
      const cfg = payloadJson.tableconfig;
      registerTableMapping(cfg.tableId, cfg.operator_game_id);
      const gid = resolveTableId(cfg.tableId);
      if (gid) {
        const s = upsertSnapshot(gid);
        if (cfg.table_name) s.tableName = cfg.table_name;
      }
    }
    eventType = pickEventType(payloadJson);
    tableId = resolveTableId(pickTableId(payloadJson));
    seq = pickSeq(payloadJson);
  } catch (_) {
    // non-json frame; keep raw
  }

  const frame = {
    connectionName,
    direction,
    eventType,
    tableId,
    seq,
    payloadJson,
    payloadText: String(rawText),
    receivedAt: nowIso()
  };

  updateTableSnapshot(frame);
  ingestDistilledRounds(frame);
  await updateRedisState(frame);
  if (logDirections.includes(direction)) {
    await writeFrameToDb(frame);
  }
}

function upsertSnapshot(tableId) {
  if (!tableSnapshots.has(tableId)) {
    tableSnapshots.set(tableId, {
      tableId,
      tableName: null,
      orderIndex: tableOrderCounter++,
      updatedAt: nowIso(),
      phase: "unknown",
      timer: null,
      gameId: null,
      seq: null,
      playersCount: null,
      seatedPlayers: null,
      result: null,
      score: null,
      playerWinCounter: null,
      bankerWinCounter: null,
      tieCounter: null,
      totalGames: null,
      lastEventType: null
    });
  }
  return tableSnapshots.get(tableId);
}

function n(v) {
  if (v == null || v === "") return null;
  const x = Number(v);
  return Number.isFinite(x) ? x : null;
}

function normalizeTimer(v, prev = null) {
  const x = n(v);
  if (x == null) return prev;
  // Provider can emit negative timer values around phase transitions; keep UI sane.
  return x < 0 ? 0 : x;
}

function updateTableSnapshot(frame) {
  if (!frame || !frame.payloadJson || !frame.tableId) return;
  const evtType = frame.eventType;
  if (!evtType) return;
  const evt = frame.payloadJson[evtType];
  const s = upsertSnapshot(String(frame.tableId));
  s.updatedAt = nowIso();
  s.lastEventType = evtType;
  if (frame.seq != null) s.seq = frame.seq;

  // tableId payload is often a string, but totalSeatedPlayers lives on root message
  if (evtType === "tableId") {
    s.seatedPlayers = n(frame.payloadJson.totalSeatedPlayers) ?? s.seatedPlayers;
    s.tableName = frame.payloadJson.tableName || s.tableName;
  }

  if (!evt || typeof evt !== "object") return;

  if (evtType === "tableconfig") {
    s.tableName = evt.table_name || s.tableName;
  }
  if (evtType === "tableId") {
    s.tableName = frame.payloadJson.tableName || evt.tableName || s.tableName;
  }
  if (evtType === "table_meta") {
    s.tableName = evt.value || s.tableName;
  }

  if (evtType === "timer") s.timer = normalizeTimer(evt.count ?? evt.value, s.timer);
  if (evtType === "game") s.gameId = evt.game || s.gameId;
  if (evtType === "betsopen") s.phase = "bets-open";
  if (evtType === "betsclosingsoon") s.phase = "bets-closing";
  if (evtType === "betsclosed") s.phase = "bets-closed";
  if (evtType === "startDealing") s.phase = "dealing";
  if (evtType === "startshuffling") s.phase = "shuffling";
  if (evtType === "endshuffling") s.phase = "bets-open";
  if (evtType === "playersCount") s.playersCount = n(evt.count) ?? n(frame.payloadJson.playersCount);
  if (evtType === "tableId") s.seatedPlayers = n(frame.payloadJson.totalSeatedPlayers) ?? n(evt.totalSeatedPlayers) ?? s.seatedPlayers;
  if (evtType === "gameresult") {
    s.result = evt.result || s.result;
    s.score = evt.score || s.score;
    s.phase = "result";
  }
  if (evtType === "ShoeSummary") {
    s.playerWinCounter = n(evt.playerWinCounter);
    s.bankerWinCounter = n(evt.bankerWinCounter);
    s.tieCounter = n(evt.tieCounter);
    s.totalGames = n(evt.totalGames);
  }
}

function roundKey(round) {
  if (!round) return null;
  if (round.gameId) return `gid:${String(round.gameId)}`;
  if (round.seq != null) return `seq:${String(round.seq)}`;
  return `raw:${String(round.at || "")}|${String(round.result || "")}|${String(round.score || "")}`;
}

function upsertDistilledRound(tableIdRaw, roundRaw) {
  const tableId = asId(tableIdRaw);
  if (!tableId || !roundRaw) return;
  const round = {
    at: String(roundRaw.at || ""),
    seq: roundRaw.seq != null ? roundRaw.seq : null,
    result: roundRaw.result != null ? String(roundRaw.result) : null,
    score: roundRaw.score != null ? String(roundRaw.score) : null,
    gameId: roundRaw.gameId != null ? String(roundRaw.gameId) : null,
    source: roundRaw.source != null ? String(roundRaw.source) : "unknown",
    receivedAt: String(roundRaw.receivedAt || nowIso())
  };
  const key = roundKey(round);
  if (!key) return;
  if (!tableRounds.has(tableId)) tableRounds.set(tableId, new Map());
  const bucket = tableRounds.get(tableId);
  const prev = bucket.get(key);
  if (!prev) {
    bucket.set(key, round);
  } else {
    const prevHasSplitScore = String(prev.score || "").includes("-");
    const nextHasSplitScore = String(round.score || "").includes("-");
    const preferIncoming =
      (nextHasSplitScore && !prevHasSplitScore) ||
      (round.gameId && !prev.gameId) ||
      String(round.receivedAt) > String(prev.receivedAt);
    if (preferIncoming) bucket.set(key, { ...prev, ...round });
  }

  if (bucket.size > 3000) {
    const sortedKeys = Array.from(bucket.entries())
      .sort((a, b) => String(b[1].receivedAt).localeCompare(String(a[1].receivedAt)))
      .slice(0, 2500)
      .map(([k]) => k);
    const keep = new Set(sortedKeys);
    for (const k of bucket.keys()) {
      if (!keep.has(k)) bucket.delete(k);
    }
  }
}

function extractRoundsFromPayload(payloadJson, frameMeta = {}) {
  if (!payloadJson || typeof payloadJson !== "object") return [];
  const out = [];
  const p = payloadJson;

  if (Array.isArray(p.gameResult)) {
    for (const g of p.gameResult) {
      if (!g || typeof g !== "object") continue;
      out.push({
        at: g.time || frameMeta.receivedAt,
        seq: frameMeta.seq ?? null,
        result: g.winner || g.result || null,
        score: g.player != null && g.banker != null ? `${g.player}-${g.banker}` : null,
        gameId: g.gameId || null,
        source: "gameResult",
        receivedAt: frameMeta.receivedAt
      });
    }
  }

  const gr = p.gameresult;
  if (gr && typeof gr === "object") {
    out.push({
      at: frameMeta.receivedAt,
      seq: gr.seq ?? frameMeta.seq ?? null,
      result: gr.result || null,
      score: gr.score || null,
      gameId: gr.game || null,
      source: "gameresult",
      receivedAt: frameMeta.receivedAt
    });
  }

  return out;
}

function ingestDistilledRounds(frame) {
  if (!frame || !frame.payloadJson || !frame.tableId) return;
  const tableId = String(frame.tableId);
  const rounds = extractRoundsFromPayload(frame.payloadJson, { seq: frame.seq, receivedAt: frame.receivedAt });
  for (const r of rounds) upsertDistilledRound(tableId, r);
}

async function backfillDistilledRoundsFromDb(tableId, limit = 6000) {
  const { rows } = await pgPool.query(
    `SELECT received_at, seq, payload_json, payload_text
     FROM ws_frames
     WHERE table_id = $1
     ORDER BY received_at DESC
     LIMIT $2`,
    [tableId, Math.max(200, Math.min(12000, Number(limit || 6000)))]
  );
  for (const r of rows) {
    let payload = r.payload_json;
    if (!payload && r.payload_text) {
      try {
        payload = JSON.parse(String(r.payload_text));
      } catch (_) {
        payload = null;
      }
    }
    if (!payload || typeof payload !== "object") continue;
    const rounds = extractRoundsFromPayload(payload, {
      seq: r.seq ?? null,
      receivedAt: r.received_at ? new Date(r.received_at).toISOString() : nowIso()
    });
    for (const round of rounds) upsertDistilledRound(tableId, round);
  }
}

function isActiveLobbyTable(t) {
  if (!t) return false;
  const hasName = Boolean(String(t.tableName || "").trim());
  const isNumericId = /^\d+$/.test(String(t.tableId || ""));
  const hasScoreboard =
    t.totalGames != null ||
    t.playerWinCounter != null ||
    t.bankerWinCounter != null ||
    t.tieCounter != null;
  const hasRoundInfo = t.result != null || t.score != null || t.gameId != null;
  const hasPhase = t.phase && t.phase !== "unknown";
  const hasTimerOrPlayers = t.timer != null || t.playersCount != null || t.seatedPlayers != null;
  const richEvent = new Set([
    "card",
    "cardinc",
    "betsopen",
    "betsclosed",
    "betsclosingsoon",
    "startDealing",
    "gameresult",
    "winners",
    "ShoeSummary",
    "statistic",
    "statisticLA",
    "timer",
    "game",
    "table_meta"
  ]);
  const hasRichEvent = richEvent.has(t.lastEventType);
  const isSparseNoise = t.lastEventType === "goodroad" || t.lastEventType === "shuffle" || t.lastEventType === "tableId";
  const hasIdentitySignal = hasName || !isNumericId;
  const hasStrongSignal = hasScoreboard || hasPhase || hasRoundInfo || hasRichEvent;
  const hasMeaningfulSignal = hasStrongSignal || hasTimerOrPlayers;

  // Numeric lobby IDs (e.g. "007", "851") often emit sparse tableId heartbeats with no table metadata.
  // Keep them hidden until we see an actual identity or meaningful game state.
  if (!hasIdentitySignal && !hasStrongSignal) return false;
  if (isSparseNoise && !(hasScoreboard || hasPhase || hasRoundInfo || hasTimerOrPlayers)) return false;
  return hasMeaningfulSignal;
}

function connectionLoop(connCfg, storageCfg) {
  const name = connCfg.name || "unnamed";
  const headers = connCfg.headers || {};
  const logDirections = storageCfg?.logDirections || ["receive"];
  const sendFrames = connCfg.sendFrames || [];
  const sendFramesJson = connCfg.sendFramesJson || [];

  const start = () => {
    if (!connCfg.enabled) return;
    console.log(`[${name}] connecting -> ${connCfg.url}`);

    const ws = new WebSocket(connCfg.url, { headers });

    ws.on("open", async () => {
      console.log(`[${name}] connected`);
      for (const f of sendFrames) {
        const out = String(f).replace('time="0"', `time="${Date.now()}"`);
        ws.send(out);
        try {
          await handleIncoming(name, "send", out, []);
        } catch (err) {
          console.error(`[${name}] failed to log sent frame:`, err.message);
        }
      }
      for (const obj of sendFramesJson) {
        const out = JSON.stringify(obj);
        ws.send(out);
        try {
          await handleIncoming(name, "send", out, []);
        } catch (err) {
          console.error(`[${name}] failed to log sent json frame:`, err.message);
        }
      }
    });

    ws.on("message", async (data) => {
      try {
        await handleIncoming(name, "receive", data.toString("utf8"), logDirections);
      } catch (err) {
        console.error(`[${name}] message handling error:`, err.message);
      }
    });

    ws.on("close", (code, reason) => {
      console.warn(`[${name}] closed code=${code} reason=${reason.toString()}`);
      setTimeout(start, RECONNECT_DELAY_MS);
    });

    ws.on("error", (err) => {
      console.error(`[${name}] socket error:`, err.message);
    });
  };

  start();
}

async function waitForInfra() {
  for (;;) {
    try {
      await redis.ping();
      await pgPool.query("SELECT 1");
      console.log("[infra] redis + postgres ready");
      return;
    } catch (err) {
      console.warn("[infra] waiting for dependencies...", err.message);
      await new Promise((r) => setTimeout(r, 1500));
    }
  }
}

function createWebApp() {
  const app = express();
  const asyncRoute = (handler) => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
  const queryBool = (req, key) => String(req.query?.[key] || "") === "1";
  const queryInt = (req, key, fallback, min, max) => {
    const parsed = Number(req.query?.[key] ?? fallback);
    const value = Number.isFinite(parsed) ? parsed : fallback;
    return Math.max(min, Math.min(max, value));
  };

  function eventSummary(eventType, payloadJson) {
    const evt = payloadJson && eventType && payloadJson[eventType] && typeof payloadJson[eventType] === "object"
      ? payloadJson[eventType]
      : null;
    if (!evt) return "";
    if (eventType === "card" || eventType === "cardinc") return `${evt.place || "?"} card=${evt.cardCount || "?"}`;
    if (eventType === "timer") return `count=${evt.count || "?"}`;
    if (eventType === "game") return `game=${evt.game || "?"}`;
    if (eventType === "betsopen" || eventType === "betsclosed" || eventType === "betsclosingsoon") return "bet-window";
    if (eventType === "gameresult") return `result=${evt.result || "?"} score=${evt.score || "?"}`;
    if (eventType === "ShoeSummary") return `P=${evt.playerWinCounter || 0} B=${evt.bankerWinCounter || 0} T=${evt.tieCounter || 0}`;
    if (eventType === "playersCount") return `players=${evt.count || payloadJson.playersCount || "?"}`;
    return "";
  }

  app.get("/health", async (_req, res) => {
    try {
      await redis.ping();
      await pgPool.query("SELECT 1");
      res.json({ ok: true, ts: nowIso() });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get("/api/global", asyncRoute(async (_req, res) => {
    const data = await redis.hgetall("baccarat:state:global");
    res.json(data);
  }));

  app.get("/api/tables", asyncRoute(async (_req, res) => {
    const includeSparse = queryBool(_req, "include_sparse");
    const { rows } = await pgPool.query(
      `SELECT table_id, last_event_type, last_seq, last_received_at
       FROM latest_table_state
       WHERE ($1::boolean OR NOT (table_id ~ '^[0-9]+$' AND last_event_type = 'tableId'))
       ORDER BY last_received_at DESC
       LIMIT 200`,
      [includeSparse]
    );
    res.json(rows);
  }));

  app.get("/api/events", asyncRoute(async (req, res) => {
    const limit = queryInt(req, "limit", 100, 1, 500);
    const tableId = req.query.table_id ? String(req.query.table_id) : null;
    if (tableId) {
      const { rows } = await pgPool.query(
        `SELECT received_at, connection_name, event_type, table_id, seq, payload_text
         FROM ws_frames
         WHERE table_id = $1
         ORDER BY received_at DESC
         LIMIT $2`,
        [tableId, limit]
      );
      return res.json(rows);
    }
    const { rows } = await pgPool.query(
      `SELECT received_at, connection_name, event_type, table_id, seq, payload_text
       FROM ws_frames
       ORDER BY received_at DESC
       LIMIT $1`,
      [limit]
    );
    res.json(rows);
  }));

  app.get("/api/table/:tableId/changes", asyncRoute(async (req, res) => {
    const tableId = String(req.params.tableId);
    const limit = queryInt(req, "limit", 200, 1, 1000);
    const { rows } = await pgPool.query(
      `SELECT received_at, event_type, table_id, seq, payload_json, payload_text
       FROM ws_frames
       WHERE table_id = $1
       ORDER BY received_at DESC
       LIMIT $2`,
      [tableId, limit]
    );
    const out = rows.map((r) => ({
      received_at: r.received_at,
      event_type: r.event_type,
      table_id: r.table_id,
      seq: r.seq,
      summary: eventSummary(r.event_type, r.payload_json),
      payload_preview: String(r.payload_text || "").slice(0, 240)
    }));
    res.json(out);
  }));

  app.get("/api/table/:tableId/history", asyncRoute(async (req, res) => {
    const tableId = String(req.params.tableId);
    const limit = queryInt(req, "limit", 500, 10, 2000);
    const { rows } = await pgPool.query(
      `SELECT received_at, connection_name, event_type, table_id, seq, payload_json, payload_text
       FROM ws_frames
       WHERE table_id = $1
       ORDER BY received_at DESC
       LIMIT $2`,
      [tableId, limit]
    );
    res.json(rows);
  }));

  app.get("/api/table/:tableId/rounds", asyncRoute(async (req, res) => {
    const tableIdRaw = String(req.params.tableId);
    const tableId = resolveTableId(tableIdRaw) || tableIdRaw;
    const limit = queryInt(req, "limit", 800, 10, 3000);
    const tableIdStr = String(tableId);
    const minTarget = queryInt(req, "min_target", 1200, 200, 2500);
    let bucket = tableRounds.get(tableIdStr);
    if (!bucket || bucket.size < minTarget) {
      await backfillDistilledRoundsFromDb(tableIdStr, 9000);
      bucket = tableRounds.get(tableIdStr);
    }
    const rounds = bucket ? Array.from(bucket.values()).sort((a, b) => String(b.receivedAt).localeCompare(String(a.receivedAt))) : [];
    res.json({
      table_id: tableIdStr,
      total: rounds.length,
      rounds: rounds.slice(0, limit)
    });
  }));

  app.get("/api/lobby", asyncRoute(async (_req, res) => {
    const includeSparse = queryBool(_req, "include_sparse");
    const orderBy = _req.query.order === "updated" ? "updated" : "fixed";
    const rows = Array.from(tableSnapshots.values())
      .filter((t) => includeSparse || isActiveLobbyTable(t))
      .sort((a, b) => {
        if (orderBy === "updated") return String(b.updatedAt).localeCompare(String(a.updatedAt));
        return (a.orderIndex || 0) - (b.orderIndex || 0);
      })
      .slice(0, 400);
    res.json({
      ts: nowIso(),
      tables: rows
    });
  }));

  app.get("/casino", (_req, res) => {
    res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Baccarat Casino Lobby</title>
  <style>
    body { margin:0; background: radial-gradient(circle at 20% 0%, #1e293b 0%, #0b1020 55%, #060912 100%); color:#e8eef8; font-family: Inter, Arial, sans-serif; }
    .wrap { padding:16px; }
    .top { display:flex; gap:10px; align-items:center; margin-bottom:14px; flex-wrap:wrap; }
    .title { font-size:22px; font-weight:700; letter-spacing:0.3px; }
    .muted { color:#94a3b8; font-size:12px; }
    input, button { background:#111a2c; color:#e8eef8; border:1px solid #2a3a56; border-radius:8px; padding:8px 10px; }
    .grid { display:grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap:10px; }
    .card { background: linear-gradient(180deg, #132039 0%, #0f1a2d 100%); border:1px solid #22314d; border-radius:12px; padding:12px; box-shadow:0 6px 18px rgba(0,0,0,0.25); }
    .head { display:flex; justify-content:space-between; gap:8px; align-items:center; margin-bottom:10px; }
    .id { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; color:#cdd8ea; }
    .phase { padding:3px 8px; border-radius:999px; font-size:11px; font-weight:600; }
    .p-open { background:#0d3d2b; color:#8fffd0; border:1px solid #1f7b57; }
    .p-closing { background:#4b2a0f; color:#ffd6a1; border:1px solid #8f4f1c; }
    .p-closed { background:#3a1225; color:#ffc0db; border:1px solid #7e2d4f; }
    .p-dealing { background:#112f56; color:#9cd0ff; border:1px solid #2d6ab2; }
    .p-result { background:#31215a; color:#cbb8ff; border:1px solid #5b43a7; }
    .stat { display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap:6px; }
    .box { background:#0b1527; border:1px solid #22314d; border-radius:8px; padding:6px; text-align:center; }
    .k { font-size:10px; color:#8ea1bf; text-transform:uppercase; letter-spacing:0.3px; }
    .v { font-size:13px; font-weight:700; margin-top:2px; }
    .line { display:flex; justify-content:space-between; font-size:12px; color:#c3d0e4; margin-top:8px; }
    .card.clickable { cursor:pointer; transition:transform .12s ease, box-shadow .12s ease, border-color .12s ease; }
    .card.clickable:hover { transform: translateY(-2px); border-color:#3a5177; box-shadow:0 10px 20px rgba(0,0,0,0.32); }
    .detail { position:fixed; right:0; top:0; width:min(920px, 96vw); height:100vh; background:linear-gradient(180deg,#0b1527 0%, #0a1323 100%); border-left:1px solid #284064; box-shadow:-14px 0 32px rgba(0,0,0,0.45); transform:translateX(100%); transition:transform .18s ease; z-index:20; display:flex; flex-direction:column; }
    .detail.open { transform:translateX(0); }
    .detail-head { display:flex; justify-content:space-between; align-items:center; padding:12px 14px; border-bottom:1px solid #22314d; }
    .detail-title { font-size:16px; font-weight:700; color:#eaf2ff; }
    .detail-body { display:grid; grid-template-columns: 1.05fr 1fr; gap:12px; padding:12px; overflow:auto; }
    .detail-box { background:#0f1a2d; border:1px solid #22314d; border-radius:10px; padding:12px; }
    .detail-box h3 { margin:0 0 8px; font-size:12px; color:#8ea1bf; text-transform:uppercase; letter-spacing:.3px; }
    .history-list { max-height:64vh; overflow:auto; }
    .evt { border-bottom:1px solid #22314d; padding:9px 0; }
    .evt:last-child { border-bottom:none; }
    .evt-meta { display:flex; justify-content:space-between; font-size:11px; color:#9fb0c9; margin-bottom:6px; gap:8px; }
    .evt-type { color:#d4e5ff; font-weight:700; }
    .evt-payload { background:#081223; border:1px solid #1d2d45; border-radius:7px; padding:8px; font-size:12px; color:#d5e2f7; }
    .intel-name { font-size:27px; font-weight:800; margin:2px 0 10px; color:#f2f7ff; letter-spacing:.2px; }
    .intel-sub { font-size:12px; color:#9db1d3; margin-bottom:10px; }
    .intel-metrics { display:grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap:8px; margin-bottom:12px; }
    .metric { background:#0b1527; border:1px solid #22314d; border-radius:8px; padding:8px; }
    .metric .k { font-size:10px; margin-bottom:3px; }
    .metric .v { font-size:15px; margin:0; }
    .road-strip { background:#081223; border:1px solid #1d2d45; border-radius:8px; padding:9px; margin-bottom:10px; font-size:13px; color:#e5efff; word-spacing:3px; letter-spacing:.4px; }
    .bead-wrap { margin:8px 0 12px; }
    .bead-grid { display:grid; grid-template-columns: repeat(12, 18px); gap:5px; align-items:center; }
    .bead { width:18px; height:18px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:10px; font-weight:700; border:1px solid #2a3a56; }
    .bead-p { background:#17365f; color:#9fd1ff; border-color:#2e5f96; }
    .bead-b { background:#4a1f29; color:#ffc3d1; border-color:#8d374c; }
    .bead-t { background:#2f274d; color:#d3c7ff; border-color:#5d4f97; }
    .bead-q { background:#1f2a3d; color:#9aa9c2; border-color:#384b67; }
    .hands-table { width:100%; border-collapse:collapse; font-size:12px; }
    .hands-table th, .hands-table td { border-bottom:1px solid #1f2f48; padding:6px 4px; text-align:left; }
    .hands-table th { color:#8ea1bf; font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.3px; }
    .winner-p { color:#8ec5ff; font-weight:700; }
    .winner-b { color:#ffb4c9; font-weight:700; }
    .winner-t { color:#d1c0ff; font-weight:700; }
    @media (max-width: 980px) {
      .detail-body { grid-template-columns: 1fr; }
      .history-list { max-height:none; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div class="title">Baccarat Live Lobby</div>
      <div class="muted" id="stamp">loading...</div>
      <input id="q" placeholder="filter table id/name..." />
      <select id="sortBy">
        <option value="fixed">Sort: Default</option>
        <option value="updated">Sort: Recently Updated</option>
        <option value="name">Sort: Name (A-Z)</option>
        <option value="players">Sort: Players (High-Low)</option>
        <option value="timer">Sort: Timer (Low-High)</option>
      </select>
      <button onclick="loadLobby()">Refresh</button>
    </div>
    <div class="grid" id="grid"></div>
  </div>
  <div id="detail" class="detail">
    <div class="detail-head">
      <div class="detail-title" id="detailTitle">Table details</div>
      <button onclick="closeDetail()">Close</button>
    </div>
    <div class="detail-body">
      <div class="detail-box">
        <h3>Table Intelligence</h3>
        <div id="detailSnapshot">Select a table card.</div>
      </div>
      <div class="detail-box">
        <h3>Shoe History</h3>
        <div class="history-list" id="detailHistory"></div>
      </div>
    </div>
  </div>
<script>
async function j(url, timeoutMs = 7000){
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ctrl.signal });
    if (!r.ok) throw new Error('HTTP ' + String(r.status));
    return await r.json();
  } finally {
    clearTimeout(t);
  }
}
function esc(s){ return String(s ?? '').replace(/[&<>"]/g, c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[c])); }
function setTopStatus(msg){
  const el = document.getElementById('stamp');
  if (el) el.textContent = String(msg || '');
}
window.addEventListener('error', (e) => {
  setTopStatus('UI error: ' + String(e?.message || 'unknown'));
});
window.addEventListener('unhandledrejection', (e) => {
  setTopStatus('UI promise error');
});
function parseJsonSafe(s){
  try { return JSON.parse(String(s || '')); } catch (_) { return null; }
}
function winnerCode(w){
  const x = String(w || '').toLowerCase();
  if (x.includes('player')) return 'P';
  if (x.includes('banker')) return 'B';
  if (x.includes('tie')) return 'T';
  return '?';
}
function renderBeadRoad(handRows){
  const recent = (handRows || []).slice(0, 60).map(h => winnerCode(h.result));
  if (!recent.length) return '<div class="muted">No resolved hands yet.</div>';
  const beads = recent.map(c => {
    const cls = c === 'P' ? 'bead bead-p' : c === 'B' ? 'bead bead-b' : c === 'T' ? 'bead bead-t' : 'bead bead-q';
    return '<div class="' + cls + '">' + esc(c) + '</div>';
  }).join('');
  return '<div class="bead-wrap"><div class="bead-grid">' + beads + '</div></div>';
}
function winnerClass(code){
  if (code === 'P') return 'winner-p';
  if (code === 'B') return 'winner-b';
  if (code === 'T') return 'winner-t';
  return '';
}
function buildIntelligence(table, handRows){
  if (!table) return null;
  const bySeq = new Map();
  for (const h of handRows || []) {
    const key = h.seq != null ? String(h.seq) : String(h.at) + '|' + String(h.result) + '|' + String(h.score || '-');
    if (!bySeq.has(key)) bySeq.set(key, h);
  }
  const hands = Array.from(bySeq.values()).sort((a,b) => String(b.at).localeCompare(String(a.at)));
  const recent = hands.slice(0, 20);
  const totalResolvedHands = hands.length;
  const shoeTotalGames = table.totalGames != null ? Number(table.totalGames) : null;
  const road = recent.map(h => winnerCode(h.result)).join(' ');
  const streak = (() => {
    if (!recent.length) return '-';
    const first = winnerCode(recent[0].result);
    let c = 0;
    for (const h of recent) {
      if (winnerCode(h.result) !== first) break;
      c += 1;
    }
    return String(first) + ' x' + String(c);
  })();
  const chips = [
    'Phase ' + String(table.phase || '-'),
    'Players ' + String(table.playersCount ?? table.seatedPlayers ?? '-'),
    'Timer ' + String(table.timer ?? '-'),
    'P/B/T ' + String(table.playerWinCounter ?? 0) + '/' + String(table.bankerWinCounter ?? 0) + '/' + String(table.tieCounter ?? 0),
    'Total ' + String(table.totalGames ?? hands.length ?? 0),
    'Streak ' + String(streak)
  ];
  const lastHands = recent.slice(0, 8).map((h) => ({
    code: winnerCode(h.result),
    score: String(h.score || '-'),
    gameId: String(h.gameId || '-'),
    at: String(h.at || '-')
  }));
  return {
    tableName: String(table.tableName || table.tableId),
    tableId: String(table.tableId || '-'),
    chips,
    road: String(road || '-'),
    totalResolvedHands,
    shoeTotalGames,
    recentHands: lastHands
  };
}
function renderTableIntelligence(intel){
  if (!intel) return '<div class="muted">No live snapshot found.</div>';
  const metrics = intel.chips.map(c => {
    const parts = String(c).split(' ');
    const k = parts.shift() || '-';
    const v = parts.join(' ') || '-';
    return '<div class="metric"><div class="k">' + esc(k) + '</div><div class="v">' + esc(v) + '</div></div>';
  }).join('');
  const rows = (intel.recentHands || []).map(h =>
    '<tr><td class="' + winnerClass(h.code) + '">' + esc(h.code) + '</td><td>' + esc(h.score) + '</td><td>' + esc(h.gameId) + '</td><td>' + esc(h.at) + '</td></tr>'
  ).join('');
  return '<div class="intel-name">' + esc(intel.tableName) + '</div>' +
    '<div class="intel-sub">' + esc(intel.tableId) + '</div>' +
    '<div class="intel-metrics">' + metrics + '</div>' +
    '<div class="k">ROAD (LATEST 20 / PARSED ' + esc(String(intel.totalResolvedHands ?? 0)) + ' / SHOE ' + esc(String(intel.shoeTotalGames ?? '-')) + ')</div>' +
    '<div class="road-strip">' + esc(intel.road) + '</div>' +
    '<div class="k">LAST HANDS</div>' +
    '<table class="hands-table"><thead><tr><th>W</th><th>Score</th><th>Game</th><th>Time</th></tr></thead><tbody>' + (rows || '<tr><td colspan="4" class="muted">No hands yet.</td></tr>') + '</tbody></table>';
}
function buildDistilledHistory(rows){
  const out = [];
  for (const e of rows || []) {
    const p = e.payload_json || parseJsonSafe(e.payload_text) || {};
    if (!p || typeof p !== 'object') continue;
    if (Array.isArray(p.gameResult)) {
      for (const g of p.gameResult) {
        out.push({
          at: e.received_at || g.time,
          seq: e.seq,
          result: g.winner || g.result || null,
          score: g.player != null && g.banker != null ? String(g.player) + '-' + String(g.banker) : null,
          gameId: g.gameId || null,
          source: 'gameResult'
        });
      }
    }
    const gr = p.gameresult;
    if (gr && typeof gr === 'object') {
      out.push({
        at: e.received_at,
        seq: gr.seq ?? e.seq ?? null,
        result: gr.result || null,
        score: gr.score || null,
        gameId: gr.game || null,
        source: 'gameresult'
      });
    }
  }
  return out;
}
function dedupeHands(handRows){
  const rows = (handRows || [])
    .slice()
    .sort((a, b) => String(b.at).localeCompare(String(a.at)));
  const byGame = new Map();
  const accepted = [];
  for (const h of rows) {
    const gameKey = h.gameId ? String(h.gameId) : null;
    if (gameKey) {
      if (byGame.has(gameKey)) continue;
      byGame.set(gameKey, true);
      accepted.push(h);
      continue;
    }
    const ts = Date.parse(String(h.at || ''));
    const winner = winnerCode(h.result);
    const score = String(h.score || '');
    const isLikelyCompactDuplicate = winner !== '?' && !score.includes('-');
    if (isLikelyCompactDuplicate && Number.isFinite(ts)) {
      const dup = accepted.some((x) => {
        if (!x || !x.gameId) return false;
        const xts = Date.parse(String(x.at || ''));
        if (!Number.isFinite(xts)) return false;
        return winnerCode(x.result) === winner && Math.abs(xts - ts) <= 3000;
      });
      if (dup) continue;
    }
    accepted.push(h);
  }
  return accepted.sort((a, b) => String(b.at).localeCompare(String(a.at)));
}
function renderShoeHistory(rows, handRows){
  const hands = handRows || [];
  const latestSummary = (rows || []).find((e) => String(e.event_type || '') === 'ShoeSummary');
  const latestSummaryPayload = latestSummary ? (latestSummary.payload_json || parseJsonSafe(latestSummary.payload_text) || {}) : {};
  const latestShoe = latestSummaryPayload && latestSummaryPayload.ShoeSummary ? latestSummaryPayload.ShoeSummary : {};
  const shoeTotal = latestShoe.totalGames != null ? String(latestShoe.totalGames) : '-';
  const recentCodes = hands.map(h => winnerCode(h.result)).join(' ');
  const summaries = (rows || [])
    .filter(e => String(e.event_type || '') === 'ShoeSummary')
    .slice(0, 6)
    .map(e => {
      const p = e.payload_json || parseJsonSafe(e.payload_text) || {};
      const s = p.ShoeSummary || {};
      return '<div class="evt"><div class="evt-meta"><span class="evt-type">ShoeSummary</span><span>' + esc(e.received_at || '-') + '</span></div>' +
        '<div class="evt-payload">P/B/T ' + esc(String(s.playerWinCounter ?? '-')) + ' / ' + esc(String(s.bankerWinCounter ?? '-')) + ' / ' + esc(String(s.tieCounter ?? '-')) +
        ' | total ' + esc(String(s.totalGames ?? '-')) + '</div></div>';
    }).join('');

  const rounds = hands.map((h, i) => {
    const result = winnerCode(h.result);
    const when = String(h.at || '-');
    return '<div class="evt"><div class="evt-meta"><span class="evt-type">Round ' + esc(String(i + 1)) + '</span><span>' + esc(when) + '</span></div>' +
      '<div class="evt-payload">result ' + esc(result) + ' | score ' + esc(String(h.score || '-')) + ' | gameId ' + esc(String(h.gameId || '-')) + ' | seq ' + esc(String(h.seq ?? '-')) + '</div></div>';
  }).join('');

  return (
    '<div class="evt"><div class="evt-meta"><span class="evt-type">Road Trend</span><span>parsed ' + esc(String(hands.length)) + ' / shoe total ' + esc(shoeTotal) + '</span></div><div class="evt-payload">' + esc(recentCodes || '-') + '</div></div>' +
    (summaries || '<div class="evt"><div class="evt-payload">No shoe summaries yet.</div></div>') +
    (rounds || '<div class="evt"><div class="evt-payload">No resolved rounds yet.</div></div>')
  );
}
function phaseClass(p){
  if (p === 'bets-open') return 'p-open';
  if (p === 'bets-closing') return 'p-closing';
  if (p === 'bets-closed' || p === 'shuffling') return 'p-closed';
  if (p === 'dealing') return 'p-dealing';
  if (p === 'result') return 'p-result';
  return 'p-dealing';
}
function render(t){
  const title = t.tableName || t.tableId;
  const encodedId = encodeURIComponent(String(t.tableId || ''));
  return '<div class="card clickable" onclick="openDetail(\\''+encodedId+'\\')">' +
    '<div class="head"><div><div style="font-size:13px;font-weight:700;color:#eaf2ff;">'+esc(title)+'</div><div class="id">'+esc(t.tableId)+'</div></div><div class="phase '+phaseClass(t.phase)+'">'+esc(t.phase || 'unknown')+'</div></div>' +
    '<div class="stat">' +
      '<div class="box"><div class="k">Timer</div><div class="v">'+esc(t.timer ?? '-')+'</div></div>' +
      '<div class="box"><div class="k">Players</div><div class="v">'+esc(t.playersCount ?? t.seatedPlayers ?? '-')+'</div></div>' +
      '<div class="box"><div class="k">P / B / T</div><div class="v">'+esc((t.playerWinCounter ?? '-') + '/' + (t.bankerWinCounter ?? '-') + '/' + (t.tieCounter ?? '-'))+'</div></div>' +
      '<div class="box"><div class="k">Total</div><div class="v">'+esc(t.totalGames ?? '-')+'</div></div>' +
    '</div>' +
    '<div class="line"><span>Result</span><span>'+esc(t.result || '-')+'</span></div>' +
    '<div class="line"><span>Score</span><span>'+esc(t.score || '-')+'</span></div>' +
    '<div class="line"><span>Last Event</span><span>'+esc(t.lastEventType || '-')+'</span></div>' +
    '<div class="line"><span>Seq</span><span>'+esc(t.seq ?? '-')+'</span></div>' +
    '<div class="line"><span>Updated</span><span>'+esc(t.updatedAt || '-')+'</span></div>' +
  '</div>';
}
function closeDetail(){
  document.getElementById('detail').classList.remove('open');
}
async function openDetail(encodedId){
  const tableId = decodeURIComponent(encodedId || '');
  if (!tableId) return;
  document.getElementById('detail').classList.add('open');
  document.getElementById('detailTitle').textContent = 'Table details: ' + tableId;
  document.getElementById('detailSnapshot').textContent = 'Loading...';
  document.getElementById('detailHistory').innerHTML = '<div class="muted">Loading...</div>';
  try {
    let table = (lastLobbyRows || []).find(t => String(t.tableId) === String(tableId));
    if (table) {
      const quickIntel = buildIntelligence(table, []);
      document.getElementById('detailSnapshot').innerHTML = renderTableIntelligence(quickIntel);
    }
    const expectedGames = Number(table && table.totalGames != null ? table.totalGames : 0);
    const roundsLimit = Math.max(200, Math.min(3000, Number.isFinite(expectedGames) && expectedGames > 0 ? (expectedGames * 3) : 800));
    const minTarget = Math.max(200, Math.min(2500, Number.isFinite(expectedGames) && expectedGames > 0 ? (expectedGames * 2) : 1200));
    const historyPromise = j('/api/table/' + encodeURIComponent(tableId) + '/history?limit=500', 7000);
    const roundsPromise = j('/api/table/' + encodeURIComponent(tableId) + '/rounds?limit=' + String(roundsLimit) + '&min_target=' + String(minTarget), 7000);
    const lobbyPromise = table ? Promise.resolve({ tables: lastLobbyRows }) : j('/api/lobby?include_sparse=1', 5000);
    const [detailHistory, roundsData, lobby] = await Promise.all([historyPromise, roundsPromise, lobbyPromise]);
    if (!table) table = (lobby.tables || []).find(t => String(t.tableId) === String(tableId));
    const shoeHands = dedupeHands(Array.isArray(roundsData && roundsData.rounds) ? roundsData.rounds : buildDistilledHistory(detailHistory));
    const intel = buildIntelligence(table, shoeHands);
    const summaryHtml = renderTableIntelligence(intel);
    const beadRoadHtml = renderBeadRoad(shoeHands);
    document.getElementById('detailSnapshot').innerHTML = summaryHtml + beadRoadHtml;
    document.getElementById('detailHistory').innerHTML = renderShoeHistory(detailHistory, shoeHands);
  } catch (err) {
    const msg = (err && err.name === 'AbortError')
      ? 'Request timed out. Click the card again to retry.'
      : ('Failed to load details: ' + (err?.message || String(err)));
    document.getElementById('detailSnapshot').innerHTML = '<div class="muted">' + esc(msg) + '</div>';
    document.getElementById('detailHistory').innerHTML = '<div class="muted">' + esc(msg) + '</div>';
  }
}
async function loadLobby(){
  try {
    const sortBy = document.getElementById('sortBy').value || 'fixed';
    const orderParam = sortBy === 'updated' ? '?order=updated' : '';
    const data = await j('/api/lobby' + orderParam);
    const q = document.getElementById('q').value.trim().toLowerCase();
    const rows = (data.tables || []).filter(t => {
      if (!q) return true;
      return String(t.tableId || '').toLowerCase().includes(q) || String(t.tableName || '').toLowerCase().includes(q);
    });
    rows.sort((a, b) => {
      if (sortBy === 'name') {
        const an = String(a.tableName || a.tableId || '');
        const bn = String(b.tableName || b.tableId || '');
        return an.localeCompare(bn);
      }
      if (sortBy === 'players') {
        const ap = Number(a.playersCount ?? a.seatedPlayers ?? -1);
        const bp = Number(b.playersCount ?? b.seatedPlayers ?? -1);
        return bp - ap;
      }
      if (sortBy === 'timer') {
        const at = Number(a.timer ?? 9999);
        const bt = Number(b.timer ?? 9999);
        return at - bt;
      }
      return 0;
    });
    lastLobbyRows = rows;
    document.getElementById('stamp').textContent = 'tables: ' + rows.length + ' | updated: ' + (data.ts || '');
    document.getElementById('grid').innerHTML = rows.map(render).join('') || '<div class="muted">No live tables yet.</div>';
  } catch (err) {
    const msg = (err && err.name === 'AbortError')
      ? 'Lobby request timed out.'
      : ('Failed to load lobby: ' + (err?.message || String(err)));
    document.getElementById('stamp').textContent = msg;
    document.getElementById('grid').innerHTML = '<div class="card"><div class="muted">' + esc(msg) + '</div><div style="margin-top:8px;"><button onclick="loadLobby()">Retry</button></div></div>';
  }
}
let lastLobbyRows = [];
window.addEventListener('DOMContentLoaded', () => {
  const q = document.getElementById('q');
  const sort = document.getElementById('sortBy');
  if (!q || !sort) {
    setTopStatus('UI init failed: controls missing');
    return;
  }
  q.addEventListener('input', loadLobby);
  sort.addEventListener('change', loadLobby);
  loadLobby();
  setInterval(loadLobby, 2500);
});
</script>
</body>
</html>`);
  });

  app.get("/", (_req, res) => {
    res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Baccarat Table Change Tracker</title>
  <style>
    body { font-family: Arial, sans-serif; background:#0b0f14; color:#e8eef5; margin:20px; }
    h1 { margin:0 0 12px; }
    .sub { color:#8ba0b7; margin:0 0 14px; font-size:13px; }
    .row { display:flex; gap:12px; margin-bottom:12px; }
    .card { background:#111a24; border:1px solid #233041; border-radius:8px; padding:12px; min-width:260px; }
    table { width:100%; border-collapse:collapse; font-size:12px; }
    th, td { border-bottom:1px solid #223; padding:6px; text-align:left; }
    th { background:#122033; position:sticky; top:0; }
    input, button { background:#122033; color:#e8eef5; border:1px solid #2b4564; border-radius:6px; padding:6px 8px; }
    .mono { font-family: monospace; white-space: pre-wrap; word-break:break-word; }
    .selected { outline:2px solid #47a8ff; }
    .muted { color:#8ba0b7; }
    .left { width: 42%; min-width: 460px; }
    .right { flex:1; min-width:520px; }
  </style>
</head>
<body>
  <h1>Baccarat Table Change Tracker</h1>
  <p class="sub">Click a table to see its latest change sequence in plain language.</p>
  <div class="row">
    <div class="card"><b>Global</b><div id="global" class="mono">loading...</div></div>
    <div class="card">
      <b>Controls</b>
      <div style="margin-top:8px;">Table filter: <input id="tableFilter" placeholder="contains..." /></div>
      <div style="margin-top:8px;">Limit: <input id="limit" value="200" style="width:80px;" /></div>
      <div style="margin-top:8px;"><button onclick="loadAll()">Refresh now</button></div>
    </div>
  </div>
  <div class="row">
    <div class="card left">
      <b>Live Tables</b> <span class="muted" id="tableCount"></span>
      <div style="max-height:560px; overflow:auto; margin-top:8px;">
        <table id="tables"><thead><tr><th>table_id</th><th>event</th><th>seq</th><th>updated</th></tr></thead><tbody></tbody></table>
      </div>
    </div>
    <div class="card right">
      <b>Changes</b> <span id="selectedTable" class="muted"></span>
      <div style="max-height:560px; overflow:auto; margin-top:8px;">
        <table id="changes"><thead><tr><th>time</th><th>seq</th><th>event</th><th>summary</th><th>payload</th></tr></thead><tbody></tbody></table>
      </div>
    </div>
  </div>
<script>
async function j(url){ const r=await fetch(url); return r.json(); }
function esc(s){ return String(s ?? '').replace(/[&<>"]/g, c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[c])); }
let selected = '';
let allTables = [];
function setSelectedTable(id){
  selected = id || '';
  document.getElementById('selectedTable').textContent = selected ? ' - ' + selected : '';
  renderTableRows();
  loadChanges();
}
function renderTableRows(){
  const f = document.getElementById('tableFilter').value.trim().toLowerCase();
  const rows = allTables.filter(t => !f || String(t.table_id || '').toLowerCase().includes(f));
  document.getElementById('tableCount').textContent = '(' + rows.length + ')';
  document.querySelector('#tables tbody').innerHTML = rows.map(t=>{
    const cls = String(t.table_id) === selected ? ' class="selected"' : '';
    return '<tr'+cls+' onclick="setSelectedTable(\\''+esc(t.table_id)+'\\')"><td>'+esc(t.table_id)+'</td><td>'+esc(t.last_event_type)+'</td><td>'+esc(t.last_seq)+'</td><td>'+esc(t.last_received_at)+'</td></tr>';
  }).join('');
}
async function loadChanges(){
  if(!selected){ document.querySelector('#changes tbody').innerHTML = '<tr><td colspan="5" class="muted">Pick a table from left list.</td></tr>'; return; }
  const lim = Math.max(10, Math.min(1000, Number(document.getElementById('limit').value || 200)));
  const ev = await j('/api/table/' + encodeURIComponent(selected) + '/changes?limit=' + lim);
  document.querySelector('#changes tbody').innerHTML = ev.map(e=>
    '<tr><td>'+esc(e.received_at)+'</td><td>'+esc(e.seq)+'</td><td>'+esc(e.event_type)+'</td><td>'+esc(e.summary)+'</td><td class="mono">'+esc(e.payload_preview)+'</td></tr>'
  ).join('');
}
async function loadAll(){
  const g = await j('/api/global'); document.getElementById('global').textContent = JSON.stringify(g, null, 2);
  allTables = await j('/api/tables');
  if(!selected && allTables.length) selected = String(allTables[0].table_id || '');
  renderTableRows();
  await loadChanges();
}
document.getElementById('tableFilter').addEventListener('input', renderTableRows);
loadAll(); setInterval(loadAll, 4000);
</script>
</body></html>`);
  });

  app.use((err, _req, res, _next) => {
    console.error("[web] request error:", err?.message || err);
    if (res.headersSent) return;
    res.status(500).json({ ok: false, error: "Internal server error" });
  });

  app.listen(WEB_PORT, () => {
    console.log(`[web] dashboard listening on :${WEB_PORT}`);
  });
}

async function main() {
  await waitForInfra();
  createWebApp();
  const config = loadConfig();
  const connections = Array.isArray(config.connections) ? config.connections : [];
  if (!connections.length) {
    console.error("No connections found in config.");
    process.exit(1);
  }

  for (const conn of connections) {
    connectionLoop(conn, config.storage || {});
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
