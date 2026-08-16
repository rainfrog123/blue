# WebSocket Logging Reference (`socks.js`)

This document lists the websocket information currently intercepted and stored by `baccarat/core/socks.js` (v3.2).

## Scope

- Source domains: Pragmatic Play lobby/game sockets used on Stake.
- Message direction: JSON `receive` frames.
- Storage model:
  - Global/session state
  - ID mapping/config state
  - Per-table state in `tables` map

---

## 1) Global/session state

- `msgCount`: total parsed websocket JSON messages.
- `lastSeq`: highest observed sequence number.
- `tablesOrder`: latest known table ordering (from `tableKey` or `tablesorder`).
- `globalStats`: raw lobby global stats object.
- `lastPlayersCount`: latest lobby players count payload.

### Warning filter state

- `suppressGoodRoadWarnings` (default: `true`)
- Suppresses only warnings containing both:
  - `is not in tablesOrder`
  - `GoodRoadGameCommunicationProcessor`

---

## 2) ID and config maps

- `uidMap`: numeric `uid -> gameId`
- `idToUid`: `gameId -> uid`
- `gameToLobby`: `gameId -> lobbyId`
- `lobbyToGame`: `lobbyId -> gameId`
- `configs`: raw `tableconfig` by `gameId`

### URL context helper

`tableId` is extracted from websocket URL query string when available, allowing table-less frames (e.g. `dealer`, `table`, `currentShoe`, `pong`) to be attached to the correct table row.

---

## 3) Message families intercepted

## Lobby-like frames

- `globalStats`
- `playersCount`
- `tableKey`
- `tableId` (full lobby update)
- `tableId + totalSeatedPlayers` (delta update)
- `tableId + partial fields` (`statistics`, `gameResult`, `goodRoadsMap`, `goodRoadsDepthMap`, `grTableCount`, `shuffle`)

## Game-like frames

- `tablesorder`
- `tableconfig`
- `statistic`
- `statisticLA`
- `betsopen`
- `betsclosed`
- `ShoeSummary`
- `goodroad`
- `game`
- `timer`
- `dealer`
- `table` (meta)
- `subscribe`
- `betstats`
- `disablesidebets`
- `gameresult`
- `winners`
- `betsclosingsoon`
- `startDealing`
- `startshuffling`
- `endshuffling`
- `currentShoe`
- `voip_cc`
- `pong`
- `seat`
- `card`
- `cardinc`

---

## 4) Per-table fields logged (`tables` map)

Each row is keyed by normalized `gameId`.

## Identity and metadata

- `uid`
- `id`
- `gameId`
- `lobbyId`
- `name`
- `type`
- `subtype`
- `category`
- `open`
- `updated`
- `updates`
- `source`

## Limits and static table config

- `minBet`
- `maxBet`
- `bettingTime`
- `mtbGroupId`

## Baccarat counters

- `P` (player win count)
- `B` (banker win count)
- `T` (tie count)
- `PP` (player pair count)
- `BP` (banker pair count)
- `total`

## Road/history structures

- `roads`
- `bigRoad`
- `games`
- `beadPlate`
- `bigEyeBoy`
- `smallRoad`
- `cockroachPig`
- `playerEnhance`
- `bankerEnhance`
- `lastBR`
- `lastBP`
- `lastBEB`
- `lastSR`
- `lastCP`
- `goodRoadsDepthMap`
- `grTableCount`
- `shuffle`

## Betting window state

- `canBet`
- `currentGame`
- `betStatusTime`

## Live/event snapshots (latest payload style)

- `goodroadLive`
- `gameClock`
- `gameStartTime`
- `bettingTimer`
- `timerGameId`
- `dealer`
- `dealerId`
- `tableLabel`
- `tableOpenTime`
- `tableNewTable`
- `tableMetaSeq`
- `subscribeChannel`
- `subscribeStatus`
- `betstats`
- `disabledSidebets`
- `lastGameresult`
- `lastWinners`
- `betsClosingSoon`
- `betsClosingSoonGame`
- `dealing`
- `dealingGame`
- `shuffling`
- `shuffleGame`
- `currentShoe`
- `voip`
- `lastPong`
- `lastSeatEvent`
- `lastCard`
- `lastCardInc`
- `seq`

---

## 5) API methods to inspect logged data

## Primary views

- `pp.get(id)` -> full row for one table (`uid | gameId | lobbyId`)
- `pp.tables()` -> all rows keyed by `gameId`
- `pp.list()` -> compact ranked list

## Grouped live view

- `pp.live(id)` / `pp.lastEvents(id)` -> grouped live snapshot:
  - card/timer/goodroad/game/gameresult/winners/betstats/etc.

## Global/session views

- `pp.stats()`
- `pp.order()`
- `pp.msgs()`
- `pp.seq()`

## ID mapping

- `pp.gameToLobby(gameId)`
- `pp.lobbyToGame(lobbyId)`

## Road helpers

- `pp.road(id)`
- `pp.pbt(id)`
- `pp.pbtStr(id)`
- `pp.lastN(id, n)`
- `pp.sequences()`
- `pp.seqAll()`

## Utility and controls

- `pp.configs()`
- `pp.export()`
- `pp.clear()`
- `pp.help()`
- `pp.setWarnFilter(true|false)`
- `pp.warnFilter()`

---

## Notes

- This reference describes current behavior of `socks.js`; fields can evolve if websocket schema changes.
- Binary/non-JSON frames are not parsed by this logger.
