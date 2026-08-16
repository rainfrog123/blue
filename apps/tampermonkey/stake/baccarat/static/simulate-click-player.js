// Simulate real click with all pointer/mouse events
// DOM: PP multibaccarat 1.3.30+ — use TileHeight / data-betcode / text labels (not hashed classes)

function simulateRealClick(el) {
    if (!el) return false;

    const rect = el.getBoundingClientRect();
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;

    const opts = {
        bubbles: true,
        cancelable: true,
        composed: true,
        clientX: x,
        clientY: y,
        screenX: x,
        screenY: y,
        pointerId: 1,
        pointerType: "mouse",
        isPrimary: true
    };

    el.dispatchEvent(new FocusEvent("focus", { bubbles: true }));

    el.dispatchEvent(new PointerEvent("pointerover", opts));
    el.dispatchEvent(new PointerEvent("pointerenter", opts));
    el.dispatchEvent(new PointerEvent("pointerdown", opts));

    el.dispatchEvent(new MouseEvent("mouseover", opts));
    el.dispatchEvent(new MouseEvent("mouseenter", opts));
    el.dispatchEvent(new MouseEvent("mousedown", opts));

    el.dispatchEvent(new PointerEvent("pointerup", opts));
    el.dispatchEvent(new MouseEvent("mouseup", opts));
    el.dispatchEvent(new MouseEvent("click", opts));

    return true;
}

/** Parse stable tile labels: table name + `ID: <round>` (hashed class names change every build). */
function getTileMeta(tile) {
    const gameId = (tile.id || "").replace(/^TileHeight-/, "");
    const texts = [...tile.querySelectorAll("span")]
        .map((s) => (s.textContent || "").trim())
        .filter(Boolean);

    const idText = texts.find((t) => /^ID:\s*\d+/i.test(t)) || "";
    const name =
        texts.find(
            (t) =>
                t !== idText &&
                !/^ID:/i.test(t) &&
                !/^\$/.test(t) &&
                !/^\d+(\.\d+)?$/.test(t) &&
                t.length > 1
        ) || "";

    return { gameId, name, idText };
}

function findTileByNameAndId(tableName, tableIdText) {
    const tiles = document.querySelectorAll('[id^="TileHeight-"]');
    for (const tile of tiles) {
        const { name, idText, gameId } = getTileMeta(tile);
        const idHaystack = `${idText} ${gameId}`;
        if (name === tableName && idHaystack.includes(String(tableIdText))) {
            return { tile, name, idText, gameId };
        }
    }
    return null;
}

function clickBetOnTable(side, tableName, tableIdText, clicks = 1) {
    const betcode = side === "B" ? "1" : "0";
    const label = side === "B" ? "Banker" : "Player";
    const hit = findTileByNameAndId(tableName, tableIdText);

    if (!hit) {
        console.log(`[Click] Table not found: ${tableName} / ${tableIdText}`);
        return false;
    }

    const btn = hit.tile.querySelector(`[data-betcode="${betcode}"]`);
    if (!btn) {
        console.log(`[Click] ${label} button not found on ${tableName} (table may not be open for betting)`);
        return false;
    }

    for (let i = 0; i < clicks; i++) {
        setTimeout(() => simulateRealClick(btn), i * 50);
    }

    console.log(`[Click] Clicked ${label} ${clicks}x on ${tableName} (${hit.idText || hit.gameId})`);
    return true;
}

function clickPlayerOnTable(tableName, tableIdText, clicks = 1) {
    return clickBetOnTable("P", tableName, tableIdText, clicks);
}

function clickBankerOnTable(tableName, tableIdText, clicks = 1) {
    return clickBetOnTable("B", tableName, tableIdText, clicks);
}

function listTables() {
    const tiles = document.querySelectorAll('[id^="TileHeight-"]');
    const tables = [];

    tiles.forEach((tile, index) => {
        const { name, idText, gameId } = getTileMeta(tile);
        const canPlayer = !!tile.querySelector('[data-betcode="0"]');
        const canBanker = !!tile.querySelector('[data-betcode="1"]');
        if (!name && !gameId) return;
        const row = {
            index,
            name,
            id: idText,
            gameId,
            canBet: canPlayer || canBanker
        };
        tables.push(row);
        console.log(
            `[${index}] ${name || "(unnamed)"} | ${idText || "—"} | ${gameId}` +
                (row.canBet ? " | BET OPEN" : "")
        );
    });

    return tables;
}

window.simulateRealClick = simulateRealClick;
window.getTileMeta = getTileMeta;
window.clickPlayerOnTable = clickPlayerOnTable;
window.clickBankerOnTable = clickBankerOnTable;
window.listTables = listTables;

console.log(`
╔════════════════════════════════════════════════════════════╗
║           CLICK SIMULATOR LOADED (DOM 1.3.30+)             ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  listTables()                                              ║
║    → List tiles: name | ID:… | gameId | BET OPEN           ║
║                                                            ║
║  clickPlayerOnTable("Baccarat 3", "10940583319", 5)        ║
║    → Click Player 5 times on matching table                ║
║                                                            ║
║  clickBankerOnTable("Baccarat 3", "10940583319", 5)        ║
║    → Click Banker 5 times on matching table                ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
`);
