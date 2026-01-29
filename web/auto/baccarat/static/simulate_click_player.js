// Simulate real click with all pointer/mouse events
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

    // Focus
    el.dispatchEvent(new FocusEvent("focus", { bubbles: true }));

    // Pointer events (PP requires these)
    el.dispatchEvent(new PointerEvent("pointerover", opts));
    el.dispatchEvent(new PointerEvent("pointerenter", opts));
    el.dispatchEvent(new PointerEvent("pointerdown", opts));

    // Mouse events (also required)
    el.dispatchEvent(new MouseEvent("mouseover", opts));
    el.dispatchEvent(new MouseEvent("mouseenter", opts));
    el.dispatchEvent(new MouseEvent("mousedown", opts));

    // Release / click
    el.dispatchEvent(new PointerEvent("pointerup", opts));
    el.dispatchEvent(new MouseEvent("mouseup", opts));
    el.dispatchEvent(new MouseEvent("click", opts));

    return true;
}

// Click Player button on a specific table by name and ID
function clickPlayerOnTable(tableName, tableIdText, clicks = 1) {
    const tiles = document.querySelectorAll('[id^="TileHeight-"]');

    for (const tile of tiles) {
        const nameEl = tile.querySelector('.rM_r1');
        const idEl = tile.querySelector('.wq_wr');

        const name = nameEl?.textContent.trim();
        const id = idEl?.textContent.trim();

        if (name === tableName && id && id.includes(tableIdText)) {
            const playerBtnWrapper = tile.querySelector('.lq_lv');
            const playerBtn = playerBtnWrapper?.querySelector('[data-betcode="0"]') || playerBtnWrapper;

            if (!playerBtn) {
                console.log(`[Click] Player button not found on ${tableName}`);
                return false;
            }

            for (let i = 0; i < clicks; i++) {
                setTimeout(() => simulateRealClick(playerBtn), i * 50);
            }

            console.log(`[Click] Clicked Player ${clicks}x on ${tableName} (${id})`);
            return true;
        }
    }

    console.log(`[Click] Table not found: ${tableName} / ${tableIdText}`);
    return false;
}

// Click Banker button on a specific table by name and ID
function clickBankerOnTable(tableName, tableIdText, clicks = 1) {
    const tiles = document.querySelectorAll('[id^="TileHeight-"]');

    for (const tile of tiles) {
        const nameEl = tile.querySelector('.rM_r1');
        const idEl = tile.querySelector('.wq_wr');

        const name = nameEl?.textContent.trim();
        const id = idEl?.textContent.trim();

        if (name === tableName && id && id.includes(tableIdText)) {
            const bankerBtnWrapper = tile.querySelector('.lq_lw');
            const bankerBtn = bankerBtnWrapper?.querySelector('[data-betcode="1"]') || bankerBtnWrapper;

            if (!bankerBtn) {
                console.log(`[Click] Banker button not found on ${tableName}`);
                return false;
            }

            for (let i = 0; i < clicks; i++) {
                setTimeout(() => simulateRealClick(bankerBtn), i * 50);
            }

            console.log(`[Click] Clicked Banker ${clicks}x on ${tableName} (${id})`);
            return true;
        }
    }

    console.log(`[Click] Table not found: ${tableName} / ${tableIdText}`);
    return false;
}

// List all visible tables with their names and IDs
function listTables() {
    const tiles = document.querySelectorAll('[id^="TileHeight-"]');
    const tables = [];

    tiles.forEach((tile, index) => {
        const name = tile.querySelector('.rM_r1')?.textContent.trim() || '';
        const id = tile.querySelector('.wq_wr')?.textContent.trim() || '';
        if (name) {
            tables.push({ index, name, id });
            console.log(`[${index}] ${name} | ${id}`);
        }
    });

    return tables;
}

// Expose to global scope for console use
window.simulateRealClick = simulateRealClick;
window.clickPlayerOnTable = clickPlayerOnTable;
window.clickBankerOnTable = clickBankerOnTable;
window.listTables = listTables;

console.log(`
╔════════════════════════════════════════════════════════════╗
║           CLICK SIMULATOR LOADED                           ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  listTables()                                              ║
║    → List all visible tables with names and IDs            ║
║                                                            ║
║  clickPlayerOnTable("Baccarat 3", "10940583319", 5)        ║
║    → Click Player 5 times on matching table                ║
║                                                            ║
║  clickBankerOnTable("Baccarat 3", "10940583319", 5)        ║
║    → Click Banker 5 times on matching table                ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
`);
