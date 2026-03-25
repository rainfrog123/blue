// ==UserScript==
// @name         table checker
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Monitors all baccarat tables data and tracks changes
// @author       You
// @match        *://client.pragmaticplaylive.net/desktop/multibaccarat/*
// @grant        none
// @run-at       document-end
// ==/UserScript==

(function() {
    'use strict';

    const CONFIG = {
        TILE_SELECTOR: '.TileComponent_tileMobile__2wg6p',
        CHECK_INTERVAL: 1000, // Check every second
        DEBUG: false
    };

    class TableData {
        constructor(element, id) {
            this.element = element;
            this.id = id;
            this.data = {};
            this.previousData = {};
        }

        parseTableData() {
            try {
                const text = this.element.innerText;
                const lines = text.split('\n').map(line => line.trim()).filter(line => line);
                
                const newData = {
                    name: '',
                    minBet: '',
                    maxBet: '',
                    roundNumber: 0,
                    currentResult: '',
                    counters: { P: 0, B: 0, T: 0 },
                    additionalNumbers: [],
                    lastResults: [],
                    tableId: '',
                    rawText: text,
                    timestamp: Date.now()
                };

                // Parse each line
                for (let i = 0; i < lines.length; i++) {
                    const line = lines[i];
                    
                    // Table name (first line, usually contains "Baccarat")
                    if (i === 0 && line.includes('Baccarat')) {
                        newData.name = line;
                    }
                    
                    // Minimum bet (starts with $ but not -$)
                    else if (line.startsWith('$') && !line.startsWith('-$')) {
                        newData.minBet = line;
                    }
                    
                    // Maximum bet (starts with -$, remove the negative sign)
                    else if (line.startsWith('-$')) {
                        newData.maxBet = line.substring(1); // Remove the - sign
                    }
                    
                    // Round number (starts with #)
                    else if (line.startsWith('#')) {
                        newData.roundNumber = parseInt(line.substring(1)) || 0;
                    }
                    
                    // Current result (single letter P, B, or T)
                    else if (line.length === 1 && ['P', 'B', 'T'].includes(line)) {
                        newData.currentResult = line;
                    }
                    
                    // Counters (number following P, B, T)
                    else if (/^\d+$/.test(line)) {
                        const prevLine = lines[i-1];
                        if (prevLine === 'P') newData.counters.P = parseInt(line);
                        else if (prevLine === 'B') newData.counters.B = parseInt(line);
                        else if (prevLine === 'T') newData.counters.T = parseInt(line);
                        else newData.additionalNumbers.push(parseInt(line));
                    }
                    
                    // Last results (sequences of P, B, T)
                    else if (/^[PBT]+$/.test(line) && line.length > 1) {
                        newData.lastResults = line.split('');
                    }
                    
                    // Table ID (starts with ID:)
                    else if (line.startsWith('ID:')) {
                        newData.tableId = line;
                    }
                }

                return newData;
            } catch (error) {
                console.error(`[TableMonitor] Error parsing table ${this.id}:`, error);
                return null;
            }
        }

        update() {
            this.previousData = { ...this.data };
            const newData = this.parseTableData();
            
            if (newData) {
                this.data = newData;
                this.detectChanges();
                return true;
            }
            return false;
        }

        detectChanges() {
            const changes = [];
            
            // Round number change
            if (this.previousData.roundNumber && this.data.roundNumber !== this.previousData.roundNumber) {
                const diff = this.data.roundNumber - this.previousData.roundNumber;
                changes.push(`Round #${this.previousData.roundNumber} → #${this.data.roundNumber} (${diff > 0 ? '+' : ''}${diff})`);
            }
            
            // Counter changes
            ['P', 'B', 'T'].forEach(side => {
                if (this.previousData.counters && this.data.counters[side] !== this.previousData.counters[side]) {
                    const diff = this.data.counters[side] - (this.previousData.counters[side] || 0);
                    changes.push(`${side} ${this.previousData.counters[side] || 0} → ${this.data.counters[side]} (${diff > 0 ? '+' : ''}${diff})`);
                }
            });
            
            // Current result change
            if (this.previousData.currentResult && this.data.currentResult !== this.previousData.currentResult) {
                changes.push(`Result ${this.previousData.currentResult} → ${this.data.currentResult}`);
            }
            
            // Last results change
            if (this.previousData.lastResults && JSON.stringify(this.data.lastResults) !== JSON.stringify(this.previousData.lastResults)) {
                changes.push(`Results ${this.previousData.lastResults.join('')} → ${this.data.lastResults.join('')}`);
            }

            if (changes.length > 0 && CONFIG.DEBUG) {
                console.log(`[TableMonitor] ${this.data.name || `Table ${this.id}`}:`);
                changes.forEach(change => console.log(`  📊 ${change}`));
            }
        }

        getStatus() {
            return {
                id: this.id,
                name: this.data.name,
                round: this.data.roundNumber,
                result: this.data.currentResult,
                counters: this.data.counters,
                bettingLimits: `${this.data.minBet} - ${this.data.maxBet}`,
                tableId: this.data.tableId,
                lastUpdate: new Date(this.data.timestamp).toLocaleTimeString()
            };
        }
    }

    class TableMonitor {
        constructor() {
            this.tables = new Map();
            this.isRunning = false;
            this.intervalId = null;
        }

        findTables() {
            const tiles = document.querySelectorAll(CONFIG.TILE_SELECTOR);
            const currentTableIds = new Set();

            tiles.forEach((tile, index) => {
                const tableId = `table_${index}`;
                currentTableIds.add(tableId);

                if (!this.tables.has(tableId)) {
                    // New table found
                    const tableData = new TableData(tile, tableId);
                    tableData.update();
                    this.tables.set(tableId, tableData);
                    if (CONFIG.DEBUG) console.log(`[TableMonitor] New table detected: ${tableData.data.name || tableId}`);
                } else {
                    // Update existing table
                    const tableData = this.tables.get(tableId);
                    tableData.element = tile; // Update element reference
                    tableData.update();
                }
            });

            // Remove tables that no longer exist
            for (const [tableId, tableData] of this.tables) {
                if (!currentTableIds.has(tableId)) {
                    if (CONFIG.DEBUG) console.log(`[TableMonitor] Table removed: ${tableData.data.name || tableId}`);
                    this.tables.delete(tableId);
                }
            }

            return tiles.length;
        }

        start() {
            if (this.isRunning) return;

            if (CONFIG.DEBUG) console.log('[TableMonitor] Starting table monitoring...');
            this.isRunning = true;

            // Initial scan
            const tableCount = this.findTables();
            if (CONFIG.DEBUG) console.log(`[TableMonitor] Found ${tableCount} tables`);

            // Set up periodic monitoring
            this.intervalId = setInterval(() => {
                if (this.isRunning) {
                    this.findTables();
                }
            }, CONFIG.CHECK_INTERVAL);

            if (CONFIG.DEBUG) console.log(`[TableMonitor] Monitoring ${this.tables.size} tables every ${CONFIG.CHECK_INTERVAL}ms`);
        }

        stop() {
            if (!this.isRunning) return;

            if (CONFIG.DEBUG) console.log('[TableMonitor] Stopping table monitoring...');
            this.isRunning = false;

            if (this.intervalId) {
                clearInterval(this.intervalId);
                this.intervalId = null;
            }
        }

        getTableData(tableId) {
            const table = this.tables.get(tableId);
            return table ? table.data : null;
        }

        getAllTables() {
            const result = {};
            for (const [tableId, tableData] of this.tables) {
                result[tableId] = tableData.data;
            }
            return result;
        }

        getTableStatus() {
            const status = [];
            for (const [tableId, tableData] of this.tables) {
                status.push(tableData.getStatus());
            }
            return status;
        }

        printStatus() {
            console.log('\n[TableMonitor] Current Status:');
            const status = this.getTableStatus();
            status.forEach(table => {
                console.log(`📋 ${table.name}`);
                console.log(`   Round: #${table.round} | Result: ${table.result} | P:${table.counters.P} B:${table.counters.B} T:${table.counters.T}`);
                console.log(`   Betting Limits: ${table.bettingLimits} | ${table.tableId} | Updated: ${table.lastUpdate}`);
            });
        }
    }

    // Initialize the monitor
    const monitor = new TableMonitor();

    // Start monitoring after DOM is ready
    setTimeout(() => {
        monitor.start();
        if (CONFIG.DEBUG) console.log('[TableMonitor] table checker v1.0 initialized');
    }, 2000);

    // Global API
    window.tableMonitor = {
        start: () => monitor.start(),
        stop: () => monitor.stop(),
        status: () => monitor.printStatus(),
        getTables: () => monitor.getAllTables(),
        getTable: (id) => monitor.getTableData(id),
        count: () => monitor.tables.size,
        list: () => {
            console.log('Available tables:');
            monitor.tables.forEach((table, id) => {
                console.log(`${id}: ${table.data.name || 'Unknown'} - Round #${table.data.roundNumber}`);
            });
        },
        toggleLogging: () => {
            CONFIG.DEBUG = !CONFIG.DEBUG;
            console.log(`[TableMonitor] Logging ${CONFIG.DEBUG ? 'enabled' : 'disabled'}`);
        },
        getEle: (id) => {
            const table = monitor.tables.get(id);
            return table ? table.element : null;
        }
    };

    if (CONFIG.DEBUG) {
        console.log('[TableMonitor] API available: window.tableMonitor');
        console.log('Commands: start(), stop(), status(), getTables(), getEle(id), list(), count(), toggleLogging()');
    }

})();
