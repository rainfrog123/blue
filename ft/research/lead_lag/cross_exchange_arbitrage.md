# Cross-Exchange Lead-Lag (Arbitrage-Lite)

ETH is traded across dozens of venues (Binance, Bybit, OKX, and decentralized perps like Hyperliquid).

## Logic

Large institutional "parent" orders often hit one major exchange (usually Binance) first.

The price move on a smaller exchange may lag by **500ms to 2 seconds**.

## The Play

1. Monitor the **Binance ETH-PERP** (Leader)
2. Execute trades on a secondary exchange (Follower)
3. Trigger the moment a significant liquidity sweep is detected on the leader
