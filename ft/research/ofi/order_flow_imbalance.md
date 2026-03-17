# Order Flow Imbalance (OFI)

The "gold standard" for 5s trading. Instead of looking at price, analyze the **Limit Order Book (LOB)**.

## Logic

Track the rate of change between Buy and Sell liquidity:
- If the "bid" side is being replenished faster than it's being hit
- While the "ask" side is thinning
- A price move upward is statistically imminent within the next few seconds

## Key Metric: Volume Delta

Look for "Aggressive" market orders (tape) hitting "Passive" limit orders.

A large positive delta at a specific price level often acts as a short-term floor.
