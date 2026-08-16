# Execution Factors

Infrastructure is as important as the math.

## Fee Optimization

On 5s, you might trade hundreds of times a day.

If you aren't a "VIP" or using a "Maker" rebate, trading fees will eat 100% of your alpha.

## Latency

- Use **WebSockets** (not REST APIs)
- Host your bot in the same AWS/Google Cloud region as the exchange's matching engine
- Usually Tokyo or Ireland for crypto

## Slippage Control

At the 5s level, "Market" orders are dangerous.

Use **FOK (Fill-or-Kill)** or **IOC (Immediate-or-Cancel)** limit orders to ensure you don't get filled at a "bad" price.
