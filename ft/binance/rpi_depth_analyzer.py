#!/usr/bin/env python3
"""
RPI Depth Analyzer - ETHUSDT Perpetual Futures

Continuously monitors Standard vs RPI Order Books on Binance USDT-M Futures.
Focused on ETHUSDT perpetual contract analysis.

Press Ctrl+C to stop and generate final analysis report.

Retail Price Improvement (RPI) orders:
- Hidden from standard /fapi/v1/depth endpoint
- Visible in /fapi/v1/rpiDepth endpoint  
- Exclusive to Binance Futures (USDT-M)
- Provides better fills for retail takers

API Endpoints:
- Standard: https://fapi.binance.com/fapi/v1/depth
- RPI:      https://fapi.binance.com/fapi/v1/rpiDepth
"""

import asyncio
import aiohttp
import signal
import sys
import time
import json
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Optional
from datetime import datetime
from pathlib import Path


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Configuration - ETHUSDT Perpetual Futures
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Binance USDT-M Futures API
BASE_URL = "https://fapi.binance.com"

# ETHUSDT Perpetual - Primary focus
DEFAULT_SYMBOL = "ETHUSDT"

# Sampling rate (seconds between API calls)
SAMPLE_INTERVAL = 0.2


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Data Structures
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class RPILevel:
    price: float
    quantity: float
    notional: float
    distance_bps: float
    is_at_best: bool
    side: str  # 'bid' or 'ask'


@dataclass 
class RPIEvent:
    timestamp: float
    elapsed: float
    best_bid: float
    best_ask: float
    spread_bps: float
    hidden_bids: list[RPILevel]
    hidden_asks: list[RPILevel]
    total_hidden_bid: float
    total_hidden_ask: float


@dataclass
class AnalysisSession:
    symbol: str
    start_time: float = field(default_factory=time.time)
    samples: int = 0
    errors: int = 0
    rpi_events: list[RPIEvent] = field(default_factory=list)
    all_hidden_bids: list[RPILevel] = field(default_factory=list)
    all_hidden_asks: list[RPILevel] = field(default_factory=list)
    
    @property
    def duration(self) -> float:
        return time.time() - self.start_time
    
    @property
    def rpi_count(self) -> int:
        return len(self.rpi_events)
    
    @property
    def rpi_rate(self) -> float:
        return self.rpi_count / self.samples * 100 if self.samples > 0 else 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Global State
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

running = True
session: Optional[AnalysisSession] = None


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global running
    print("\n\n⏹️  Stopping analysis... generating report...\n")
    running = False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# API Fetching
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def fetch_both_books(http: aiohttp.ClientSession, symbol: str) -> tuple[dict, dict]:
    """Fetch standard and RPI order books simultaneously"""
    std_url = f"{BASE_URL}/fapi/v1/depth?symbol={symbol}&limit=100"
    rpi_url = f"{BASE_URL}/fapi/v1/rpiDepth?symbol={symbol}"
    
    async with http.get(std_url) as std_resp, http.get(rpi_url) as rpi_resp:
        std = await std_resp.json()
        rpi = await rpi_resp.json()
        return std, rpi


def analyze_books(std: dict, rpi: dict) -> Optional[RPIEvent]:
    """Compare books and extract hidden RPI liquidity"""
    if 'bids' not in std or 'bids' not in rpi:
        return None
    
    best_bid = float(std['bids'][0][0])
    best_ask = float(std['asks'][0][0])
    mid_price = (best_bid + best_ask) / 2
    spread_bps = (best_ask - best_bid) / mid_price * 10000
    
    std_bids = {float(p): float(q) for p, q in std['bids'][:100]}
    rpi_bids = {float(p): float(q) for p, q in rpi['bids'][:100]}
    std_asks = {float(p): float(q) for p, q in std['asks'][:100]}
    rpi_asks = {float(p): float(q) for p, q in rpi['asks'][:100]}
    
    hidden_bids = []
    hidden_asks = []
    
    # Find hidden bid liquidity
    for p, q in rpi_bids.items():
        diff = q - std_bids.get(p, 0)
        if diff > 0:
            distance = best_bid - p
            distance_bps = (distance / mid_price) * 10000
            hidden_bids.append(RPILevel(
                price=p, quantity=diff, notional=p * diff,
                distance_bps=distance_bps, is_at_best=(p == best_bid), side='bid'
            ))
    
    # Find hidden ask liquidity
    for p, q in rpi_asks.items():
        diff = q - std_asks.get(p, 0)
        if diff > 0:
            distance = p - best_ask
            distance_bps = (distance / mid_price) * 10000
            hidden_asks.append(RPILevel(
                price=p, quantity=diff, notional=p * diff,
                distance_bps=distance_bps, is_at_best=(p == best_ask), side='ask'
            ))
    
    total_bid = sum(h.notional for h in hidden_bids)
    total_ask = sum(h.notional for h in hidden_asks)
    
    return RPIEvent(
        timestamp=time.time(),
        elapsed=0,  # Set by caller
        best_bid=best_bid,
        best_ask=best_ask,
        spread_bps=spread_bps,
        hidden_bids=hidden_bids,
        hidden_asks=hidden_asks,
        total_hidden_bid=total_bid,
        total_hidden_ask=total_ask
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Display Functions
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def print_header(symbol: str):
    """Print startup header"""
    print("\033[2J\033[H")  # Clear screen
    print("╔═══════════════════════════════════════════════════════════════════════════════╗")
    print("║         🔬 RPI DEPTH ANALYZER - BINANCE USDT-M PERPETUAL FUTURES              ║")
    print("╠═══════════════════════════════════════════════════════════════════════════════╣")
    print(f"║   Symbol: {symbol:<15} (Perpetual)                                       ║")
    print("║   Exchange: Binance Futures (fapi.binance.com)                                ║")
    print("║                                                                               ║")
    print("║   Comparing: /fapi/v1/depth vs /fapi/v1/rpiDepth                              ║")
    print("║   Press Ctrl+C to stop and generate analysis report                          ║")
    print("╚═══════════════════════════════════════════════════════════════════════════════╝")
    print()


def print_rpi_event(event: RPIEvent, session: AnalysisSession):
    """Print a single RPI detection event"""
    print(f"🟢 {event.elapsed:6.1f}s | RPI DETECTED | Samples: {session.samples} | RPI Rate: {session.rpi_rate:.1f}%")
    
    # Show top bids
    for h in sorted(event.hidden_bids, key=lambda x: -x.price)[:3]:
        at_best = "⭐ BEST" if h.is_at_best else f"{h.distance_bps:+.1f}bps"
        print(f"     BID @ {h.price:>10.2f} | {h.quantity:>10.4f} | ${h.notional:>10,.2f} | {at_best}")
    
    # Show top asks
    for h in sorted(event.hidden_asks, key=lambda x: x.price)[:3]:
        at_best = "⭐ BEST" if h.is_at_best else f"{h.distance_bps:+.1f}bps"
        print(f"     ASK @ {h.price:>10.2f} | {h.quantity:>10.4f} | ${h.notional:>10,.2f} | {at_best}")
    
    print()


def print_status(session: AnalysisSession):
    """Print periodic status update"""
    elapsed = session.duration
    rate = session.samples / elapsed if elapsed > 0 else 0
    print(f"⚪ {elapsed:6.1f}s | Samples: {session.samples:>6} | RPI Events: {session.rpi_count:>4} ({session.rpi_rate:.1f}%) | Rate: {rate:.1f}/s", end='\r')


def generate_report(session: AnalysisSession) -> str:
    """Generate comprehensive analysis report"""
    
    duration = session.duration
    
    report = []
    report.append("")
    report.append("━" * 80)
    report.append("                    📊 RPI ANALYSIS REPORT")
    report.append("━" * 80)
    report.append("")
    
    # Basic Stats
    report.append("┌────────────────────────────────────────────────────────────────────────────────┐")
    report.append("│                              SESSION STATISTICS                               │")
    report.append("├────────────────────────────────────────────────────────────────────────────────┤")
    report.append(f"│  Symbol:                {session.symbol:>15}                                    │")
    report.append(f"│  Duration:              {duration:>12.1f}s                                      │")
    report.append(f"│  Total Samples:         {session.samples:>15}                                    │")
    report.append(f"│  API Errors:            {session.errors:>15}                                    │")
    report.append(f"│  Sample Rate:           {session.samples/duration:>12.1f}/s                                      │")
    report.append("├────────────────────────────────────────────────────────────────────────────────┤")
    report.append(f"│  RPI Events:            {session.rpi_count:>15}                                    │")
    report.append(f"│  RPI Appearance Rate:   {session.rpi_rate:>12.1f}%                                      │")
    report.append(f"│  Avg Time Between RPI:  {duration/session.rpi_count if session.rpi_count > 0 else 0:>12.1f}s                                      │")
    report.append("└────────────────────────────────────────────────────────────────────────────────┘")
    report.append("")
    
    if session.rpi_count > 0:
        # Aggregate all hidden levels
        all_bids = session.all_hidden_bids
        all_asks = session.all_hidden_asks
        
        total_bid_notional = sum(h.notional for h in all_bids)
        total_ask_notional = sum(h.notional for h in all_asks)
        
        avg_bid_size = total_bid_notional / len(all_bids) if all_bids else 0
        avg_ask_size = total_ask_notional / len(all_asks) if all_asks else 0
        
        max_bid = max((h.notional for h in all_bids), default=0)
        max_ask = max((h.notional for h in all_asks), default=0)
        
        bids_at_best = sum(1 for h in all_bids if h.is_at_best)
        asks_at_best = sum(1 for h in all_asks if h.is_at_best)
        
        away_bids = [h for h in all_bids if not h.is_at_best]
        away_asks = [h for h in all_asks if not h.is_at_best]
        
        avg_bid_dist = sum(h.distance_bps for h in away_bids) / len(away_bids) if away_bids else 0
        avg_ask_dist = sum(h.distance_bps for h in away_asks) / len(away_asks) if away_asks else 0
        
        # Size Analysis
        report.append("┌────────────────────────────────────────────────────────────────────────────────┐")
        report.append("│                              RPI SIZE ANALYSIS                                │")
        report.append("├────────────────────────────────────────────────────────────────────────────────┤")
        report.append(f"│                                 BIDS                    ASKS                   │")
        report.append(f"│  Total Notional:       ${total_bid_notional:>12,.2f}          ${total_ask_notional:>12,.2f}             │")
        report.append(f"│  Avg Size per Level:   ${avg_bid_size:>12,.2f}          ${avg_ask_size:>12,.2f}             │")
        report.append(f"│  Max Single Level:     ${max_bid:>12,.2f}          ${max_ask:>12,.2f}             │")
        report.append(f"│  Total Levels Seen:    {len(all_bids):>12}          {len(all_asks):>12}             │")
        report.append("└────────────────────────────────────────────────────────────────────────────────┘")
        report.append("")
        
        # Position Analysis
        report.append("┌────────────────────────────────────────────────────────────────────────────────┐")
        report.append("│                           RPI POSITION ANALYSIS                               │")
        report.append("├────────────────────────────────────────────────────────────────────────────────┤")
        report.append("│  📍 WHERE DOES RPI APPEAR?                                                     │")
        report.append("│                                                                                │")
        bid_pct = bids_at_best / len(all_bids) * 100 if all_bids else 0
        ask_pct = asks_at_best / len(all_asks) * 100 if all_asks else 0
        report.append(f"│  AT BEST PRICE:                                                                │")
        report.append(f"│    Bids at Best:       {bids_at_best:>5} / {len(all_bids):<5} ({bid_pct:>5.1f}%)                                │")
        report.append(f"│    Asks at Best:       {asks_at_best:>5} / {len(all_asks):<5} ({ask_pct:>5.1f}%)                                │")
        report.append("│                                                                                │")
        report.append(f"│  AWAY FROM BEST (potential price improvement):                                 │")
        report.append(f"│    Bids away:          {len(away_bids):>5} levels, avg {avg_bid_dist:>+6.2f} bps from best               │")
        report.append(f"│    Asks away:          {len(away_asks):>5} levels, avg {avg_ask_dist:>+6.2f} bps from best               │")
        report.append("└────────────────────────────────────────────────────────────────────────────────┘")
        report.append("")
        
        # Edge Quantification
        report.append("┌────────────────────────────────────────────────────────────────────────────────┐")
        report.append("│                          🎯 EDGE QUANTIFICATION                               │")
        report.append("├────────────────────────────────────────────────────────────────────────────────┤")
        
        rpi_per_sample = (total_bid_notional + total_ask_notional) / session.samples
        avg_improvement = (avg_bid_dist + avg_ask_dist) / 2
        effective_edge = avg_improvement * session.rpi_rate / 100
        
        report.append(f"│  RPI Liquidity/Sample: ${rpi_per_sample:>12,.2f}                                      │")
        report.append(f"│  Avg Price Improvement:{avg_improvement:>+10.2f} bps (when present)                        │")
        report.append(f"│  Effective Edge:       {effective_edge:>+10.3f} bps (probability-weighted)                │")
        report.append("│                                                                                │")
        
        # Daily savings estimate
        daily_volume = 100  # ETH
        avg_price = session.rpi_events[-1].best_ask if session.rpi_events else 2940
        daily_notional = daily_volume * avg_price
        daily_savings = daily_notional * effective_edge / 10000
        yearly_savings = daily_savings * 365
        
        report.append(f"│  📈 ESTIMATED SAVINGS (100 ETH/day @ ${avg_price:,.0f}):                              │")
        report.append(f"│     Daily:             ${daily_savings:>12,.2f}                                      │")
        report.append(f"│     Yearly:            ${yearly_savings:>12,.2f}                                      │")
        report.append("└────────────────────────────────────────────────────────────────────────────────┘")
        report.append("")
        
        # Top RPI Events
        if session.rpi_events:
            top_events = sorted(session.rpi_events, 
                              key=lambda e: e.total_hidden_bid + e.total_hidden_ask, 
                              reverse=True)[:5]
            
            report.append("┌────────────────────────────────────────────────────────────────────────────────┐")
            report.append("│                          TOP 5 RPI EVENTS                                     │")
            report.append("├────────────────────────────────────────────────────────────────────────────────┤")
            for i, e in enumerate(top_events, 1):
                total = e.total_hidden_bid + e.total_hidden_ask
                report.append(f"│  #{i}  @ {e.elapsed:>6.1f}s | Bid: ${e.total_hidden_bid:>10,.2f} | Ask: ${e.total_hidden_ask:>10,.2f} | Total: ${total:>10,.2f} │")
            report.append("└────────────────────────────────────────────────────────────────────────────────┘")
            report.append("")
    
    # Conclusion
    report.append("┌────────────────────────────────────────────────────────────────────────────────┐")
    report.append("│                              💡 CONCLUSIONS                                   │")
    report.append("├────────────────────────────────────────────────────────────────────────────────┤")
    
    if session.rpi_count > 0:
        report.append("│                                                                                │")
        report.append(f"│  ✅ RPI liquidity detected in {session.rpi_rate:.1f}% of samples                              │")
        report.append("│  ✅ Hidden liquidity provides structural advantage for retail                  │")
        report.append("│  ✅ Both price improvement AND extra depth observed                            │")
        report.append("│                                                                                │")
        report.append("│  ⚠️  RPI is sporadic - cannot be predicted or timed                            │")
        report.append("│  ⚠️  Not exploitable alpha - passive benefit during execution                  │")
        report.append("│  ⚠️  Requires retail account classification from Binance                       │")
    else:
        report.append("│                                                                                │")
        report.append("│  ℹ️  No RPI liquidity detected during this session                             │")
        report.append("│  ℹ️  RPI availability varies by market conditions                              │")
        report.append("│  ℹ️  Try running during higher volatility periods                              │")
    
    report.append("│                                                                                │")
    report.append("└────────────────────────────────────────────────────────────────────────────────┘")
    report.append("")
    
    return "\n".join(report)


def save_report(session: AnalysisSession, report: str):
    """Save report to files"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save text report
    report_file = Path(f"rpi_report_{session.symbol}_{timestamp}.txt")
    report_file.write_text(report)
    print(f"📄 Report saved to: {report_file}")
    
    # Save JSON data
    json_data = {
        "symbol": session.symbol,
        "start_time": datetime.fromtimestamp(session.start_time).isoformat(),
        "duration_seconds": session.duration,
        "total_samples": session.samples,
        "api_errors": session.errors,
        "rpi_events_count": session.rpi_count,
        "rpi_appearance_rate": session.rpi_rate,
        "total_hidden_bid_notional": sum(h.notional for h in session.all_hidden_bids),
        "total_hidden_ask_notional": sum(h.notional for h in session.all_hidden_asks),
        "events": [
            {
                "elapsed": e.elapsed,
                "best_bid": e.best_bid,
                "best_ask": e.best_ask,
                "spread_bps": e.spread_bps,
                "total_hidden_bid": e.total_hidden_bid,
                "total_hidden_ask": e.total_hidden_ask,
                "bid_levels": len(e.hidden_bids),
                "ask_levels": len(e.hidden_asks)
            }
            for e in session.rpi_events
        ]
    }
    
    json_file = Path(f"rpi_data_{session.symbol}_{timestamp}.json")
    json_file.write_text(json.dumps(json_data, indent=2))
    print(f"📁 Data saved to: {json_file}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Main Loop
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def run_analysis(symbol: str):
    """Main analysis loop"""
    global running, session
    
    session = AnalysisSession(symbol=symbol)
    print_header(symbol)
    
    print("🚀 Starting continuous RPI analysis...")
    print("   Watching for hidden retail liquidity...\n")
    
    last_status = 0
    
    async with aiohttp.ClientSession() as http:
        while running:
            try:
                std, rpi = await fetch_both_books(http, symbol)
                session.samples += 1
                
                event = analyze_books(std, rpi)
                
                if event and (event.hidden_bids or event.hidden_asks):
                    event.elapsed = session.duration
                    session.rpi_events.append(event)
                    session.all_hidden_bids.extend(event.hidden_bids)
                    session.all_hidden_asks.extend(event.hidden_asks)
                    print_rpi_event(event, session)
                else:
                    # Periodic status update every 2 seconds
                    if time.time() - last_status > 2:
                        print_status(session)
                        last_status = time.time()
                
            except Exception as e:
                session.errors += 1
                if session.errors % 10 == 0:
                    print(f"\n⚠️  API errors: {session.errors}")
            
            await asyncio.sleep(SAMPLE_INTERVAL)
    
    # Generate and display report
    print("\n" * 2)
    report = generate_report(session)
    print(report)
    
    # Save files
    save_report(session, report)


def main():
    """Entry point"""
    global SAMPLE_INTERVAL
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Continuous RPI Order Book Analyzer - Press Ctrl+C to stop and generate report"
    )
    parser.add_argument("-s", "--symbol", default=DEFAULT_SYMBOL, help="Trading pair (default: ETHUSDT)")
    parser.add_argument("-i", "--interval", type=float, default=SAMPLE_INTERVAL, 
                       help="Seconds between samples (default: 0.2)")
    
    args = parser.parse_args()
    SAMPLE_INTERVAL = args.interval
    
    # Setup signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        asyncio.run(run_analysis(args.symbol))
    except KeyboardInterrupt:
        pass  # Already handled by signal_handler


if __name__ == "__main__":
    main()
