#!/usr/bin/env python3
"""Transfer funds from Binance Funding account to Futures account."""

import sys
from pathlib import Path
# Add cred_loader to path (binance -> misc -> freq -> blue -> linux/extra)
sys.path.insert(0, str(Path(__file__).parents[3] / "linux" / "extra"))

import ccxt
from cred_loader import get_binance

# Load Binance API credentials from secure file
_binance = get_binance()
API_KEY = _binance["api_key"]
API_SECRET = _binance["api_secret"]

# Transfer settings
CURRENCY = "USDT"
AMOUNT = 0.01
FROM_ACCOUNT = "funding"
TO_ACCOUNT = "future"


def main():
    # Initialize Binance
    binance = ccxt.binance({
        'apiKey': API_KEY,
        'secret': API_SECRET,
    })

    print(f"Transferring {AMOUNT} {CURRENCY} from {FROM_ACCOUNT} to {TO_ACCOUNT}...")

    # Check balances before transfer
    try:
        funding_balance = binance.fetch_balance({'type': 'funding'})
        futures_balance = binance.fetch_balance({'type': 'future'})
        
        funding_free = funding_balance.get(CURRENCY, {}).get('free', 0)
        futures_free = futures_balance.get(CURRENCY, {}).get('free', 0)
        
        print(f"\n=== Before Transfer ===")
        print(f"Funding {CURRENCY}: {funding_free}")
        print(f"Futures {CURRENCY}: {futures_free}")
    except Exception as e:
        print(f"Warning: Could not fetch balances: {e}")

    # Perform the transfer
    try:
        result = binance.transfer(
            code=CURRENCY,
            amount=AMOUNT,
            fromAccount=FROM_ACCOUNT,
            toAccount=TO_ACCOUNT,
        )
        print(f"\n✅ Transfer successful!")
        print(f"Transaction ID: {result.get('id', 'N/A')}")
        print(f"Result: {result}")
    except ccxt.InsufficientFunds as e:
        print(f"\n❌ Insufficient funds in {FROM_ACCOUNT} account: {e}")
    except ccxt.ExchangeError as e:
        print(f"\n❌ Exchange error: {e}")
    except Exception as e:
        print(f"\n❌ Error: {e}")

    # Check balances after transfer
    try:
        funding_balance = binance.fetch_balance({'type': 'funding'})
        futures_balance = binance.fetch_balance({'type': 'future'})
        
        funding_free = funding_balance.get(CURRENCY, {}).get('free', 0)
        futures_free = futures_balance.get(CURRENCY, {}).get('free', 0)
        
        print(f"\n=== After Transfer ===")
        print(f"Funding {CURRENCY}: {funding_free}")
        print(f"Futures {CURRENCY}: {futures_free}")
    except Exception as e:
        print(f"Warning: Could not fetch balances: {e}")


if __name__ == "__main__":
    main()

