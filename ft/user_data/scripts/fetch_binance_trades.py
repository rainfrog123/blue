#!/usr/bin/env python3
"""
Script to fetch trades from Binance API and aggregate them into 5-second candles.
Stores the result in parquet files that can be loaded by Freqtrade.
"""
import os
import sys
import time
import logging
import argparse
import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

import numpy as np
import pandas as pd
import ccxt
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

# Constants
TIMEFRAME = "5s"
EXCHANGE_NAME = "binance"
BASE_DATA_DIR = Path("/allah/stuff/freq/project_2/user_data/data")
TEMP_DIR = Path("/allah/stuff/freq/project_2/user_data/data/temp")

# Ensure directories exist
TEMP_DIR.mkdir(parents=True, exist_ok=True)

class BinanceTradesFetcher:
    """Class to fetch trades from Binance and convert them to 5s candles."""
    
    def __init__(self, exchange_name: str = EXCHANGE_NAME):
        """Initialize the fetcher with the exchange."""
        self.exchange_name = exchange_name
        self.exchange = self._init_exchange()
        logger.info(f"Initialized {exchange_name} exchange connection")
    
    def _init_exchange(self) -> ccxt.Exchange:
        """Initialize the CCXT exchange object."""
        exchange_class = getattr(ccxt, self.exchange_name)
        exchange = exchange_class({
            'enableRateLimit': True,
            'options': {
                'defaultType': 'future',  # Use futures API for Binance
            }
        })
        return exchange
    
    def fetch_trades(self, symbol: str, start_time: int, end_time: int) -> List[Dict]:
        """
        Fetch all trades for a symbol between start_time and end_time.
        
        Args:
            symbol: Trading pair symbol (e.g., 'ETH/USDT:USDT')
            start_time: Start timestamp in milliseconds
            end_time: End timestamp in milliseconds
            
        Returns:
            List of trade dictionaries
        """
        logger.info(f"Fetching trades for {symbol} from {datetime.datetime.fromtimestamp(start_time/1000)} "
                    f"to {datetime.datetime.fromtimestamp(end_time/1000)}")
        
        all_trades = []
        current_since = start_time
        
        with tqdm(total=(end_time - start_time)/1000, unit='s') as pbar:
            while current_since < end_time:
                try:
                    # Fetch trades starting from current_since
                    trades_batch = self.exchange.fetch_trades(
                        symbol=symbol,
                        since=current_since,
                        limit=1000,  # Maximum allowed by Binance
                    )
                    
                    if not trades_batch:
                        # No more trades
                        logger.info(f"No more trades found after {datetime.datetime.fromtimestamp(current_since/1000)}")
                        break
                    
                    # Add the new trades to our list
                    all_trades.extend(trades_batch)
                    
                    # Update the starting point for the next batch
                    last_trade_timestamp = trades_batch[-1]['timestamp']
                    
                    # Update progress bar based on data fetched
                    progress = min(last_trade_timestamp, end_time) - current_since
                    pbar.update(progress/1000)
                    
                    # Move to the next batch (add 1ms to avoid duplicating the last trade)
                    current_since = last_trade_timestamp + 1
                    
                    # If we've reached or passed the end time, we're done
                    if current_since >= end_time:
                        break
                    
                    # Respect rate limits
                    time.sleep(self.exchange.rateLimit / 1000)
                    
                except Exception as e:
                    logger.error(f"Error fetching trades: {str(e)}")
                    # Wait a bit longer on error
                    time.sleep(10)
        
        # Filter out any trades beyond our end time
        all_trades = [t for t in all_trades if t['timestamp'] <= end_time]
        
        logger.info(f"Fetched {len(all_trades)} trades for {symbol}")
        return all_trades
    
    def trades_to_dataframe(self, trades: List[Dict]) -> pd.DataFrame:
        """
        Convert a list of trades to a DataFrame.
        
        Args:
            trades: List of trade dictionaries from CCXT
            
        Returns:
            DataFrame with trade data
        """
        if not trades:
            logger.warning("No trades to convert to DataFrame")
            return pd.DataFrame()
        
        # Extract the fields we need
        df = pd.DataFrame([
            {
                'timestamp': trade['timestamp'],
                'price': float(trade['price']),
                'amount': float(trade['amount']),
                'side': 1 if trade['side'] == 'buy' else -1,  # 1 for buy, -1 for sell
                'cost': float(trade['cost']),
            }
            for trade in trades
        ])
        
        # Convert timestamp to datetime and set as index
        df['datetime'] = pd.to_datetime(df['timestamp'], unit='ms')
        return df
    
    def aggregate_to_candles(self, trades_df: pd.DataFrame, timeframe: str = TIMEFRAME) -> pd.DataFrame:
        """
        Aggregate trades into OHLCV candles.
        
        Args:
            trades_df: DataFrame of trades
            timeframe: Candle timeframe (e.g., '5s' for 5 seconds)
            
        Returns:
            DataFrame of OHLCV candles
        """
        if trades_df.empty:
            logger.warning("No trades to aggregate into candles")
            return pd.DataFrame(columns=['date', 'open', 'high', 'low', 'close', 'volume'])
        
        # Group by time interval and calculate OHLCV
        candles = trades_df.set_index('datetime').resample(timeframe).agg({
            'price': ['first', 'max', 'min', 'last'],
            'amount': 'sum',
            'cost': 'sum',
            'timestamp': 'first'
        })
        
        # Flatten column names and rename
        candles.columns = ['_'.join(col).strip() for col in candles.columns.values]
        candles = candles.rename(columns={
            'price_first': 'open',
            'price_max': 'high',
            'price_min': 'low',
            'price_last': 'close',
            'amount_sum': 'volume',
            'cost_sum': 'quote_volume',
            'timestamp_first': 'timestamp'
        })
        
        # Reset index to get datetime as a column
        candles = candles.reset_index()
        
        # Convert datetime to millisecond timestamp for Freqtrade compatibility
        candles['date'] = candles['datetime'].astype(np.int64) // 10**6
        
        # Select and order columns for Freqtrade compatibility
        result = candles[['date', 'open', 'high', 'low', 'close', 'volume', 'quote_volume']]
        
        # Forward fill any missing values (important for continuous data)
        result = result.ffill()
        
        logger.info(f"Aggregated {len(trades_df)} trades into {len(result)} {timeframe} candles")
        return result
    
    def fetch_and_aggregate(self, symbol: str, start_time: int, end_time: int, 
                           timeframe: str = TIMEFRAME) -> pd.DataFrame:
        """
        Fetch trades and aggregate them into candles in one operation.
        
        Args:
            symbol: Trading pair symbol (e.g., 'ETH/USDT:USDT')
            start_time: Start timestamp in milliseconds
            end_time: End timestamp in milliseconds
            timeframe: Candle timeframe
            
        Returns:
            DataFrame of OHLCV candles
        """
        # Fetch trades
        trades = self.fetch_trades(symbol, start_time, end_time)
        
        # Convert to DataFrame
        trades_df = self.trades_to_dataframe(trades)
        
        # Aggregate to candles
        candles_df = self.aggregate_to_candles(trades_df, timeframe)
        
        return candles_df
    
    def save_candles(self, candles_df: pd.DataFrame, symbol: str, timeframe: str = TIMEFRAME) -> Path:
        """
        Save candles to a parquet file in Freqtrade format.
        
        Args:
            candles_df: DataFrame of candles
            symbol: Trading pair symbol
            timeframe: Candle timeframe
            
        Returns:
            Path to the saved file
        """
        if candles_df.empty:
            logger.warning(f"No candles to save for {symbol}")
            return None
        
        # Normalize symbol for filename
        symbol_filename = symbol.replace('/', '-').replace(':', '')
        
        # Create directory structure
        pair_dir = BASE_DATA_DIR / self.exchange_name / timeframe
        pair_dir.mkdir(parents=True, exist_ok=True)
        
        # Define file path
        file_path = pair_dir / f"{symbol_filename}.parquet"
        
        # Save to parquet
        candles_df.to_parquet(file_path, index=False)
        
        logger.info(f"Saved {len(candles_df)} candles to {file_path}")
        return file_path

def timestamp_from_days_ago(days: int) -> int:
    """
    Get a timestamp in milliseconds from N days ago.
    
    Args:
        days: Number of days ago
        
    Returns:
        Timestamp in milliseconds
    """
    now = datetime.datetime.now()
    days_ago = now - datetime.timedelta(days=days)
    return int(days_ago.timestamp() * 1000)

def main():
    parser = argparse.ArgumentParser(description='Fetch trades from Binance and convert to 5s candles')
    parser.add_argument('--pairs', type=str, nargs='+', default=["ETH/USDT:USDT"],
                        help='Trading pairs to fetch (e.g. ETH/USDT:USDT)')
    parser.add_argument('--days', type=int, default=1,
                        help='Number of days of data to fetch')
    parser.add_argument('--timeframe', type=str, default=TIMEFRAME,
                        help=f'Candle timeframe (default: {TIMEFRAME})')
    
    args = parser.parse_args()
    
    # Calculate time range
    end_time = int(time.time() * 1000)  # Now in milliseconds
    start_time = timestamp_from_days_ago(args.days)
    
    logger.info(f"Fetching {args.days} days of data for {', '.join(args.pairs)}")
    logger.info(f"Time range: {datetime.datetime.fromtimestamp(start_time/1000)} to "
                f"{datetime.datetime.fromtimestamp(end_time/1000)}")
    
    # Initialize fetcher
    fetcher = BinanceTradesFetcher()
    
    # Process each pair
    for symbol in args.pairs:
        try:
            # Fetch and aggregate data
            candles_df = fetcher.fetch_and_aggregate(symbol, start_time, end_time, args.timeframe)
            
            if not candles_df.empty:
                # Save data
                file_path = fetcher.save_candles(candles_df, symbol, args.timeframe)
                if file_path:
                    logger.info(f"Successfully processed {symbol}: {len(candles_df)} candles saved to {file_path}")
            else:
                logger.warning(f"No data processed for {symbol}")
        
        except Exception as e:
            logger.error(f"Error processing {symbol}: {str(e)}")
    
    logger.info("Finished processing all pairs")
    return 0

if __name__ == "__main__":
    sys.exit(main()) 