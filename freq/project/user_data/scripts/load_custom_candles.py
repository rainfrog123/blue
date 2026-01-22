#!/usr/bin/env python3
"""
Script to load custom candles from parquet files and display them.
This script is designed to work with the output of fetch_binance_trades.py.
"""
import os
import sys
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Union

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.ticker import FuncFormatter

# Add the parent directory to sys.path
sys.path.append(str(Path(__file__).parents[3]))

# Import freqtrade modules
from freqtrade.data.history.history_utils import pair_to_filename
from freqtrade.data.converter import convert_ohlcv_format

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_EXCHANGE = "binance"
DEFAULT_TIMEFRAME = "5s"
BASE_DATA_DIR = Path("/allah/stuff/freq/project_2/user_data/data")

class CustomCandleLoader:
    """Class to load and display custom candles from parquet files."""
    
    def __init__(self, exchange_name: str = DEFAULT_EXCHANGE, timeframe: str = DEFAULT_TIMEFRAME):
        """Initialize the loader with exchange and timeframe."""
        self.exchange_name = exchange_name
        self.timeframe = timeframe
        self.data_dir = BASE_DATA_DIR / exchange_name / timeframe
        
        if not self.data_dir.exists():
            logger.warning(f"Data directory {self.data_dir} does not exist. No candles available.")
    
    def list_available_pairs(self) -> List[str]:
        """List all available trading pairs with data."""
        if not self.data_dir.exists():
            return []
        
        # Get all parquet files
        parquet_files = list(self.data_dir.glob("*.parquet"))
        
        # Convert filenames to pair format
        pairs = []
        for file_path in parquet_files:
            filename = file_path.stem
            # Convert filename format (ETH-USDT) to pair format (ETH/USDT)
            if '-' in filename:
                # Handle futures pairs like ETH-USDT-USDT
                parts = filename.split('-')
                if len(parts) == 3 and parts[1] == parts[2]:
                    # This is a futures pair like ETH-USDT-USDT
                    pair = f"{parts[0]}/{parts[1]}:{parts[2]}"
                else:
                    # Regular pair
                    pair = filename.replace('-', '/')
                pairs.append(pair)
        
        return pairs
    
    def get_pair_data_path(self, pair: str) -> Optional[Path]:
        """Get the path to the parquet file for a specific pair."""
        if not self.data_dir.exists():
            return None
        
        # Convert pair to filename format
        filename = pair.replace('/', '-').replace(':', '')
        file_path = self.data_dir / f"{filename}.parquet"
        
        if file_path.exists():
            return file_path
        
        logger.warning(f"No data file found for {pair} at {file_path}")
        return None
    
    def load_pair_data(self, pair: str) -> Optional[pd.DataFrame]:
        """Load candle data for a specific pair."""
        file_path = self.get_pair_data_path(pair)
        if not file_path:
            return None
        
        try:
            # Load parquet file
            df = pd.read_parquet(file_path)
            
            # Ensure required columns exist
            required_cols = ['date', 'open', 'high', 'low', 'close', 'volume']
            if not all(col in df.columns for col in required_cols):
                logger.error(f"Missing required columns in {file_path}. Found: {df.columns.tolist()}")
                return None
            
            # Convert date to datetime for easier manipulation
            df['datetime'] = pd.to_datetime(df['date'], unit='ms')
            
            logger.info(f"Loaded {len(df)} candles for {pair} from {file_path}")
            return df
        
        except Exception as e:
            logger.error(f"Error loading data for {pair}: {str(e)}")
            return None
    
    def plot_candles(self, pair: str, df: pd.DataFrame, days: Optional[int] = None,
                    show_volume: bool = True, save_path: Optional[str] = None):
        """
        Plot candles for a specific pair.
        
        Args:
            pair: Trading pair symbol
            df: DataFrame with candle data
            days: Number of days to plot (from the end of data)
            show_volume: Whether to show volume in the plot
            save_path: Path to save the plot image (if None, display instead)
        """
        if df is None or df.empty:
            logger.warning(f"No data to plot for {pair}")
            return
        
        # Filter data if days is specified
        if days:
            end_date = df['datetime'].max()
            start_date = end_date - pd.Timedelta(days=days)
            df = df[df['datetime'] >= start_date]
            
            if df.empty:
                logger.warning(f"No data to plot for {pair} in the last {days} days")
                return
        
        # Create subplots
        fig, ax1 = plt.subplots(figsize=(12, 8))
        
        # Format dates for x-axis
        date_format = mdates.DateFormatter('%Y-%m-%d %H:%M:%S')
        ax1.xaxis.set_major_formatter(date_format)
        
        # Plot price data
        ax1.set_ylabel('Price')
        ax1.set_title(f"{pair} - {self.timeframe} Candles")
        
        # Plot candles
        for i in range(len(df)):
            # Get data point
            date = df['datetime'].iloc[i]
            op = df['open'].iloc[i]
            hi = df['high'].iloc[i]
            lo = df['low'].iloc[i]
            cl = df['close'].iloc[i]
            
            # Determine candle color
            color = 'g' if cl >= op else 'r'
            
            # Plot candle body
            ax1.plot([date, date], [op, cl], color=color, linewidth=2)
            
            # Plot wicks
            ax1.plot([date, date], [lo, hi], color='black', linewidth=1)
        
        # Volume subplot
        if show_volume:
            ax2 = ax1.twinx()
            ax2.set_ylabel('Volume')
            ax2.bar(df['datetime'], df['volume'], alpha=0.3, color='blue')
            
            # Format volume y-axis
            ax2.yaxis.set_major_formatter(
                FuncFormatter(lambda y, _: f'{y:.0f}')
            )
        
        # Rotate x-axis labels
        plt.xticks(rotation=45)
        
        # Adjust layout
        plt.tight_layout()
        
        # Save or show the plot
        if save_path:
            plt.savefig(save_path)
            logger.info(f"Saved plot to {save_path}")
        else:
            plt.show()
        
        plt.close(fig)
    
    def convert_to_freqtrade_format(self, df: pd.DataFrame) -> pd.DataFrame:
        """Convert dataframe to format compatible with Freqtrade strategy backtest."""
        if df is None or df.empty:
            return pd.DataFrame()
        
        # Ensure we have required columns
        required_cols = ['date', 'open', 'high', 'low', 'close', 'volume']
        if not all(col in df.columns for col in required_cols):
            logger.error(f"Missing required columns for Freqtrade format. Found: {df.columns.tolist()}")
            return pd.DataFrame()
        
        # Select and reorder columns
        df_freqtrade = df[required_cols].copy()
        
        # Make sure date is in milliseconds
        if 'datetime' in df.columns:
            df_freqtrade['date'] = df['datetime'].astype(np.int64) // 10**6
        
        # Sort by date
        df_freqtrade = df_freqtrade.sort_values('date')
        
        return df_freqtrade
    
    def display_stats(self, pair: str, df: pd.DataFrame):
        """Display statistics about the loaded candles."""
        if df is None or df.empty:
            logger.warning(f"No data to display stats for {pair}")
            return
        
        # Calculate time range
        start_time = df['datetime'].min()
        end_time = df['datetime'].max()
        duration = end_time - start_time
        
        # Calculate basic stats
        total_candles = len(df)
        price_range = (df['low'].min(), df['high'].max())
        price_change = ((df['close'].iloc[-1] / df['open'].iloc[0]) - 1) * 100
        total_volume = df['volume'].sum()
        
        # Check for gaps
        df_sorted = df.sort_values('datetime')
        time_diffs = df_sorted['datetime'].diff()
        expected_diff = pd.Timedelta(seconds=int(self.timeframe[:-1]) if self.timeframe.endswith('s') else 60)
        gaps = time_diffs[time_diffs > expected_diff * 1.5]
        gap_count = len(gaps)
        
        # Display statistics
        print(f"\n{'='*50}")
        print(f"Statistics for {pair} ({self.timeframe}):")
        print(f"{'='*50}")
        print(f"Time range: {start_time} to {end_time} ({duration})")
        print(f"Total candles: {total_candles}")
        print(f"Price range: {price_range[0]} to {price_range[1]}")
        print(f"Price change: {price_change:.2f}%")
        print(f"Total volume: {total_volume:.2f}")
        print(f"Detected gaps: {gap_count}")
        
        if gap_count > 0:
            print("\nLargest gaps:")
            largest_gaps = gaps.nlargest(5)
            for dt, gap in zip(largest_gaps.index, largest_gaps.values):
                print(f"  {dt}: {gap}")
        
        print(f"{'='*50}\n")

def main():
    parser = argparse.ArgumentParser(description='Load and display custom candles')
    parser.add_argument('--pairs', type=str, nargs='+', default=None,
                        help='Trading pairs to load (e.g. ETH/USDT:USDT)')
    parser.add_argument('--exchange', type=str, default=DEFAULT_EXCHANGE,
                        help=f'Exchange name (default: {DEFAULT_EXCHANGE})')
    parser.add_argument('--timeframe', type=str, default=DEFAULT_TIMEFRAME,
                        help=f'Candle timeframe (default: {DEFAULT_TIMEFRAME})')
    parser.add_argument('--days', type=int, default=None,
                        help='Number of days to display (from the end)')
    parser.add_argument('--no-plot', action='store_true',
                        help='Skip plotting candles')
    parser.add_argument('--save-plots', type=str, default=None,
                        help='Directory to save plots instead of displaying them')
    parser.add_argument('--list-pairs', action='store_true',
                        help='List available pairs and exit')
    
    args = parser.parse_args()
    
    # Initialize loader
    loader = CustomCandleLoader(args.exchange, args.timeframe)
    
    # List available pairs if requested
    if args.list_pairs:
        pairs = loader.list_available_pairs()
        if pairs:
            print(f"Available pairs for {args.exchange} ({args.timeframe}):")
            for pair in pairs:
                print(f"  {pair}")
        else:
            print(f"No pairs available for {args.exchange} ({args.timeframe})")
        return 0
    
    # Determine which pairs to process
    if args.pairs:
        pairs_to_process = args.pairs
    else:
        pairs_to_process = loader.list_available_pairs()
        if not pairs_to_process:
            logger.error(f"No pairs available for {args.exchange} ({args.timeframe})")
            return 1
    
    # Create save directory if needed
    if args.save_plots:
        save_dir = Path(args.save_plots)
        save_dir.mkdir(parents=True, exist_ok=True)
    
    # Process each pair
    for pair in pairs_to_process:
        try:
            # Load data
            df = loader.load_pair_data(pair)
            
            if df is not None and not df.empty:
                # Display statistics
                loader.display_stats(pair, df)
                
                # Plot candles if not disabled
                if not args.no_plot:
                    save_path = None
                    if args.save_plots:
                        filename = f"{pair.replace('/', '-').replace(':', '')}.png"
                        save_path = str(Path(args.save_plots) / filename)
                    
                    loader.plot_candles(pair, df, args.days, save_path=save_path)
            else:
                logger.warning(f"No data loaded for {pair}")
        
        except Exception as e:
            logger.error(f"Error processing {pair}: {str(e)}")
    
    logger.info("Finished processing all pairs")
    return 0

if __name__ == "__main__":
    sys.exit(main()) 