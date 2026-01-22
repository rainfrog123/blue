#!/usr/bin/env python3
"""
Script to integrate custom candles with Freqtrade strategies.
This shows how to use custom candles in a strategy and backtest.
"""
import os
import sys
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

import pandas as pd
import numpy as np

# Add the parent directory to sys.path
sys.path.append(str(Path(__file__).parents[3]))

# Import freqtrade modules
from freqtrade.data.history.history_utils import pair_to_filename, load_pair_history
from freqtrade.data.converter import convert_ohlcv_format
from freqtrade.optimize.backtesting import Backtesting
from freqtrade.configuration import Configuration
from freqtrade.resolvers import StrategyResolver
from freqtrade.exchange import timeframe_to_minutes

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
CONFIG_FILE = Path("/allah/stuff/freq/project_2/custom_config.json")


class CustomCandleIntegrator:
    """Class to integrate custom candles with Freqtrade."""
    
    def __init__(self, config_file: Path = CONFIG_FILE, 
                 exchange_name: str = DEFAULT_EXCHANGE, 
                 timeframe: str = DEFAULT_TIMEFRAME):
        """Initialize the integrator with config and timeframe."""
        self.config_file = config_file
        self.exchange_name = exchange_name
        self.timeframe = timeframe
        self.data_dir = BASE_DATA_DIR / exchange_name / timeframe
        
        # Load configuration
        try:
            self.config = Configuration.from_files([str(config_file)])
            
            # Update config with our settings
            self.config['exchange']['name'] = exchange_name
            self.config['timeframe'] = timeframe
            self.config['datadir'] = str(BASE_DATA_DIR)
            
            logger.info(f"Loaded configuration from {config_file}")
        except Exception as e:
            logger.error(f"Error loading config: {str(e)}")
            raise
    
    def load_custom_candles(self, pair: str) -> Optional[pd.DataFrame]:
        """Load custom candles for a specific pair."""
        # Convert pair to filename format
        filename = pair.replace('/', '-').replace(':', '')
        file_path = self.data_dir / f"{filename}.parquet"
        
        if not file_path.exists():
            logger.warning(f"No data file found for {pair} at {file_path}")
            return None
        
        try:
            # Load parquet file
            df = pd.read_parquet(file_path)
            
            # Ensure required columns exist
            required_cols = ['date', 'open', 'high', 'low', 'close', 'volume']
            if not all(col in df.columns for col in required_cols):
                logger.error(f"Missing required columns in {file_path}. Found: {df.columns.tolist()}")
                return None
            
            # Convert to Freqtrade format
            df_freqtrade = df[required_cols].copy()
            
            # Make sure date is in milliseconds (int)
            if isinstance(df_freqtrade['date'].iloc[0], pd.Timestamp):
                df_freqtrade['date'] = df_freqtrade['date'].astype(np.int64) // 10**6
            
            # Sort by date
            df_freqtrade = df_freqtrade.sort_values('date')
            
            logger.info(f"Loaded {len(df_freqtrade)} candles for {pair}")
            return df_freqtrade
        
        except Exception as e:
            logger.error(f"Error loading data for {pair}: {str(e)}")
            return None
    
    def prepare_data_for_backtest(self, pairs: List[str]) -> Dict[str, pd.DataFrame]:
        """Prepare data for backtesting."""
        data: Dict[str, pd.DataFrame] = {}
        
        for pair in pairs:
            df = self.load_custom_candles(pair)
            if df is not None and not df.empty:
                data[pair] = df
            else:
                logger.warning(f"Skipping {pair} due to missing or empty data")
        
        if not data:
            logger.error("No data available for backtesting")
            return {}
        
        return data
    
    def run_backtest(self, strategy_name: str, pairs: List[str]) -> Optional[Dict[str, Any]]:
        """Run a backtest using the custom candles."""
        # Prepare data
        data = self.prepare_data_for_backtest(pairs)
        if not data:
            return None
        
        # Configure backtesting
        self.config['strategy'] = strategy_name
        self.config['pairs'] = pairs
        
        try:
            # Initialize backtesting
            backtesting = Backtesting(self.config)
            backtesting.load_bt_data_detail = data  # Set our custom data
            backtesting.timeframe = self.timeframe
            backtesting.timeframe_min = timeframe_to_minutes(self.timeframe)
            
            # Load strategy
            strategy = StrategyResolver.load_strategy(strategy_name, self.config)
            
            # Run backtest
            logger.info(f"Running backtest with strategy {strategy_name} on {len(pairs)} pairs")
            results = backtesting.start(strategy)
            
            return results
        
        except Exception as e:
            logger.error(f"Error during backtesting: {str(e)}")
            return None
    
    def display_backtest_results(self, results: Dict[str, Any]) -> None:
        """Display backtest results."""
        if not results:
            logger.error("No backtest results to display")
            return
        
        # Display summary
        print(f"\n{'='*50}")
        print(f"Backtest Results:")
        print(f"{'='*50}")
        
        # Extract key metrics
        if 'results_per_pair' in results:
            print("\nResults per pair:")
            for pair, pair_results in results['results_per_pair'].items():
                profit = pair_results.get('profit_abs', 0)
                profit_pct = pair_results.get('profit_ratio', 0) * 100
                trade_count = pair_results.get('trade_count', 0)
                print(f"  {pair}: {profit:.2f} ({profit_pct:.2f}%) over {trade_count} trades")
        
        # Overall performance
        if 'strategy_comparison' in results:
            performance = results['strategy_comparison'][0]
            total_profit = performance.get('profit_total_abs', 0)
            total_profit_pct = performance.get('profit_total', 0) * 100
            total_trades = performance.get('trade_count', 0)
            win_rate = performance.get('win_ratio', 0) * 100
            
            print(f"\nOverall performance:")
            print(f"  Total profit: {total_profit:.2f} ({total_profit_pct:.2f}%)")
            print(f"  Total trades: {total_trades}")
            print(f"  Win rate: {win_rate:.2f}%")
        
        print(f"{'='*50}\n")
    
    def create_custom_config(self, output_file: Path) -> None:
        """Create a custom configuration for using 5s candles."""
        config = {
            "max_open_trades": 1,
            "stake_currency": "USDT",
            "stake_amount": "unlimited",
            "tradable_balance_ratio": 0.99,
            "fiat_display_currency": "USD",
            "timeframe": self.timeframe,
            "dry_run": True,
            "cancel_open_orders_on_exit": False,
            "use_exit_signal": True,
            "exit_profit_only": False,
            "ignore_roi_if_entry_signal": False,
            "exchange": {
                "name": self.exchange_name,
                "key": "",
                "secret": "",
                "ccxt_config": {},
                "ccxt_async_config": {},
                "pair_whitelist": [],
                "pair_blacklist": []
            },
            "datadir": str(BASE_DATA_DIR),
            "initial_state": "running",
            "db_url": "sqlite:///user_data/tradesv3.sqlite",
            "user_data_dir": "user_data",
            "strategy": "SampleStrategy",
            "strategy_path": "user_data/strategies/",
            "internals": {
                "process_throttle_secs": 5
            }
        }
        
        # Write to file
        try:
            import json
            with open(output_file, 'w') as f:
                json.dump(config, f, indent=4)
            logger.info(f"Created custom config at {output_file}")
        except Exception as e:
            logger.error(f"Error creating config file: {str(e)}")
    
    def create_sample_strategy(self, output_file: Path) -> None:
        """Create a sample strategy optimized for 5s candles."""
        strategy_code = """
from freqtrade.strategy import IStrategy, merge_informative_pair
from pandas import DataFrame
import talib.abstract as ta
import pandas as pd
import numpy as np

class FiveSecondStrategy(IStrategy):
    """
    Strategy optimized for 5-second candles.
    """
    # Strategy interface version
    INTERFACE_VERSION = 3

    # Minimal ROI designed for 5-second timeframe
    minimal_roi = {
        "0": 0.01,      # 1% profit at any time
        "60": 0.005,    # 0.5% profit after 60 seconds (12 candles)
        "180": 0        # 0% profit after 180 seconds (36 candles)
    }

    # Stoploss designed for 5-second timeframe
    stoploss = -0.02    # 2% maximum loss

    # Trailing stoploss (suitable for volatile 5s candles)
    trailing_stop = True
    trailing_stop_positive = 0.005
    trailing_stop_positive_offset = 0.01
    trailing_only_offset_is_reached = True

    # Timeframe for the strategy
    timeframe = '5s'

    # Run "populate_indicators" only for new candle.
    process_only_new_candles = True

    # Number of candles the strategy requires before producing valid signals
    startup_candle_count: int = 30

    # Optional order type mapping
    order_types = {
        'entry': 'limit',
        'exit': 'limit',
        'stoploss': 'market',
        'stoploss_on_exchange': False
    }

    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Adds several indicators to the given DataFrame.
        Optimized for 5-second candles by using shorter windows.
        """
        # Volume-weighted RSI (shorter windows for 5s candles)
        dataframe['rsi'] = ta.RSI(dataframe, timeperiod=9)
        
        # EMA - using short windows
        dataframe['ema5'] = ta.EMA(dataframe, timeperiod=5)
        dataframe['ema10'] = ta.EMA(dataframe, timeperiod=10)
        dataframe['ema20'] = ta.EMA(dataframe, timeperiod=20)
        
        # Bollinger Bands - adjusted for 5s volatility
        bollinger = ta.BBANDS(dataframe, timeperiod=12, nbdevup=2.0, nbdevdn=2.0)
        dataframe['bb_lowerband'] = bollinger['lowerband']
        dataframe['bb_middleband'] = bollinger['middleband']
        dataframe['bb_upperband'] = bollinger['upperband']
        
        # MACD - faster settings for 5s
        macd = ta.MACD(dataframe, fastperiod=6, slowperiod=12, signalperiod=3)
        dataframe['macd'] = macd['macd']
        dataframe['macdsignal'] = macd['macdsignal']
        dataframe['macdhist'] = macd['macdhist']
        
        # Volume moving average - shorter window
        dataframe['volume_mean'] = dataframe['volume'].rolling(6).mean()
        
        # Volatility indicator
        dataframe['atr'] = ta.ATR(dataframe, timeperiod=7)
        
        # Price change rate over short periods (suitable for 5s)
        dataframe['pct_change'] = dataframe['close'].pct_change(3)
        
        return dataframe

    def populate_entry_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Based on TA indicators, defines entry signals.
        Optimized for 5-second candles by looking for quick momentum shifts.
        """
        dataframe.loc[
            (
                # MACD rising and crossing signal
                (dataframe['macd'] > dataframe['macdsignal']) &
                (dataframe['macd'].shift(1) < dataframe['macdsignal'].shift(1)) &
                
                # RSI shows momentum but not overbought
                (dataframe['rsi'] > 45) & (dataframe['rsi'] < 70) &
                
                # EMA alignment shows uptrend
                (dataframe['ema5'] > dataframe['ema10']) &
                (dataframe['ema10'] > dataframe['ema20']) &
                
                # Volume is increasing
                (dataframe['volume'] > dataframe['volume_mean']) &
                
                # Volatility is reasonable
                (dataframe['atr'] < dataframe['close'] * 0.01) &
                
                # Recent positive momentum
                (dataframe['pct_change'] > 0.001)
            ),
            'enter_long'] = 1
        
        dataframe.loc[
            (
                # MACD falling and crossing signal
                (dataframe['macd'] < dataframe['macdsignal']) &
                (dataframe['macd'].shift(1) > dataframe['macdsignal'].shift(1)) &
                
                # RSI shows downward momentum but not oversold
                (dataframe['rsi'] < 55) & (dataframe['rsi'] > 30) &
                
                # EMA alignment shows downtrend
                (dataframe['ema5'] < dataframe['ema10']) &
                (dataframe['ema10'] < dataframe['ema20']) &
                
                # Volume is increasing
                (dataframe['volume'] > dataframe['volume_mean']) &
                
                # Volatility is reasonable
                (dataframe['atr'] < dataframe['close'] * 0.01) &
                
                # Recent negative momentum
                (dataframe['pct_change'] < -0.001)
            ),
            'enter_short'] = 1
            
        return dataframe

    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Based on TA indicators, defines exit signals.
        Optimized for 5-second candles by using quick reversal signals.
        """
        dataframe.loc[
            (
                # MACD crossing signal to the downside
                ((dataframe['macd'] < dataframe['macdsignal']) &
                (dataframe['macd'].shift(1) > dataframe['macdsignal'].shift(1))) |
                
                # RSI overbought
                (dataframe['rsi'] > 75) |
                
                # Price hit upper Bollinger Band
                (dataframe['close'] > dataframe['bb_upperband']) |
                
                # EMAs showing trend weakness
                (dataframe['ema5'] < dataframe['ema10'])
            ),
            'exit_long'] = 1
            
        dataframe.loc[
            (
                # MACD crossing signal to the upside
                ((dataframe['macd'] > dataframe['macdsignal']) &
                (dataframe['macd'].shift(1) < dataframe['macdsignal'].shift(1))) |
                
                # RSI oversold
                (dataframe['rsi'] < 25) |
                
                # Price hit lower Bollinger Band
                (dataframe['close'] < dataframe['bb_lowerband']) |
                
                # EMAs showing trend weakness
                (dataframe['ema5'] > dataframe['ema10'])
            ),
            'exit_short'] = 1
            
        return dataframe
"""
        
        # Write to file
        try:
            with open(output_file, 'w') as f:
                f.write(strategy_code.strip())
            logger.info(f"Created sample strategy at {output_file}")
        except Exception as e:
            logger.error(f"Error creating strategy file: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description='Integrate custom candles with Freqtrade')
    parser.add_argument('--config', type=str, default=str(CONFIG_FILE),
                        help=f'Configuration file path (default: {CONFIG_FILE})')
    parser.add_argument('--exchange', type=str, default=DEFAULT_EXCHANGE,
                        help=f'Exchange name (default: {DEFAULT_EXCHANGE})')
    parser.add_argument('--timeframe', type=str, default=DEFAULT_TIMEFRAME,
                        help=f'Candle timeframe (default: {DEFAULT_TIMEFRAME})')
    parser.add_argument('--pairs', type=str, nargs='+', default=["ETH/USDT:USDT"],
                        help='Trading pairs to use (default: ["ETH/USDT:USDT"])')
    parser.add_argument('--strategy', type=str, default="FiveSecondStrategy",
                        help='Strategy name to use for backtesting')
    parser.add_argument('--create-config', action='store_true',
                        help='Create a custom config file for 5s candles')
    parser.add_argument('--create-strategy', action='store_true',
                        help='Create a sample strategy optimized for 5s candles')
    parser.add_argument('--backtest', action='store_true',
                        help='Run a backtest with the custom candles')
    
    args = parser.parse_args()
    
    # Initialize integrator
    integrator = CustomCandleIntegrator(
        Path(args.config), args.exchange, args.timeframe
    )
    
    # Create config if requested
    if args.create_config:
        integrator.create_custom_config(Path(args.config))
    
    # Create strategy if requested
    if args.create_strategy:
        strategy_dir = Path('/allah/stuff/freq/project_2/user_data/strategies')
        strategy_dir.mkdir(parents=True, exist_ok=True)
        strategy_path = strategy_dir / f"{args.strategy}.py"
        integrator.create_sample_strategy(strategy_path)
    
    # Run backtest if requested
    if args.backtest:
        results = integrator.run_backtest(args.strategy, args.pairs)
        if results:
            integrator.display_backtest_results(results)
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 