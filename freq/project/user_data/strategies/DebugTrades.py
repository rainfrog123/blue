from freqtrade.strategy import IStrategy
from pandas import DataFrame
import logging
import pandas as pd

logger = logging.getLogger(__name__)

class DebugTrades(IStrategy):
    """Strategy to debug trade data conversion to OHLCV"""
    
    timeframe = '5s'
    minimal_roi = {"0": 100}
    stoploss = -0.99
    
    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Log information about the dataframe we're receiving"""
        pair = metadata['pair']
        
        # Log basic info about the dataframe
        if dataframe.empty:
            logger.warning(f"EMPTY DATAFRAME for {pair}. This is a problem!")
            return dataframe
        
        # Log some data about what we received
        logger.info(f"Received dataframe for {pair} with {len(dataframe)} rows")
        logger.info(f"Timerange: {dataframe['date'].min()} to {dataframe['date'].max()}")
        
        # Log the last few candles
        logger.info(f"Last 3 candles:\n{dataframe[['date', 'open', 'high', 'low', 'close', 'volume']].tail(3)}")
        
        # Add indicators (just a simple one to verify processing)
        dataframe['sma_5'] = dataframe['close'].rolling(5).mean()
        
        return dataframe
    
    def populate_entry_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Define entry conditions"""
        dataframe['enter_long'] = 0  # No entries for debugging
        return dataframe
    
    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Define exit conditions"""
        dataframe['exit_long'] = 0  # No exits for debugging
        return dataframe 