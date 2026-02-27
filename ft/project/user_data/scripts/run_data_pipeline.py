#!/usr/bin/env python3
"""
Run the complete data pipeline:
1. Fetch trades from Binance
2. Convert to 5s candles
3. Load and display the candles
"""
import os
import sys
import logging
import argparse
import subprocess
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

# Set paths
SCRIPTS_DIR = Path(__file__).parent
PYTHON_INTERPRETER = "/allah/freqtrade/.venv/bin/python3"

def run_command(cmd, description):
    """Run a command and log its output."""
    logger.info(f"Running {description}")
    logger.info(f"Command: {' '.join(cmd)}")
    
    try:
        # Run the command and capture output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        # Stream output
        while True:
            stdout_line = process.stdout.readline()
            stderr_line = process.stderr.readline()
            
            if stdout_line == '' and stderr_line == '' and process.poll() is not None:
                break
                
            if stdout_line:
                logger.info(stdout_line.strip())
            if stderr_line:
                logger.error(stderr_line.strip())
                
        # Get return code
        return_code = process.poll()
        if return_code != 0:
            logger.error(f"{description} failed with return code {return_code}")
            return False
            
        logger.info(f"{description} completed successfully")
        return True
    
    except Exception as e:
        logger.error(f"Error running {description}: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Run the complete data pipeline')
    parser.add_argument('--pairs', type=str, nargs='+', default=["ETH/USDT:USDT"],
                        help='Trading pairs to process (e.g. ETH/USDT:USDT)')
    parser.add_argument('--days', type=int, default=1,
                        help='Number of days of data to fetch')
    parser.add_argument('--skip-fetch', action='store_true',
                        help='Skip fetching trades and only load existing candles')
    
    args = parser.parse_args()
    
    # 1. Fetch trades from Binance and convert to candles
    if not args.skip_fetch:
        pairs_arg = " ".join([f"--pairs {pair}" for pair in args.pairs])
        fetch_cmd = [
            PYTHON_INTERPRETER,
            str(SCRIPTS_DIR / "fetch_binance_trades.py"),
            f"--days {args.days}"
        ]
        fetch_cmd.extend(pairs_arg.split())
        
        if not run_command(fetch_cmd, "Fetching trades and converting to candles"):
            logger.error("Pipeline halted due to error in fetch step")
            return 1
    
    # 2. Load and display the candles for each pair
    success = True
    for pair in args.pairs:
        load_cmd = [
            PYTHON_INTERPRETER,
            str(SCRIPTS_DIR / "load_custom_candles.py"),
            f"--pair {pair}"
        ]
        
        if not run_command(load_cmd, f"Loading candles for {pair}"):
            logger.error(f"Failed to load candles for {pair}")
            success = False
    
    if success:
        logger.info("Data pipeline completed successfully")
        return 0
    else:
        logger.error("Data pipeline encountered errors")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 