#!/usr/bin/env python
"""
Download daily ETH/USDT trade data from Binance Data Vision.
Downloads zip files, extracts to CSV, converts to Parquet format.
"""

import requests
import os
import time
import sys
import glob
import zipfile
import shutil
import io
from datetime import datetime, timedelta
from tqdm import tqdm
import humanize
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.dates import DateFormatter
import matplotlib.dates as mdates
from tabulate import tabulate

BASE_URL = "https://data.binance.vision/data/futures/um/daily/trades/ETHUSDT"
DEFAULT_OUTPUT_DIR = "/allah/data/trades"
DEFAULT_DATA_DIR = os.path.join(DEFAULT_OUTPUT_DIR, "eth_usdt_daily_trades")

class BinanceDailyTradesDownloader:
    """Download and manage daily ETH/USDT trade data from Binance."""
    
    def __init__(self, trades_dir=None):
        os.makedirs(DEFAULT_OUTPUT_DIR, exist_ok=True)
        
        if trades_dir is None:
            self.trades_dir = DEFAULT_DATA_DIR
            os.makedirs(self.trades_dir, exist_ok=True)
            print(f"Using directory: {self.trades_dir}")
        else:
            self.trades_dir = trades_dir
            os.makedirs(self.trades_dir, exist_ok=True)
            print(f"Using provided directory: {self.trades_dir}")
    
    def get_free_space(self, path):
        try:
            total, used, free = shutil.disk_usage(path)
            return free
        except:
            try:
                st = os.statvfs(path)
                return st.f_frsize * st.f_bavail
            except:
                return 0

    def get_file_size(self, url):
        try:
            response = requests.head(url, timeout=10)
            response.raise_for_status()
            return int(response.headers.get('content-length', 0))
        except Exception as e:
            print(f"Error checking file size for {url}: {e}")
            return 0

    def download_file(self, url, output_path):
        response = requests.get(url, stream=True, timeout=30)
        total_size = int(response.headers.get('content-length', 0))
        
        with open(output_path, 'wb') as file, tqdm(
            desc=os.path.basename(output_path),
            total=total_size,
            unit='iB',
            unit_scale=True,
            unit_divisor=1024,
        ) as pbar:
            for data in response.iter_content(chunk_size=1024):
                size = file.write(data)
                pbar.update(size)

    def convert_csv_to_parquet(self, csv_path, parquet_path):
        try:
            chunk_size = 500000
            
            first_chunk = pd.read_csv(csv_path, nrows=1)
            schema = {}
            for column in first_chunk.columns:
                if column == 'timestamp':
                    schema[column] = 'datetime64[ns]'
                else:
                    schema[column] = first_chunk[column].dtype
            
            chunks = pd.read_csv(csv_path, chunksize=chunk_size, dtype=schema)
            
            first = True
            for chunk in chunks:
                if 'timestamp' in chunk.columns:
                    chunk['timestamp'] = pd.to_datetime(chunk['timestamp'])
                chunk.to_parquet(
                    parquet_path,
                    compression='snappy',
                    index=False,
                    engine='fastparquet',
                    append=not first
                )
                first = False
            
            os.remove(csv_path)
            print(f"Converted: {os.path.basename(csv_path)} → {os.path.basename(parquet_path)}")
            return True
        except Exception as e:
            print(f"Error converting to parquet: {e}")
            if os.path.exists(parquet_path):
                os.remove(parquet_path)
            return False

    def get_existing_files(self):
        existing_files = set()
        for file in glob.glob(os.path.join(self.trades_dir, "*.parquet")):
            basename = os.path.basename(file)
            if basename.startswith("ETHUSDT-trades-"):
                date_str = basename.split("ETHUSDT-trades-")[1].split(".")[0]
                existing_files.add(date_str)
        return existing_files

    def extract_and_convert(self, zip_path, extract_path):
        success = False
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                csv_files = [f for f in zip_ref.namelist() if f.endswith('.csv')]
                for csv_file in csv_files:
                    zip_ref.extract(csv_file, extract_path)
                    csv_path = os.path.join(extract_path, csv_file)
                    parquet_path = csv_path.replace('.csv', '.parquet')
                    
                    print(f"Converting {csv_file} to Parquet format...")
                    if self.convert_csv_to_parquet(csv_path, parquet_path):
                        success = True
                    elif os.path.exists(csv_path):
                        os.remove(csv_path)
            return success
        except Exception as e:
            print(f"Error extracting zip: {e}")
            return False

    def download(self, year=2025, month=3):
        """Download daily trades for a specific month."""
        existing_files = self.get_existing_files()
        print(f"\nFound {len(existing_files)} existing processed files")
        if existing_files:
            print("Date range:", min(existing_files), "to", max(existing_files))
        
        days_to_download = []
        
        first_day = datetime(year, month, 1)
        if month == 12:
            next_month = datetime(year + 1, 1, 1)
        else:
            next_month = datetime(year, month + 1, 1)
        
        num_days = (next_month - first_day).days
        
        for day in range(1, num_days + 1):
            date = first_day + timedelta(days=day-1)
            date_str = date.strftime('%Y-%m-%d')
            
            parquet_filename = f"ETHUSDT-trades-{date_str}.parquet"
            parquet_path = os.path.join(self.trades_dir, parquet_filename)
            if os.path.exists(parquet_path):
                print(f"Skipping {date_str} - parquet file already exists")
                continue
            
            days_to_download.append(date)
        
        if not days_to_download:
            print("\nAll files are up to date!")
            return
        
        total_files = len(days_to_download)
        print(f"\nFiles to download: {total_files}")
        
        processed_count = 0
        for idx, date in enumerate(days_to_download, 1):
            date_str = date.strftime('%Y-%m-%d')
            zip_filename = f"ETHUSDT-trades-{date_str}.zip"
            
            zip_url = f"{BASE_URL}/{zip_filename}"
            zip_path = os.path.join(self.trades_dir, zip_filename)
            
            try:
                print(f"\nProcessing file {idx}/{total_files}: {zip_filename}")
                
                file_size = self.get_file_size(zip_url)
                if file_size == 0:
                    print(f"Skipping {zip_filename} - file not available or empty")
                    continue
                
                print(f"File size: {humanize.naturalsize(file_size)}")
                
                free_space = self.get_free_space(self.trades_dir)
                required_space = file_size * 2
                
                if required_space > free_space:
                    print(f"Warning: Not enough disk space!")
                    print(f"Required: {humanize.naturalsize(required_space)}")
                    print(f"Available: {humanize.naturalsize(free_space)}")
                    print("Please free up some space and try again.")
                    break
                
                print(f"Downloading {zip_filename}...")
                self.download_file(zip_url, zip_path)
                
                print(f"Processing {zip_filename}...")
                if self.extract_and_convert(zip_path, self.trades_dir):
                    processed_count += 1
                
                if os.path.exists(zip_path):
                    os.remove(zip_path)
                
                time.sleep(1)
                
            except Exception as e:
                print(f"Error processing {zip_filename}: {e}")
                if os.path.exists(zip_path):
                    os.remove(zip_path)
                continue
        
        print(f"\nDownload completed! Data saved to: {self.trades_dir}")
        
        final_files = self.get_existing_files()
        print(f"Total files processed this run: {processed_count}")
        print(f"Total files in directory: {len(final_files)}")
        if final_files:
            print("Date range:", min(final_files), "to", max(final_files))
    
    def parse_date(self, date_str):
        try:
            if len(date_str) == 10:
                return datetime.strptime(date_str, "%Y-%m-%d")
            else:
                raise ValueError(f"Invalid date format: {date_str}. Use YYYY-MM-DD")
        except ValueError as e:
            print(f"Error parsing date: {e}")
            sys.exit(1)
    
    def get_available_dates(self):
        all_files = glob.glob(os.path.join(self.trades_dir, "ETHUSDT-trades-????-??-??.parquet"))
        dates = []
        
        for file_path in all_files:
            file_name = os.path.basename(file_path)
            try:
                date_part = file_name.split('-trades-')[1].split('.')[0]
                dates.append(date_part)
            except (IndexError, ValueError):
                continue
        
        dates.sort()
        return dates
    
    def get_parquet_files(self, start_date, end_date=None):
        start_dt = self.parse_date(start_date)
        
        if end_date:
            end_dt = self.parse_date(end_date)
        else:
            end_dt = start_dt
        
        if end_dt < start_dt:
            raise ValueError("End date must be after or equal to start date")
        
        all_files = glob.glob(os.path.join(self.trades_dir, "ETHUSDT-trades-????-??-??.parquet"))
        filtered_files = []
        for file_path in all_files:
            file_name = os.path.basename(file_path)
            try:
                date_part = file_name.split('-trades-')[1].split('.')[0]
                file_dt = datetime.strptime(date_part, "%Y-%m-%d")
                
                if start_dt <= file_dt <= end_dt:
                    filtered_files.append(file_path)
            except (IndexError, ValueError):
                continue
        
        filtered_files.sort()
        return filtered_files
    
    def load_trades(self, start_date, end_date=None, columns=None, sample_rate=None, verbose=True):
        """Load trades for a specific date range."""
        files = self.get_parquet_files(start_date, end_date)
        
        if not files:
            if verbose:
                print(f"No files found for the specified date range: {start_date} to {end_date or start_date}")
            return None
        
        if verbose:
            print(f"Found {len(files)} files for the specified date range")
            for file in files:
                print(f"  - {os.path.basename(file)}")
        
        dfs = []
        total_size = 0
        
        if verbose:
            print(f"Loading {len(files)} files...")
            file_iter = tqdm(files)
        else:
            file_iter = files
            
        for file_path in file_iter:
            try:
                if columns:
                    df = pd.read_parquet(file_path, columns=columns, engine='pyarrow')
                else:
                    df = pd.read_parquet(file_path, engine='pyarrow')
                
                if sample_rate and 0 < sample_rate < 1:
                    df = df.sample(frac=sample_rate, random_state=42)
                
                dfs.append(df)
                total_size += len(df)
                
                if verbose:
                    file_name = os.path.basename(file_path)
                    print(f"Loaded {file_name}: {len(df):,} rows")
                
            except Exception as e:
                if verbose:
                    print(f"Error loading {file_path}: {e}")
        
        if not dfs:
            return None
        
        if verbose:
            print(f"Concatenating {len(dfs)} dataframes with total {total_size:,} rows...")
        result = pd.concat(dfs, ignore_index=True)
        
        if 'time' in result.columns:
            result['datetime'] = pd.to_datetime(result['time'], unit='ms')
        
        return result

    def visualize(self, df, timeframe='1min', price_col='price', save_path=None):
        """Visualize trade data with the specified timeframe."""
        if df is None or len(df) == 0:
            print("No data to visualize")
            return
        
        if 'datetime' not in df.columns and 'time' in df.columns:
            df['datetime'] = pd.to_datetime(df['time'], unit='ms')
        
        if 'datetime' not in df.columns:
            print("No datetime column found in data")
            return
        
        df = df.set_index('datetime')
        resampled = df[price_col].resample(timeframe).agg(['first', 'max', 'min', 'last'])
        
        fig, ax = plt.figure(figsize=(12, 6)), plt.gca()
        ax.plot(resampled.index, resampled['last'], label=f'ETH/USDT ({timeframe} timeframe)')
        
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
        plt.xticks(rotation=45)
        
        plt.xlabel('Time')
        plt.ylabel('Price (USDT)')
        plt.title(f'ETH/USDT Price ({timeframe} timeframe)')
        
        plt.grid(True, alpha=0.3)
        plt.legend()
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path)
            print(f"Figure saved to {save_path}")
        else:
            plt.show()

def main():
    pd.set_option('display.max_rows', 20)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', None)
    pd.set_option('display.float_format', lambda x: '%.5f' % x)
    
    downloader = BinanceDailyTradesDownloader()
    
    start_date = datetime(2025, 12, 1)
    today = datetime.now()
    yesterday = today - timedelta(days=1)
    
    print(f"Downloading ETH/USDT trades data from September 2025 to {yesterday.strftime('%Y-%m-%d')}...")
    
    current_date = start_date
    while current_date <= yesterday:
        print(f"\nProcessing {current_date.strftime('%B %Y')}...")
        downloader.download(year=current_date.year, month=current_date.month)
        
        if current_date.month == 12:
            current_date = datetime(current_date.year + 1, 1, 1)
        else:
            current_date = datetime(current_date.year, current_date.month + 1, 1)
    
    daily_dates = downloader.get_available_dates()
    if daily_dates:
        print(f"\nAvailable data files ({len(daily_dates)}):")
        for date in daily_dates:
            print(f"  - {date}")
        print(f"\nDate range: {daily_dates[0]} to {daily_dates[-1]}")
    else:
        print("No data files found")

if __name__ == "__main__":
    main()

