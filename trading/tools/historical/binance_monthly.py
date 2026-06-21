#!/usr/bin/env python
"""
Download monthly ETH/USDT trade data from Binance Data Vision.
Downloads zip files, extracts to CSV, converts to Parquet format.
"""

import requests
import os
import time
import sys
import glob
import zipfile
import shutil
import argparse
import io
from datetime import datetime
from tqdm import tqdm
import humanize
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.dates import DateFormatter
import matplotlib.dates as mdates
from tabulate import tabulate

BASE_URL = "https://data.binance.vision/data/futures/um/monthly/trades/ETHUSDT"
DEFAULT_OUTPUT_DIR = "/allah/data/trades"
DEFAULT_DATA_DIR = os.path.join(DEFAULT_OUTPUT_DIR, "eth_usdt_monthly_trades")

class BinanceMonthlyTradesDownloader:
    """Download and manage monthly ETH/USDT trade data from Binance."""
    
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
            response = requests.head(url)
            return int(response.headers.get('content-length', 0))
        except:
            return 0

    def download_file(self, url, output_path):
        response = requests.get(url, stream=True)
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
                year_month = basename.split("ETHUSDT-trades-")[1].split(".")[0]
                existing_files.add(year_month)
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

    def download(self, start_year=2019, start_month=11):
        """Download monthly trades from start date to present."""
        existing_files = self.get_existing_files()
        print(f"\nFound {len(existing_files)} existing processed files")
        if existing_files:
            print("Date range:", min(existing_files), "to", max(existing_files))
        
        current_date = datetime.now()
        current_year = current_date.year
        current_month = current_date.month
        
        months_to_download = []
        for year in range(start_year, current_year + 1):
            for month in range(1, 13):
                if year == current_year and month > current_month:
                    continue
                if year == start_year and month < start_month:
                    continue
                month_str = f"{month:02d}"
                year_month = f"{year}-{month_str}"
                
                parquet_filename = f"ETHUSDT-trades-{year_month}.parquet"
                parquet_path = os.path.join(self.trades_dir, parquet_filename)
                if os.path.exists(parquet_path):
                    print(f"Skipping {year_month} - parquet file already exists")
                    continue
                
                months_to_download.append((year, month))
        
        if not months_to_download:
            print("\nAll files are up to date!")
            return
        
        total_files = len(months_to_download)
        print(f"\nFiles to download: {total_files}")
        
        processed_count = 0
        for idx, (year, month) in enumerate(months_to_download, 1):
            month_str = f"{month:02d}"
            zip_filename = f"ETHUSDT-trades-{year}-{month_str}.zip"
            
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
            if len(date_str) == 7:
                dt = datetime.strptime(date_str, "%Y-%m")
                return dt.year, dt.month
            else:
                raise ValueError(f"Invalid date format: {date_str}. Use YYYY-MM")
        except ValueError as e:
            print(f"Error parsing date: {e}")
            sys.exit(1)
    
    def get_available_dates(self):
        all_files = glob.glob(os.path.join(self.trades_dir, "ETHUSDT-trades-????-??.parquet"))
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
        start_year, start_month = self.parse_date(start_date)
        
        if end_date:
            end_year, end_month = self.parse_date(end_date)
        else:
            end_year, end_month = start_year, start_month
        
        if (end_year < start_year) or (end_year == start_year and end_month < start_month):
            raise ValueError("End date must be after or equal to start date")
        
        all_files = glob.glob(os.path.join(self.trades_dir, "ETHUSDT-trades-????-??.parquet"))
        
        filtered_files = []
        for file_path in all_files:
            file_name = os.path.basename(file_path)
            try:
                date_part = file_name.split('-trades-')[1].split('.')[0]
                file_year, file_month = map(int, date_part.split('-'))
                
                if (file_year > start_year or (file_year == start_year and file_month >= start_month)) and \
                   (file_year < end_year or (file_year == end_year and file_month <= end_month)):
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

    def visualize(self, df, timeframe='5m', price_col='price', save_path=None):
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
    
    parser = argparse.ArgumentParser(description='Binance Monthly Trades Downloader')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Download command
    download_parser = subparsers.add_parser('download', help='Download monthly trade data')
    download_parser.add_argument('--start_year', type=int, default=2025, help='Starting year (default: 2025)')
    download_parser.add_argument('--start_month', type=int, default=6, help='Starting month (default: 6)')
    download_parser.add_argument('--output_dir', type=str, help='Output directory (optional)')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List available monthly dates')
    list_parser.add_argument('--data_dir', type=str, help='Data directory (optional)')
    
    # Aggregate command
    aggregate_parser = subparsers.add_parser('aggregate', help='Aggregate monthly trade data')
    aggregate_parser.add_argument('start_date', type=str, help='Start date in format YYYY-MM')
    aggregate_parser.add_argument('--end_date', type=str, help='End date in format YYYY-MM (optional)')
    aggregate_parser.add_argument('--columns', type=str, nargs='+', help='Columns to load (optional)')
    aggregate_parser.add_argument('--sample_rate', type=float, help='Sample rate between 0 and 1 (optional)')
    aggregate_parser.add_argument('--output', type=str, help='Output file path (optional)')
    aggregate_parser.add_argument('--data_dir', type=str, help='Data directory (optional)')
    
    # Visualize command
    visualize_parser = subparsers.add_parser('visualize', help='Visualize monthly trade data')
    visualize_parser.add_argument('start_date', type=str, help='Start date in format YYYY-MM')
    visualize_parser.add_argument('--end_date', type=str, help='End date in format YYYY-MM (optional)')
    visualize_parser.add_argument('--timeframe', type=str, default='5m', help='Timeframe for resampling (default: 5m)')
    visualize_parser.add_argument('--sample_rate', type=float, default=0.1, help='Sample rate between 0 and 1 (default: 0.1)')
    visualize_parser.add_argument('--save', type=str, help='Path to save the figure (optional)')
    visualize_parser.add_argument('--data_dir', type=str, help='Data directory (optional)')
    
    args = parser.parse_args()
    
    if args.command == 'download':
        downloader = BinanceMonthlyTradesDownloader(args.output_dir if hasattr(args, 'output_dir') and args.output_dir else None)
        downloader.download(args.start_year, args.start_month)
    
    elif args.command == 'list':
        downloader = BinanceMonthlyTradesDownloader(args.data_dir if hasattr(args, 'data_dir') and args.data_dir else None)
        monthly_dates = downloader.get_available_dates()
        if monthly_dates:
            print(f"\nMonthly data files ({len(monthly_dates)}):")
            for date in monthly_dates:
                print(f"  - {date}")
            print(f"\nDate range: {monthly_dates[0]} to {monthly_dates[-1]}")
        else:
            print("No monthly data files found")
    
    elif args.command == 'aggregate':
        downloader = BinanceMonthlyTradesDownloader(args.data_dir if hasattr(args, 'data_dir') and args.data_dir else None)
        df = downloader.load_trades(args.start_date, args.end_date, args.columns, args.sample_rate)
        
        if df is not None:
            print(f"\nLoaded DataFrame with {len(df):,} rows and {len(df.columns)} columns")
            
            print("\nDataFrame Info:")
            buffer = io.StringIO()
            df.info(buf=buffer)
            print(buffer.getvalue())
            
            print("\nDataFrame Preview:")
            print(tabulate(df.head(20), headers='keys', tablefmt='psql', showindex=True))
            
            print("\nDataFrame Statistics:")
            print(tabulate(df.describe(), headers='keys', tablefmt='psql', showindex=True))
            
            if args.output:
                file_ext = os.path.splitext(args.output)[1].lower()
                if file_ext == '.csv':
                    df.to_csv(args.output, index=False)
                    print(f"Saved to CSV: {args.output}")
                elif file_ext == '.parquet':
                    df.to_parquet(args.output, index=False, engine='pyarrow')
                    print(f"Saved to Parquet: {args.output}")
                else:
                    print(f"Unsupported output format: {file_ext}")
    
    elif args.command == 'visualize':
        downloader = BinanceMonthlyTradesDownloader(args.data_dir if hasattr(args, 'data_dir') and args.data_dir else None)
        print(f"Loading data from {args.start_date} to {args.end_date or args.start_date} (sample rate: {args.sample_rate})")
        df = downloader.load_trades(args.start_date, args.end_date, sample_rate=args.sample_rate)
        
        if df is not None:
            print(f"Visualizing {len(df):,} trades")
            downloader.visualize(df, timeframe=args.timeframe, save_path=args.save)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

