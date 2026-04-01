#!/usr/bin/env python3
"""
HLS Video Downloader
Downloads videos from pages containing DPlayer with HLS streams.

Usage:
    python download_hls.py <page_url> [output_name]

Example:
    python download_hls.py https://www.mrds66.com/archives/171859/
    python download_hls.py https://www.mrds66.com/archives/171859/ my_video
"""

import subprocess
import sys
import re
import requests
from pathlib import Path
from urllib.parse import urlparse

OUTPUT_DIR = "/media/videos"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"


def fetch_page(page_url: str) -> str | None:
    """Fetch page HTML."""
    headers = {"User-Agent": USER_AGENT}
    
    try:
        response = requests.get(page_url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching page: {e}")
        return None


def extract_m3u8_url(html: str) -> str | None:
    """Extract m3u8 URL from page HTML."""
    # Look for DPlayer data-config attribute (handles both single and double quotes)
    config_match = re.search(r"data-config='([^']+)'", html)
    if not config_match:
        config_match = re.search(r'data-config="([^"]+)"', html)
    
    if config_match:
        config = config_match.group(1)
        # Extract m3u8 URL from config (handles escaped slashes like \/)
        m3u8_match = re.search(r'https?:[\\]?/[\\]?/[^"]+\.m3u8[^"]*', config)
        if m3u8_match:
            url = m3u8_match.group(0).replace("\\/", "/")
            return url
    
    # Fallback: search entire HTML for m3u8 URLs
    m3u8_match = re.search(r'https?://[^\s"\'<>]+\.m3u8[^\s"\'<>]*', html)
    if m3u8_match:
        return m3u8_match.group(0)
    
    return None


def extract_title(html: str) -> str | None:
    """Extract page title from HTML."""
    # Try <title> tag first
    title_match = re.search(r'<title>([^<]+)</title>', html)
    if title_match:
        title = title_match.group(1)
        # Remove site name suffix (e.g., " - 每日大赛")
        title = re.sub(r'\s*[-|].*$', '', title)
        return title.strip()
    
    # Try <h1> tag
    h1_match = re.search(r'<h1[^>]*>([^<]+)</h1>', html)
    if h1_match:
        return h1_match.group(1).strip()
    
    return None


def sanitize_filename(name: str) -> str:
    """Remove invalid characters from filename."""
    # Remove/replace invalid filename characters
    name = re.sub(r'[<>:"/\\|?*]', '', name)
    name = re.sub(r'\s+', ' ', name)
    name = name.strip()
    # Limit length
    if len(name) > 100:
        name = name[:100]
    return name


def get_output_filename(page_url: str, title: str | None = None, custom_name: str | None = None) -> str:
    """Generate output filename from title, URL, or custom name."""
    if custom_name:
        name = custom_name
    elif title:
        name = sanitize_filename(title)
    else:
        # Fallback: extract ID from URL path (e.g., /archives/171859/ -> 171859)
        path = urlparse(page_url).path
        match = re.search(r'/(\d+)/?$', path)
        if match:
            name = match.group(1)
        else:
            name = "video"
    
    if not name.endswith(".mp4"):
        name += ".mp4"
    
    return str(Path(OUTPUT_DIR) / name)


def download_video(m3u8_url: str, output_path: str, referer: str) -> bool:
    """Download HLS video using yt-dlp."""
    cmd = [
        "yt-dlp",
        m3u8_url,
        "--referer", referer,
        "--user-agent", USER_AGENT,
        "-o", output_path,
        "--no-warnings",
    ]
    
    print(f"Downloading to: {output_path}")
    print(f"M3U8 URL: {m3u8_url[:80]}...")
    print()
    
    try:
        result = subprocess.run(cmd, check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"Download failed: {e}")
        return False
    except FileNotFoundError:
        print("Error: yt-dlp not found. Install with: pip install yt-dlp")
        return False


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    page_url = sys.argv[1]
    custom_name = sys.argv[2] if len(sys.argv) > 2 else None
    
    print(f"Fetching: {page_url}")
    
    html = fetch_page(page_url)
    if not html:
        sys.exit(1)
    
    m3u8_url = extract_m3u8_url(html)
    if not m3u8_url:
        print("Error: Could not find m3u8 URL in page")
        sys.exit(1)
    
    title = extract_title(html)
    if title:
        print(f"Title: {title}")
    
    output_path = get_output_filename(page_url, title, custom_name)
    
    success = download_video(m3u8_url, output_path, page_url)
    
    if success:
        print(f"\nDone! Saved to: {output_path}")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
