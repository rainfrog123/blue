# HLS Video Download Guide

## Directory Structure

```
/media/
├── download-hls.md      # This documentation
├── scripts/
│   └── download_hls.py  # Auto-download script
└── videos/              # Downloaded videos
```

## Prerequisites

```bash
pip install yt-dlp requests
apt install -y ffmpeg
```

## Quick Start

```bash
# Download video (auto-extracts title for filename)
python3 /media/scripts/download_hls.py "PAGE_URL"

# Example
python3 /media/scripts/download_hls.py "https://www.mrds66.com/archives/170930/"
```

## Python Script Usage

The script automatically:
1. Fetches the page
2. Extracts the m3u8 URL from DPlayer config
3. Extracts the page title for filename
4. Downloads using yt-dlp

```bash
# Basic usage (filename from page title)
python3 /media/scripts/download_hls.py "https://www.mrds66.com/archives/171859/"

# Custom output name
python3 /media/scripts/download_hls.py "https://www.mrds66.com/archives/171859/" my_video
```

Output saved to: `/media/videos/`

## Manual Methods

### Method 1: Extract m3u8 URL from Page Source

For sites using DPlayer, the m3u8 URL is embedded in HTML:

```bash
curl -sL "PAGE_URL" | \
  grep -oP "data-config='\K[^']+" | \
  grep -oP 'https:\\/\\/[^"]+\.m3u8[^"]*' | \
  sed 's/\\//g'
```

### Method 2: Browser DevTools

1. Open the video page in Chrome
2. Press F12 to open DevTools
3. Go to **Network** tab
4. Filter by **Media** or search for `.m3u8`
5. Play the video
6. Right-click the m3u8 request → **Copy** → **Copy URL**

## Manual Download Commands

### Using yt-dlp

```bash
yt-dlp "M3U8_URL" \
  --referer "PAGE_URL" \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36" \
  -o "/media/videos/OUTPUT.mp4"
```

### Using ffmpeg

```bash
ffmpeg -headers "Referer: PAGE_URL" \
  -user_agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36" \
  -i "M3U8_URL" \
  -c copy /media/videos/OUTPUT.mp4
```

## Notes

- **ffmpeg is required** for AES-128 encrypted streams (most HLS streams)
- Without ffmpeg, decryption is extremely slow
- The `auth_key` in URLs usually expires, so download promptly
- Use `--referer` to match the original page (some servers check this)

## Supported Sites

- Sites using DPlayer with HLS streams
- mrds66.com (tested)

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Could not find m3u8 URL" | Site may load video dynamically via JS; use browser DevTools |
| Slow download | Ensure ffmpeg is installed for HLS decryption |
| 403 Forbidden | Check referer header matches the page URL |
| auth_key expired | Re-fetch the page to get fresh URL |
