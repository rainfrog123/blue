version: "3.8"

services:

  aria2-pro:
    container_name: aria2-pro
    image: p3terx/aria2-pro
    environment:
      - PUID=65534
      - PGID=65534
      - UMASK_SET=022
      - RPC_SECRET=aria2
      - RPC_PORT=6800
      - LISTEN_PORT=6888
      - DISK_CACHE=64M
      - IPV6_MODE=false
      - UPDATE_TRACKERS=true
      - CUSTOM_TRACKER_URL=
      - TZ=Asia/Shanghai
    volumes:
      - ${PWD}/aria2-config:/config
      - ${PWD}/aria2-downloads:/downloads
    ports:
      - 8080:6800 # Changed to 8080 for Cloudflare
      - 2052:6888 # Changed to 2052 for Cloudflare
      - 2052:6888/udp # Changed to 2052 for Cloudflare
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: 1m

  ariang:
    container_name: ariang
    image: p3terx/ariang
    command: --port 6880 --ipv6
    ports:
      - 2095:6880 # Changed to 2095 for Cloudflare
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: 1m

  filebrowser:
    image: hurlenko/filebrowser
    container_name: filebrowser
    volumes:
      - ${PWD}/filebrowser-data:/data
      - ${PWD}/filebrowser-config:/data/config
      - ${PWD}/aria2-downloads:/data/downloads # This mounts the aria2-downloads to /downloads in the container
    ports:
      - "2086:8080"
    environment:
      - FB_BASEURL=/filebrowser
      - FB_ROOT=/downloads # Optional: Set this to change the root directory that Filebrowser will use
    restart: always
