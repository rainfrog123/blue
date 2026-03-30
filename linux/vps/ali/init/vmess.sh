#!/bin/bash
sudo mkdir -p /etc/xray

sudo tee /etc/xray/config.json > /dev/null << 'EOF'
{
  "inbounds": [
    {
      "port": 30201,
      "listen": "0.0.0.0",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "bb553795-6a8f-493c-960c-12a6f2f65eee",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/",
          "headers": {
            "Host": "live.bilibili.com"
          }
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "settings": {} },
    { "protocol": "blackhole", "settings": {}, "tag": "blocked" }
  ]
}
EOF

sudo docker rm -f xray 2>/dev/null
sudo docker run -d \
  --name xray \
  --restart=always \
  -p 30201:30201/tcp -p 30201:30201/udp \
  -v /etc/xray:/etc/xray \
  teddysun/xray

echo "Done. Client config:"
echo "server: hk.edgesoftware.xyz, port: 30201, uuid: bb553795-6a8f-493c-960c-12a6f2f65eee"
