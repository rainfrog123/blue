#!/bin/bash

set -e  # Exit on error

echo "🖥️ Installing VPS-friendly desktop and VNC server..."

# Update system
sudo apt update

# Install XFCE4 (lightweight desktop, perfect for VPS)
sudo DEBIAN_FRONTEND=noninteractive apt install -y xfce4 xfce4-goodies dbus-x11

# Install TigerVNC server
sudo apt install -y tigervnc-standalone-server tigervnc-common

# Create VNC directory
mkdir -p ~/.vnc

# Set VNC password (change 'vncpass123' to your preferred password)
echo "vncpass123" | vncpasswd -f > ~/.vnc/passwd
chmod 600 ~/.vnc/passwd

# Create VNC startup script
cat > ~/.vnc/xstartup << 'EOF'
#!/bin/bash
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
export XKL_XMODMAP_DISABLE=1
exec startxfce4
EOF
chmod +x ~/.vnc/xstartup

# Create VNC config
cat > ~/.vnc/config << 'EOF'
geometry=1920x1080
depth=24
EOF

# Create systemd service for VNC (runs as current user)
sudo bash -c "cat > /etc/systemd/system/vncserver@.service << 'EOF'
[Unit]
Description=TigerVNC server on display %i
After=syslog.target network.target

[Service]
Type=forking
User=root
Group=root
WorkingDirectory=/root
ExecStartPre=/bin/sh -c '/usr/bin/vncserver -kill :%i > /dev/null 2>&1 || :'
ExecStart=/usr/bin/vncserver :%i -localhost no -geometry 1920x1080 -depth 24
ExecStop=/usr/bin/vncserver -kill :%i
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF"

# Reload systemd and enable VNC on display :1 (port 5901)
sudo systemctl daemon-reload
sudo systemctl enable vncserver@1
sudo systemctl start vncserver@1

# Open firewall port 5901 (if ufw is active)
if command -v ufw &> /dev/null; then
    sudo ufw allow 5901/tcp
    echo "✅ UFW: Port 5901 opened"
fi

# Also allow with iptables (in case ufw is not used)
sudo iptables -I INPUT -p tcp --dport 5901 -j ACCEPT 2>/dev/null || true

# Get server IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo "=============================================="
echo "🎉 Desktop + VNC Installation Complete!"
echo "=============================================="
echo ""
echo "📌 Connection Details:"
echo "   VNC Address: ${SERVER_IP}:5901"
echo "   VNC Display: ${SERVER_IP}:1"
echo "   Password:    vncpass123"
echo ""
echo "🔧 To change VNC password run: vncpasswd"
echo ""
echo "📱 Connect using any VNC client:"
echo "   - RealVNC Viewer"
echo "   - TigerVNC Viewer"  
echo "   - Remmina (Linux)"
echo "=============================================="
