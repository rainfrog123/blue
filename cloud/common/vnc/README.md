# TigerVNC + XFCE4 Setup Guide

**Server:** blue (Ubuntu 24.04.4 LTS)  
**Date:** 2026-04-30  
**VNC Server:** TigerVNC 1.13.1  
**Desktop Environment:** XFCE4  

---

## Connection Details

### Primary Session (Display :1, Port 5901)

| Property | Value |
|----------|-------|
| **IP Address** | `129.212.209.177` |
| **VNC Port** | `5901` |
| **VNC Display** | `:1` |
| **Resolution** | 1920x1080 |
| **Color Depth** | 24-bit |
| **VNC Password** | `vncpass123` |

```
Address: 129.212.209.177:5901
Password: vncpass123
```

---

### Secure Session (Display :2, Port 5902) ⭐ RECOMMENDED

| Property | Value |
|----------|-------|
| **IP Address** | `129.212.209.177` |
| **VNC Port** | `5902` |
| **VNC Display** | `:2` |
| **Resolution** | 1920x1080 |
| **Color Depth** | 24-bit |
| **VNC Password** | `lBoI6Ob6rD0s5MKO` |
| **Linux User** | `vncuser` |
| **User Password** | `vncuser123` |
| **Password File** | `/home/vncuser/.vnc/passwd` |

```
Address: 129.212.209.177:5902
Password: lBoI6Ob6rD0s5MKO
```

### How to Connect

Use any VNC client (RealVNC, TigerVNC Viewer, Remmina, etc.):

Command line:
```bash
vncviewer 129.212.209.177:5902
```

---

## Installed Packages

```bash
apt install -y xfce4 xfce4-goodies tigervnc-standalone-server tigervnc-common dbus-x11
```

---

## Configuration Files

### VNC Password Location
```
/root/.vnc/passwd
```

### VNC Startup Script
**Path:** `/root/.vnc/xstartup`

```bash
#!/bin/bash
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS

export XDG_SESSION_TYPE=x11
export XDG_CURRENT_DESKTOP=XFCE

[ -r $HOME/.Xresources ] && xrdb $HOME/.Xresources

exec startxfce4
```

### Systemd Service (Primary - Display :1)
**Path:** `/etc/systemd/system/vncserver@.service`

```ini
[Unit]
Description=TigerVNC Server for display %i
After=syslog.target network.target

[Service]
Type=forking
User=root
Group=root
WorkingDirectory=/root

ExecStartPre=/bin/sh -c '/usr/bin/vncserver -kill :%i > /dev/null 2>&1 || :'
ExecStart=/usr/bin/vncserver :%i -geometry 1920x1080 -depth 24 -localhost no
ExecStop=/usr/bin/vncserver -kill :%i

[Install]
WantedBy=multi-user.target
```

### Systemd Service (Secure - Display :2)
**Path:** `/etc/systemd/system/vncserver-secure@.service`

```ini
[Unit]
Description=TigerVNC Secure Server for display %i
After=syslog.target network.target

[Service]
Type=forking
User=vncuser
Group=vncuser
WorkingDirectory=/home/vncuser

ExecStartPre=/bin/sh -c '/usr/bin/vncserver -kill :%i > /dev/null 2>&1 || :'
ExecStart=/usr/bin/vncserver :%i -geometry 1920x1080 -depth 24 -localhost no
ExecStop=/usr/bin/vncserver -kill :%i

[Install]
WantedBy=multi-user.target
```

---

## Management Commands

### Start VNC Server
```bash
# Primary (port 5901)
systemctl start vncserver@1

# Secure (port 5902) - RECOMMENDED
systemctl start vncserver-secure@2

# Manual
vncserver :1 -geometry 1920x1080 -depth 24 -localhost no
vncserver :2 -geometry 1920x1080 -depth 24 -localhost no -rfbauth /root/.vnc2/passwd
```

### Stop VNC Server
```bash
# Primary
systemctl stop vncserver@1

# Secure
systemctl stop vncserver-secure@2

# Manual
vncserver -kill :1
vncserver -kill :2
```

### Check Status
```bash
# Primary
systemctl status vncserver@1

# Secure
systemctl status vncserver-secure@2

# List active VNC sessions
vncserver -list
```

### View Logs
```bash
cat /root/.vnc/blue:1.log
cat /root/.vnc/blue:2.log
journalctl -u vncserver@1
journalctl -u vncserver-secure@2
```

### Change VNC Password
```bash
# Primary session password
vncpasswd

# Secure session password
vncpasswd /root/.vnc2/passwd
```

### Enable/Disable Auto-start
```bash
# Enable on boot
systemctl enable vncserver@1
systemctl enable vncserver-secure@2

# Disable on boot
systemctl disable vncserver@1
systemctl disable vncserver-secure@2
```

---

## Errors Encountered & Solutions

### Error 1: Session Startup Exited Too Early

**Error Message:**
```
Session startup via '/root/.vnc/xstartup' cleanly exited too early (< 3 seconds)!
```

**Cause:** Initial xstartup script used `dbus-launch --exit-with-session startxfce4 &` which ran in background and caused the session to appear as exited.

**Solution:** Changed xstartup to use `exec startxfce4` (foreground, replaces shell process).

---

### Error 2: Cannot Open Display

**Error Message:**
```
xfce4-session: Cannot open display: .
/usr/bin/startxfce4: X server already running on display :1
xrdb: Connection refused
```

**Cause:** The DISPLAY environment variable wasn't being set properly, and dbus wasn't launching correctly.

**Solution:** Simplified the xstartup script:
- Removed manual dbus-launch (XFCE handles this internally)
- Used `exec startxfce4` directly
- Added `XDG_CURRENT_DESKTOP=XFCE` export

---

### Error 3: VNC Bound to Localhost Only

**Symptom:** VNC server starts but can't connect from remote machine.

**Cause:** TigerVNC defaults to `-localhost=1` for security.

**Solution:** Start VNC with `-localhost no` flag:
```bash
vncserver :1 -localhost no
```

---

### Warning: XKB Keysym Warnings (Non-Fatal)

**Messages:**
```
Warning: Could not resolve keysym XF86CameraAccessEnable
Warning: Could not resolve keysym XF86CameraAccessDisable
...
```

**Status:** These are harmless warnings about missing keysym definitions for special function keys (camera, fishing chart, radar, etc.). They don't affect normal operation.

---

## Security Considerations

1. **VNC Password:** Change the default password immediately:
   ```bash
   vncpasswd
   ```

2. **Firewall:** Consider restricting port 5901 to trusted IPs:
   ```bash
   apt install ufw
   ufw allow from YOUR_IP to any port 5901
   ufw enable
   ```

3. **SSH Tunneling (More Secure):** Instead of exposing VNC directly:
   ```bash
   # On server, start VNC with localhost only:
   vncserver :1 -localhost yes
   
   # On client, create SSH tunnel:
   ssh -L 5901:localhost:5901 root@129.212.209.177
   
   # Then connect VNC to localhost:5901
   ```

---

## Troubleshooting

### Black Screen After Connect
```bash
# Check if XFCE is running
ps aux | grep xfce

# Check VNC log
tail -50 /root/.vnc/blue:1.log

# Restart VNC
vncserver -kill :1
vncserver :1 -geometry 1920x1080 -depth 24 -localhost no
```

### Connection Refused
```bash
# Check if VNC is listening
ss -tlnp | grep 5901

# Check firewall
iptables -L INPUT -n
```

### Slow Performance
- Reduce resolution: `-geometry 1280x720`
- Reduce color depth: `-depth 16`
- Use compression in your VNC client

---

## Additional Displays

To run multiple VNC sessions on different displays:

```bash
# Display :2 on port 5902
vncserver :2 -geometry 1920x1080 -depth 24 -localhost no

# Display :3 on port 5903
vncserver :3 -geometry 1920x1080 -depth 24 -localhost no
```

---

## Quick Reference

| Display | Port | Command |
|---------|------|---------|
| :1 | 5901 | `vncserver :1` |
| :2 | 5902 | `vncserver :2` |
| :3 | 5903 | `vncserver :3` |

Formula: **Port = 5900 + Display Number**
