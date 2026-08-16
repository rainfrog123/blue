import paramiko

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(
    "127.0.0.1",
    port=2222,
    username="mobile",
    password="971203",
    timeout=8,
    look_for_keys=False,
    allow_agent=False,
)
cmd = r"""echo 971203 | sudo -S -p '' sh -c '
export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:$PATH
if /var/jb/usr/bin/pgrep -x frida-server >/dev/null 2>&1 || /var/jb/bin/pgrep -x frida-server >/dev/null 2>&1; then
  echo already_running
else
  /var/jb/usr/sbin/frida-server -l 0.0.0.0:27042 >/tmp/frida-server.log 2>&1 &
  echo started
fi
sleep 1
/var/jb/usr/bin/pgrep -af frida-server || /var/jb/bin/pgrep -af frida-server || echo no_pgrep
'"""
_, out, err = c.exec_command(cmd)
print(out.read().decode())
print(err.read().decode())
c.close()
