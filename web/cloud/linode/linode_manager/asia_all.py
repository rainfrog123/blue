import os
import time
import paramiko
from typing import List
import concurrent.futures
from linode_manager import LinodeManager

SETUP_SCRIPT = """#!/bin/bash
set -e
LOG_FILE="/var/log/setup_script.log"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }
log "Starting automated setup..."
export DEBIAN_FRONTEND=noninteractive
sudo apt update -y && sudo apt upgrade -y
sudo apt install -y docker.io docker-compose tmux htop x11-apps
sudo docker pull teddysun/shadowsocks-r
sudo mkdir -p /etc/shadowsocks-r/
sudo bash -c 'cat > /etc/shadowsocks-r/config.json <<EOF
{
    "server":"0.0.0.0",
    "server_ipv6":"::",
    "server_port":19000,
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"bxsnucrgk6hfish",
    "timeout":120,
    "method":"chacha20-ietf",
    "protocol":"auth_aes128_sha1",
    "protocol_param":"",
    "obfs":"plain",
    "obfs_param":"",
    "redirect":"",
    "dns_ipv6":false,
    "fast_open":true,
    "workers":5
}
EOF'
sudo docker run -d -p 19000:19000 -p 19000:19000/udp --name ssr --restart=always -v /etc/shadowsocks-r:/etc/shadowsocks-r teddysun/shadowsocks-r
echo "net.core.default_qdisc = fq" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control = bbr" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
echo 'PS1="\\[\\033[1;32m\\]\\u\\[\\033[0m\\]@\\[\\033[1;34m\\]\\h\\[\\033[0m\\] \\[\\e[1;34m\\]\\w\\[\\e[0m\\] 🚀🚀🚀  $ "' >> ~/.bashrc
sudo mkdir -p /allah
git config --global user.name "$(openssl rand -hex 12)"
git config --global user.email "$(openssl rand -hex 12)@example.com"
cd /allah
git clone https://github.com/rainfrog123/stuff.git
mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys
if ! grep -q "jeffrey" ~/.ssh/authorized_keys; then
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5yrqQ9Eq4di8Aalzv0OZLU8LBPXwm2CjSDl3e4LDFQK16M5baWxZb4cd5YytRJBcal28nWiZiYKcJjW7sNUuU5gmij9fBWgvX2r4Rhm7vvt8K5a1gJkcfermkJnfnImBrWHiMfOigpcfFvblYlEcXgvrIKfMeZMJ3PxRfkHEXST2PfS/nqJKZEYB6Du32Nr3LsXisJ4WLJ2la8q7Zj0kM3QW9AeBNgFLKgsez4Y8KWrlQotbgUBkxZm7vUq0aRvFBtIN24DzCjWEm9jMn6UE4d1Bad/fwqdji8cjDcINb9TN8h0oNqG2skP7jOC8tHDMhlRiP90ZtrTBamfp6lldmMQgIAY+CWxRru4Dbbtjn9ikwlcWlyRJN1PwnAbmbYzGaE/rQ7ohwNiH1b7f+znIPayFkm56yYodFjKush6/S16v5P9bgNNIrWMQ08FLYms8PeLxCXz6ZGH6bET6mvkN8Tg4GA7DlzdbaBnCBRxbaIAmA89svFk7fa/tJT8KEBsU= jeffrey" >> ~/.ssh/authorized_keys
    chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
fi
log "Setup completed successfully!"
"""

class AsiaDeployer:
    def __init__(self, api_token: str):
        self.manager = LinodeManager(api_token)
        self.root_pass = "4dwlq5!H4uA26A8"
        # All regions in JP, SG, AU
        self.target_regions = [
            # "jp-osa",      # Osaka, JP
            # "jp-tyo-3",    # Tokyo 3, JP
            # "ap-northeast", # Tokyo 2, JP
            # "sg-sin-2",    # Singapore 2, SG
            # "ap-south",    # Singapore, SG
            # "ap-southeast", # Sydney, AU
            # "au-mel",      # Melbourne, AU
        ]

    def deploy_instance(self, region: str) -> dict:
        """Deploy a single instance in the specified region."""
        try:
            # Add region code to label for better identification
            instance = self.manager.create_instance(
                label=f"linode-{region}-{int(time.time())}",
                region=region,
                type_id="g6-nanode-1",
                root_pass=self.root_pass
            )
            
            print(f"Created instance in {region}: ID {instance.id}")
            return {"id": instance.id, "ip": instance.ipv4[0], "region": region}
        except Exception as e:
            print(f"Failed to create instance in {region}: {str(e)}")
            return None

    def wait_for_running(self, instance_id: int, timeout: int = 300) -> bool:
        """Wait for instance to be in running state."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            instance = self.manager.get_instance(instance_id)
            if instance and instance.status == "running":
                return True
            time.sleep(10)
        return False

    def setup_instance(self, ip: str) -> bool:
        """Configure the instance with SSH and run setup script."""
        try:
            # Wait for SSH to be available
            time.sleep(30)
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Try to connect multiple times
            for _ in range(3):
                try:
                    ssh.connect(ip, username='root', password=self.root_pass)
                    break
                except Exception:
                    time.sleep(10)
            
            # Upload and execute setup script
            sftp = ssh.open_sftp()
            with sftp.file('/root/setup.sh', 'w') as f:
                f.write(SETUP_SCRIPT)
            
            ssh.exec_command('chmod +x /root/setup.sh')
            stdin, stdout, stderr = ssh.exec_command('/root/setup.sh')
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status == 0:
                print(f"Setup completed successfully on {ip}")
                return True
            else:
                print(f"Setup failed on {ip}: {stderr.read().decode()}")
                return False
                
        except Exception as e:
            print(f"Failed to setup instance {ip}: {str(e)}")
            return False
        finally:
            try:
                ssh.close()
            except:
                pass

    def deploy_all(self):
        """Deploy instances in all target regions."""
        print("Starting deployment in Asian regions...")
        
        # Deploy instances
        instances = []
        for region in self.target_regions:
            instance = self.deploy_instance(region)
            if instance:
                instances.append(instance)
        
        # Wait for instances to be running
        running_instances = []
        for instance in instances:
            if self.wait_for_running(instance["id"]):
                running_instances.append(instance)
                print(f"Instance {instance['id']} is running")
            else:
                print(f"Instance {instance['id']} failed to start")
        
        # Setup running instances
        for instance in running_instances:
            if self.setup_instance(instance["ip"]):
                print(f"Instance {instance['id']} setup completed")
            else:
                print(f"Instance {instance['id']} setup failed")

def main():
    import sys
    sys.path.insert(0, str(__import__('pathlib').Path(__file__).parents[4] / 'linux' / 'extra' / 'config'))
    from cred_loader import get_linode_token
    api_token = get_linode_token(0)
    deployer = AsiaDeployer(api_token)
    deployer.deploy_all()

if __name__ == "__main__":
    main() 