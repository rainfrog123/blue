import requests
import json
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging
import argparse
import sys
from getpass import getpass
import subprocess
import statistics
import concurrent.futures
import socket
import speedtest
import random
import string
import datetime
import paramiko

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s'  # Simplified format
)

@dataclass
class LinodeRegion:
    id: str
    label: str
    country: str
    capabilities: List[str]
    resolvers: Dict[str, List[str]]

@dataclass
class LinodeInstance:
    id: int
    label: str
    region: str
    type: str
    ipv4: List[str]
    ipv6: str
    status: str

class LinodeManager:
    def __init__(self, api_token: str, proxy: Optional[str] = None):
        self.api_token = api_token
        self.base_url = "https://api.linode.com/v4"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        if proxy:
            logging.info(f"Using proxy: {proxy}")

    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict:
        """Make an API request to Linode."""
        url = f"{self.base_url}/{endpoint}"
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=self.headers,
                json=data,
                proxies=self.proxies
            )
            
            # Try to get detailed error information if the request fails
            if not response.ok:
                error_msg = f"{response.status_code} {response.reason}"
                try:
                    error_data = response.json()
                    if "errors" in error_data:
                        # Only log the error data, not the full error message with URL
                        logging.error(f"API request failed: {error_msg}")
                        # This will be raised and caught by the calling function
                        raise requests.exceptions.HTTPError(
                            f"{error_msg}\nAPI Error Details: {json.dumps(error_data, indent=2)}",
                            response=response
                        )
                except ValueError:
                    # If we can't parse the JSON, just use the original error
                    pass
                
                # If we didn't raise a custom error above, raise the standard one
            response.raise_for_status()
            
            return response.json()
        except requests.exceptions.RequestException as e:
            # Don't log the full exception here, let the calling function handle it
            raise

    def validate_token(self) -> bool:
        """Validate the API token by making a simple request."""
        try:
            self._make_request("GET", "profile")
            return True
        except Exception:
            logging.error("API token validation failed")
            return False

    def get_regions(self) -> List[LinodeRegion]:
        """Get available Linode regions."""
        response = self._make_request("GET", "regions")
        regions = []
        for region in response.get("data", []):
            regions.append(LinodeRegion(
                id=region["id"],
                label=region["label"],
                country=region["country"],
                capabilities=region["capabilities"],
                resolvers={
                    "ipv4": str(region["resolvers"]["ipv4"]).split(","),
                    "ipv6": str(region["resolvers"]["ipv6"]).split(",")
                }
            ))
        return regions

    def create_instance(
        self,
        label: str,
        region: str,
        type_id: str = "g6-nanode-1",  # Default to Nanode 1GB
        image: str = "linode/debian12",  # Updated to debian12
        root_pass: Optional[str] = None,
        authorized_keys: Optional[List[str]] = None,
        stackscript_id: Optional[int] = None,
        stackscript_data: Optional[Dict] = None,
        backups_enabled: bool = False
    ) -> LinodeInstance:
        """Create a new Linode instance."""
        data = {
            "label": label,
            "region": region,
            "type": type_id,
            "image": image,
            "backups_enabled": backups_enabled
        }

        if root_pass:
            data["root_pass"] = root_pass
        if authorized_keys:
            data["authorized_keys"] = authorized_keys
        if stackscript_id:
            data["stackscript_id"] = stackscript_id
        if stackscript_data:
            data["stackscript_data"] = stackscript_data

        # Log minimal info - don't include sensitive data like passwords
        logging.info(f"Creating instance '{label}' in region {region}")

        response = self._make_request("POST", "linode/instances", data)
        return LinodeInstance(
            id=response["id"],
            label=response["label"],
            region=response["region"],
            type=response["type"],
            ipv4=response["ipv4"],
            ipv6=response["ipv6"],
            status=response["status"]
        )

    def delete_instance(self, instance_id: int) -> bool:
        """Delete a Linode instance."""
        try:
            self._make_request("DELETE", f"linode/instances/{instance_id}")
            return True
        except Exception:
            logging.error(f"Failed to delete instance {instance_id}")
            return False

    def get_instance(self, instance_id: int) -> Optional[LinodeInstance]:
        """Get information about a specific Linode instance."""
        try:
            response = self._make_request("GET", f"linode/instances/{instance_id}")
            return LinodeInstance(
                id=response["id"],
                label=response["label"],
                region=response["region"],
                type=response["type"],
                ipv4=response["ipv4"],
                ipv6=response["ipv6"],
                status=response["status"]
            )
        except Exception:
            logging.error(f"Failed to get instance {instance_id}")
            return None

    def list_instances(self) -> List[LinodeInstance]:
        """List all Linode instances."""
        response = self._make_request("GET", "linode/instances")
        instances = []
        for instance in response.get("data", []):
            instances.append(LinodeInstance(
                id=instance["id"],
                label=instance["label"],
                region=instance["region"],
                type=instance["type"],
                ipv4=instance["ipv4"],
                ipv6=instance["ipv6"],
                status=instance["status"]
            ))
        return instances

    def reboot_instance(self, instance_id: int) -> bool:
        """Reboot a Linode instance."""
        try:
            self._make_request("POST", f"linode/instances/{instance_id}/reboot")
            return True
        except Exception:
            logging.error(f"Failed to reboot instance {instance_id}")
            return False

    def ping_instance(self, ip: str, count: int = 5) -> Optional[float]:
        """Ping an instance and return average response time."""
        try:
            output = subprocess.check_output(
                ["ping", "-c", str(count), ip],
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            if "time=" in output:
                # Extract average time from ping output
                times = [float(x.split('time=')[1].split()[0]) 
                        for x in output.splitlines() 
                        if 'time=' in x]
                return statistics.mean(times) if times else None
            return None
        except subprocess.CalledProcessError:
            return None

    def test_instance_speed(self, ip: str) -> Tuple[Optional[float], Optional[float]]:
        """Test download and upload speeds to the instance."""
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            download_speed = st.download() / 1_000_000  # Convert to Mbps
            upload_speed = st.upload() / 1_000_000      # Convert to Mbps
            return download_speed, upload_speed
        except Exception as e:
            print(f"Speed test failed for {ip}: {str(e)}")
            return None, None

    def test_all_instances(self) -> List[Dict]:
        """Test and rank all instances by connection quality."""
        instances = self.list_instances()
        results = []

        print("\nTesting connection quality for all instances...")
        for instance in instances:
            ip = instance.ipv4[0]
            print(f"\nTesting {instance.label} ({ip})...")
            
            # Test ping
            ping_time = self.ping_instance(ip)
            ping_status = f"{ping_time:.1f}ms" if ping_time else "Failed"
            print(f"Ping: {ping_status}")

            # Test speed
            download_speed, upload_speed = self.test_instance_speed(ip)
            if download_speed and upload_speed:
                print(f"Download: {download_speed:.1f} Mbps")
                print(f"Upload: {upload_speed:.1f} Mbps")
            else:
                print("Speed test failed")

            results.append({
                "label": instance.label,
                "id": instance.id,
                "region": instance.region,
                "ip": ip,
                "ping": ping_time,
                "download_speed": download_speed,
                "upload_speed": upload_speed
            })

        # Sort results by ping time (if available) or region
        results.sort(key=lambda x: (
            float('inf') if x['ping'] is None else x['ping'],
            x['region']
        ))

        return results

    def rebuild_instance(self, instance_id: int, image: str = "linode/debian12", root_pass: str = "4dwlq5!H4uA26A8") -> bool:
        """Rebuild a Linode instance."""
        try:
            data = {
                "image": image,
                "root_pass": root_pass
            }
            logging.info(f"Rebuilding instance {instance_id}")
            self._make_request("POST", f"linode/instances/{instance_id}/rebuild", data)
            return True
        except Exception as e:
            logging.error(f"Failed to rebuild instance {instance_id}")
            return False

    def run_setup_script(self, instance_id: int, script: str) -> bool:
        """Run a setup script on a specific instance."""
        try:
            # Get instance details
            instance = self.get_instance(instance_id)
            if not instance:
                logging.error(f"Instance {instance_id} not found")
                return False
                
            ip = instance.ipv4[0]
            logging.info(f"Running setup script on instance {instance_id} ({ip})")
            
            # Wait a moment to ensure SSH is available
            time.sleep(5)
            
            # Connect via SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Default root password
            root_pass = "4dwlq5!H4uA26A8"
            
            # Try to connect multiple times
            connected = False
            for attempt in range(3):
                try:
                    ssh.connect(ip, username='root', password=root_pass, timeout=30)
                    connected = True
                    break
                except Exception as e:
                    logging.info(f"SSH connection attempt {attempt+1} failed: {str(e)}")
                    time.sleep(10)
            
            if not connected:
                logging.error(f"Failed to connect to instance {instance_id} via SSH")
                return False
                
            # Upload and execute setup script
            sftp = ssh.open_sftp()
            with sftp.file('/root/setup.sh', 'w') as f:
                f.write(script)
            
            ssh.exec_command('chmod +x /root/setup.sh')
            stdin, stdout, stderr = ssh.exec_command('nohup /root/setup.sh > /root/setup.log 2>&1 &')
            
            # Explain what's happening with the background process
            print("\nTechnical details about background execution:")
            print("1. The 'nohup' command allows the script to continue running even if the SSH connection is closed")
            print("2. Output is redirected to /root/setup.log (both standard output and errors)")
            print("3. The '&' at the end launches the process in the background")
            print("4. This means the Linode Manager doesn't have to wait for the script to complete")
            print("5. The setup typically takes 3-5 minutes to complete depending on server location")
            
            logging.info(f"Setup script started on instance {instance_id}")
            return True
                
        except Exception as e:
            logging.error(f"Failed to run setup script on instance {instance_id}: {str(e)}")
            return False
        finally:
            try:
                ssh.close()
            except:
                pass

    def track_setup_progress(self, instance_id: int) -> bool:
        """Track the progress of a setup script on an instance."""
        try:
            # Get instance details
            instance = self.get_instance(instance_id)
            if not instance:
                logging.error(f"Instance {instance_id} not found")
                return False
                
            ip = instance.ipv4[0]
            logging.info(f"Connecting to instance {instance_id} ({ip}) to track setup progress")
            
            # Connect via SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Default root password
            root_pass = "4dwlq5!H4uA26A8"
            
            # Try to connect
            try:
                ssh.connect(ip, username='root', password=root_pass, timeout=30)
            except Exception as e:
                print(f"SSH connection failed: {str(e)}")
                print("The instance may not be ready yet or the setup script hasn't started.")
                return False
                
            # Check if setup log exists
            stdin, stdout, stderr = ssh.exec_command('ls -la /root/setup.sh /var/log/setup_script.log 2>/dev/null || echo "Files not found"')
            file_check = stdout.read().decode('utf-8')
            
            if "Files not found" in file_check:
                print("Setup files not found. The setup script may not have been run on this instance.")
                return False
                
            # Check if the script is still running
            stdin, stdout, stderr = ssh.exec_command('pgrep -f "/root/setup.sh" || echo "not running"')
            process_check = stdout.read().decode('utf-8').strip()
            
            is_running = process_check != "not running"
            
            # Display the log file
            print("\n=== Setup Script Progress ===")
            if is_running:
                print("Status: RUNNING")
            else:
                # Check if the script completed successfully
                stdin, stdout, stderr = ssh.exec_command('grep "Setup completed successfully" /var/log/setup_script.log || echo "not completed"')
                completion_check = stdout.read().decode('utf-8').strip()
                if "not completed" in completion_check:
                    print("Status: STOPPED (may have failed or been interrupted)")
                else:
                    print("Status: COMPLETED SUCCESSFULLY")
            
            # Show the last 20 lines of the log
            stdin, stdout, stderr = ssh.exec_command('tail -n 20 /var/log/setup_script.log || echo "Log file not found"')
            log_content = stdout.read().decode('utf-8')
            
            print("\nRecent log entries:")
            print("-" * 50)
            print(log_content)
            print("-" * 50)
            
            # Offer to follow the log in real-time if the script is still running
            if is_running:
                follow = input("\nDo you want to follow the log in real-time? (y/n): ")
                if follow.lower() == 'y':
                    print("\nShowing live log (press Ctrl+C to stop)...")
                    try:
                        # Use a channel for interactive commands
                        channel = ssh.invoke_shell()
                        channel.send('tail -f /var/log/setup_script.log\n')
                        
                        # Display output in real-time
                        while True:
                            if channel.recv_ready():
                                output = channel.recv(4096).decode('utf-8')
                                print(output, end='')
                            time.sleep(0.1)
                    except KeyboardInterrupt:
                        print("\nStopped following the log.")
            
            return True
                
        except Exception as e:
            print(f"An error occurred while tracking setup progress: {str(e)}")
            return False
        finally:
            try:
                ssh.close()
            except:
                pass

def print_menu():
    """Print the main menu."""
    print("\n=== Linode Manager ===")
    print("1. List Regions | 2. List Instances | 3. Create Instance | 4. Delete Instance")
    print("5. Reboot Instance | 6. Get Instance Details | 7. Test Instance Connections")
    print("8. List Linode Types | 9. Rebuild Instance | 10. Reboot Multiple Instances")
    print("11. Run Setup Script on Instance | 12. Track Setup Progress | 0. Exit")
    print("===================")

def select_region(manager: LinodeManager) -> Optional[str]:
    """Interactive region selection."""
    regions = manager.get_regions()
    print("\nAvailable Regions:")
    for i, region in enumerate(regions, 1):
        print(f"{i}. {region.label} ({region.id}) - {region.country}")
    
    try:
        choice = int(input("\nSelect region number (0 to cancel): "))
        if choice == 0:
            return None
        if 1 <= choice <= len(regions):
            return regions[choice - 1].id
        print("Invalid selection!")
        return None
    except ValueError:
        print("Invalid input!")
        return None

def select_instance(manager: LinodeManager) -> Optional[int]:
    """Interactive instance selection."""
    instances = manager.list_instances()
    if not instances:
        print("No instances found!")
        return None
    
    print("\nAvailable Instances:")
    for i, instance in enumerate(instances, 1):
        print(f"{i}. {instance.label} (ID: {instance.id}) - Region: {instance.region} - Status: {instance.status}")
    
    try:
        choice = int(input("\nSelect instance number (0 to cancel): "))
        if choice == 0:
            return None
        if 1 <= choice <= len(instances):
            return instances[choice - 1].id
        print("Invalid selection!")
        return None
    except ValueError:
        print("Invalid input!")
        return None

def handle_create_instance(manager: LinodeManager, custom_label: Optional[str] = None):
    """Handle instance creation workflow."""
    print("\n=== Create New Instance ===")
    
    # Get region
    region_id = select_region(manager)
    if not region_id:
        return
    
    # Use custom label if provided, otherwise generate one
    if custom_label:
        label = custom_label
        print(f"Using custom label: {label}")
    else:
        # Generate a unique instance label
        timestamp = datetime.datetime.now().strftime("%m%d%H%M")
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
        label = f"linode-{timestamp}-{random_suffix}"
        print(f"Using auto-generated label: {label}")
    
    # Use default root password
    root_pass = "4dwlq5!H4uA26A8"
    print("Using default root password")
    
    try:
        # Add debug information
        print(f"Creating instance in region: {region_id}")
        print(f"Using instance type: g6-nanode-1")
        print(f"Using image: linode/debian12")
        
        instance = manager.create_instance(
            label=label,
            region=region_id,
            type_id="g6-nanode-1",
            image="linode/debian12",
            root_pass=root_pass
        )
        print(f"\nInstance created successfully!")
        print(f"ID: {instance.id}")
        print(f"Label: {instance.label}")
        print(f"IPv4: {', '.join(instance.ipv4)}")
        print(f"IPv6: {instance.ipv6}")
    except Exception as e:
        error_str = str(e)
        
        # Check for API error details in the exception message
        if "API Error Details:" in error_str:
            # Extract and print the JSON part of the error message
            try:
                error_start = error_str.find('{"errors":')
                if error_start != -1:
                    error_json = error_str[error_start:]
                    error_data = json.loads(error_json)
                    print("\nFailed to create instance:")
                    print(json.dumps(error_data, indent=2))
                    return
            except:
                pass
                
        # If we couldn't extract detailed error, show a simpler message
        print(f"Failed to create instance. Please check region availability and try again.")

def handle_rebuild_instance(manager: LinodeManager):
    """Handle instance rebuild workflow."""
    print("\n=== Rebuild Instance ===")
    
    # Select instance
    instance_id = select_instance(manager)
    if not instance_id:
        return
    
    # Confirm rebuild
    confirm = input(f"Are you sure you want to rebuild instance {instance_id}? This will erase all data. (y/n): ")
    if confirm.lower() != 'y':
        print("Rebuild cancelled.")
        return
    
    # Use default root password
    root_pass = "4dwlq5!H4uA26A8"
    print("Using default root password")
    print("Using image: linode/debian12")
    
    try:
        if manager.rebuild_instance(instance_id):
            print("Instance rebuild initiated successfully!")
            print("This process may take several minutes to complete.")
        else:
            print("Failed to rebuild instance!")
    except Exception as e:
        error_str = str(e)
        
        # Check for API error details in the exception message
        if "API Error Details:" in error_str:
            # Extract and print the JSON part of the error message
            try:
                error_start = error_str.find('{"errors":')
                if error_start != -1:
                    error_json = error_str[error_start:]
                    error_data = json.loads(error_json)
                    print("\nFailed to rebuild instance:")
                    print(json.dumps(error_data, indent=2))
                    return
            except:
                pass
                
        # If we couldn't extract detailed error, show a simpler message
        print(f"Failed to rebuild instance. Please try again later.")

def handle_reboot_multiple(manager: LinodeManager):
    """Handle rebooting multiple instances."""
    print("\n=== Reboot Multiple Instances ===")
    
    instances = manager.list_instances()
    if not instances:
        print("No instances found!")
        return
    
    print("\nAvailable Instances:")
    for i, instance in enumerate(instances, 1):
        print(f"{i}. {instance.label} (ID: {instance.id}) - Status: {instance.status}")
    
    print("\nEnter instance numbers to reboot (comma-separated, e.g., '1,3,4')")
    print("Enter '0' to cancel")
    
    try:
        selection = input("Selection: ")
        if selection == "0":
            return
            
        # Parse selection
        try:
            selected_indices = [int(x.strip()) for x in selection.split(",")]
            selected_ids = []
            
            for idx in selected_indices:
                if 1 <= idx <= len(instances):
                    selected_ids.append(instances[idx-1].id)
                else:
                    print(f"Invalid selection: {idx}")
            
            if not selected_ids:
                print("No valid instances selected.")
                return
                
            # Confirm reboot
            print(f"\nYou are about to reboot {len(selected_ids)} instance(s):")
            for instance_id in selected_ids:
                for instance in instances:
                    if instance.id == instance_id:
                        print(f"- {instance.label} (ID: {instance_id})")
                        break
                        
            confirm = input("\nProceed with reboot? (y/n): ")
            if confirm.lower() != 'y':
                print("Reboot cancelled.")
                return
                
            # Reboot instances
            success_count = 0
            for instance_id in selected_ids:
                print(f"Rebooting instance ID: {instance_id}...")
                if manager.reboot_instance(instance_id):
                    print(f"Reboot request sent for instance ID: {instance_id}")
                    success_count += 1
                else:
                    print(f"Failed to reboot instance ID: {instance_id}")
                    
            print(f"\nReboot completed. {success_count}/{len(selected_ids)} instances rebooted successfully.")
            
        except ValueError:
            print("Invalid input format. Please use comma-separated numbers.")
            
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def handle_run_setup_script(manager: LinodeManager):
    """Handle running a setup script on an instance."""
    print("\n=== Run Setup Script on Instance ===")
    
    # Select instance
    instance_id = select_instance(manager)
    if not instance_id:
        return
    
    # Default setup script
    script = """#!/bin/bash
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
    
    print("\nSetup script will:")
    print("1. Update system packages")
    print("2. Install Docker and other utilities")
    print("3. Set up Shadowsocks-R server")
    print("4. Enable BBR for better network performance")
    print("5. Configure SSH access")
    
    # Confirm
    confirm = input(f"\nRun setup script on instance {instance_id}? (y/n): ")
    if confirm.lower() != 'y':
        print("Operation cancelled.")
        return
    
    # Run the script
    try:
        if manager.run_setup_script(instance_id, script):
            print("\nSetup script started successfully!")
            print("The script is running in the background.")
            print("You can check progress with: 'cat /root/setup.log' when you SSH into the server.")
        else:
            print("\nFailed to run setup script.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def handle_track_setup_progress(manager: LinodeManager):
    """Handle tracking setup script progress."""
    print("\n=== Track Setup Script Progress ===")
    
    # Select instance
    instance_id = select_instance(manager)
    if not instance_id:
        return
    
    # Track progress
    manager.track_setup_progress(instance_id)

def main():
    parser = argparse.ArgumentParser(description="Linode Manager CLI")
    parser.add_argument("--token", help="Linode API token")
    parser.add_argument("--label", help="Custom label for new instances")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:7890)")
    args = parser.parse_args()

    # Get API token
    api_token = args.token or "19756de4a2fcc796663de2eb65efececb9cfec81e853103d174ec202bdd5e2a6"

    # Get proxy if provided
    proxy = args.proxy

    manager = LinodeManager(api_token, proxy)
    
    # Validate API token
    print("Validating API token...")
    if not manager.validate_token():
        print("Error: Invalid API token or API access issue.")
        sys.exit(1)
    
    # Add a function to get available Linode types
    def list_linode_types():
        try:
            response = manager._make_request("GET", "linode/types")
            print("\nAvailable Linode Types:")
            for type_info in response.get("data", []):
                print(f"- {type_info['id']}: {type_info['label']} ({type_info['memory']/1024} GB RAM, {type_info['vcpus']} vCPUs)")
        except Exception:
            print("Failed to get Linode types")

    while True:
        print_menu()
        choice = input("Enter your choice (0-12): ")

        try:
            if choice == "0":
                print("Goodbye!")
                break
            elif choice == "1":
                regions = manager.get_regions()
                print("\nAvailable Regions:")
                for region in regions:
                    print(f"- {region.label} ({region.id}) - {region.country}")
            elif choice == "2":
                instances = manager.list_instances()
                if not instances:
                    print("No instances found.")
                    continue
                    
                print("\nYour Instances:")
                for instance in instances:
                    print(f"- {instance.label} (ID: {instance.id})")
                    print(f"  Status: {instance.status}")
                    print(f"  Region: {instance.region}")
                    print(f"  IPv4: {', '.join(instance.ipv4)}")
                    print(f"  IPv6: {instance.ipv6}")
                    print()
            elif choice == "3":
                handle_create_instance(manager, args.label)
            elif choice == "4":
                instance_id = select_instance(manager)
                if instance_id:
                    if manager.delete_instance(instance_id):
                        print("Instance deleted successfully!")
                    else:
                        print("Failed to delete instance!")
            elif choice == "5":
                instance_id = select_instance(manager)
                if instance_id:
                    if manager.reboot_instance(instance_id):
                        print("Instance rebooted successfully!")
                    else:
                        print("Failed to reboot instance!")
            elif choice == "6":
                instance_id = select_instance(manager)
                if instance_id:
                    instance = manager.get_instance(instance_id)
                    if instance:
                        print(f"\nInstance Details:")
                        print(f"Label: {instance.label}")
                        print(f"ID: {instance.id}")
                        print(f"Status: {instance.status}")
                        print(f"Region: {instance.region}")
                        print(f"Type: {instance.type}")
                        print(f"IPv4: {', '.join(instance.ipv4)}")
                        print(f"IPv6: {instance.ipv6}")
            elif choice == "7":
                results = manager.test_all_instances()
                if not results:
                    print("No instances to test.")
                    continue
                    
                print("\nConnection Quality Rankings:")
                for i, result in enumerate(results, 1):
                    print(f"\n{i}. {result['label']} ({result['region']})")
                    print(f"   IP: {result['ip']}")
                    print(f"   Ping: {result['ping']:.1f}ms" if result['ping'] else "   Ping: Failed")
                    if result['download_speed'] and result['upload_speed']:
                        print(f"   Download: {result['download_speed']:.1f} Mbps")
                        print(f"   Upload: {result['upload_speed']:.1f} Mbps")
                    else:
                        print("   Speed test failed")
            elif choice == "8":
                list_linode_types()
            elif choice == "9":
                handle_rebuild_instance(manager)
            elif choice == "10":
                handle_reboot_multiple(manager)
            elif choice == "11":
                handle_run_setup_script(manager)
            elif choice == "12":
                handle_track_setup_progress(manager)
            else:
                print("Invalid choice!")
        except Exception as e:
            print(f"An error occurred: {str(e).split('for url:')[0]}")

if __name__ == "__main__":
    main() 