"""
Linode Multi-Region Parallel Deployment Script
===========================================

This script enables simultaneous deployment of Linode instances across multiple regions.
It uses Python's concurrent.futures for parallel processing, significantly reducing deployment time.

Available Regions:
----------------
Asia Pacific:
- Japan: Osaka (jp-osa), Tokyo 3 (jp-tyo-3), Tokyo 2 (ap-northeast)
- Singapore: Singapore 2 (sg-sin-2), Singapore (ap-south)
- Australia: Sydney (ap-southeast), Melbourne (au-mel)
- India: Mumbai (ap-west), Chennai (in-maa), Mumbai 2 (in-bom-2)
- Indonesia: Jakarta (id-cgk)

North America:
- United States: Washington DC (us-iad), Chicago (us-ord), Seattle (us-sea),
                Miami (us-mia), Los Angeles (us-lax), Dallas (us-central),
                Fremont (us-west), Atlanta (us-southeast), Newark (us-east)
- Canada: Toronto (ca-central)

Europe:
- United Kingdom: London 2 (gb-lon), London (eu-west)
- Germany: Frankfurt 2 (de-fra-2), Frankfurt (eu-central)
- France: Paris (fr-par)
- Netherlands: Amsterdam (nl-ams)
- Sweden: Stockholm (se-sto)
- Spain: Madrid (es-mad)
- Italy: Milan (it-mil)

South America:
- Brazil: Sao Paulo (br-gru)

Parallel Processing Features:
--------------------------
1. Simultaneous Instance Creation:
   - Deploys all selected instances in parallel using ThreadPoolExecutor
   - Each region gets its own thread for deployment
   - Real-time progress updates as deployments complete

2. Parallel Instance Startup:
   - Monitors all instances simultaneously for running state
   - Reduces total waiting time for multiple instances
   - Shows progress for each instance as they become ready

3. Parallel Setup:
   - Configures all running instances simultaneously
   - Each instance setup runs in its own thread
   - Includes Docker and SSR configuration

Progress Reporting:
----------------
- Uses emoji indicators (✅ for success, ❌ for failure)
- Shows detailed region and IP information
- Provides a final summary of success rates
- Clear error reporting at each stage

Usage Example:
------------
1. Run the script: python deploy_nodes.py
2. Select regions using the interactive menu
3. Confirm deployment
4. Watch real-time parallel deployment progress

The script will show output like:
Starting parallel deployment in regions: jp-osa, us-east, fr-par
✅ Deployed instance in jp-osa: ID 123456
✅ Deployed instance in us-east: ID 123457
✅ Deployed instance in fr-par: ID 123458

Final Results will show:
- Total regions selected
- Successfully deployed count
- Successfully running count
- Successfully setup count
- List of all deployed instances with IPs

Dependencies:
-----------
- concurrent.futures: For parallel processing
- paramiko: For SSH operations
- LinodeManager: Custom wrapper for Linode API
"""

import os
import time
import paramiko
import argparse
from typing import List, Dict
import concurrent.futures
from linode_manager import LinodeManager
import warnings

# Filter all deprecation warnings from paramiko
warnings.filterwarnings('ignore', category=DeprecationWarning)

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

class LinodeDeployer:
    def __init__(self, api_token: str):
        self.manager = LinodeManager(api_token)
        self.root_pass = "4dwlq5!H4uA26A8"
        
        # Add region descriptions
        self.region_descriptions = {
            # Asia Pacific
            "jp-osa": "Osaka, Japan",
            "jp-tyo-3": "Tokyo 3, Japan",
            "ap-northeast": "Tokyo 2, Japan",
            "sg-sin-2": "Singapore 2",
            "ap-south": "Singapore",
            "ap-southeast": "Sydney, Australia",
            "au-mel": "Melbourne, Australia",
            "ap-west": "Mumbai, India",
            "in-maa": "Chennai, India",
            "in-bom-2": "Mumbai 2, India",
            "id-cgk": "Jakarta, Indonesia",
            
            # North America
            "us-iad": "Washington, DC",
            "us-ord": "Chicago, IL",
            "us-sea": "Seattle, WA",
            "us-mia": "Miami, FL",
            "us-lax": "Los Angeles, CA",
            "us-central": "Dallas, TX",
            "us-west": "Fremont, CA",
            "us-southeast": "Atlanta, GA",
            "us-east": "Newark, NJ",
            "ca-central": "Toronto, Canada",
            
            # Europe
            "gb-lon": "London 2, UK",
            "eu-west": "London, UK",
            "de-fra-2": "Frankfurt 2, Germany",
            "eu-central": "Frankfurt, Germany",
            "fr-par": "Paris, France",
            "nl-ams": "Amsterdam, Netherlands",
            "se-sto": "Stockholm, Sweden",
            "es-mad": "Madrid, Spain",
            "it-mil": "Milan, Italy",
            
            # South America
            "br-gru": "Sao Paulo, Brazil"
        }
        
        # Organize all regions by country for better selection
        self.regions: Dict[str, Dict[str, list]] = {
            'asia_pacific': {
                'japan': [
                    "jp-osa",        # Osaka, JP
                    "jp-tyo-3",      # Tokyo 3, JP
                    "ap-northeast",  # Tokyo 2, JP
                ],
                'singapore': [
                    "sg-sin-2",      # Singapore 2, SG
                    "ap-south",      # Singapore, SG
                ],
                'australia': [
                    "ap-southeast",  # Sydney, AU
                    "au-mel",        # Melbourne, AU
                ],
                'india': [
                    "ap-west",       # Mumbai, IN
                    "in-maa",        # Chennai, IN
                    "in-bom-2",      # Mumbai 2, IN
                ],
                'indonesia': [
                    "id-cgk",        # Jakarta, ID
                ]
            },
            'north_america': {
                'united_states': [
                    "us-iad",        # Washington, DC
                    "us-ord",        # Chicago, IL
                    "us-sea",        # Seattle, WA
                    "us-mia",        # Miami, FL
                    "us-lax",        # Los Angeles, CA
                    "us-central",    # Dallas, TX
                    "us-west",       # Fremont, CA
                    "us-southeast",  # Atlanta, GA
                    "us-east",       # Newark, NJ
                ],
                'canada': [
                    "ca-central",    # Toronto, CA
                ]
            },
            'europe': {
                'united_kingdom': [
                    "gb-lon",        # London 2, UK
                    "eu-west",       # London, UK
                ],
                'germany': [
                    "de-fra-2",      # Frankfurt 2, DE
                    "eu-central",    # Frankfurt, DE
                ],
                'france': [
                    "fr-par",        # Paris, FR
                ],
                'netherlands': [
                    "nl-ams",        # Amsterdam, NL
                ],
                'sweden': [
                    "se-sto",        # Stockholm, SE
                ],
                'spain': [
                    "es-mad",        # Madrid, ES
                ],
                'italy': [
                    "it-mil",        # Milan, IT
                ]
            },
            'south_america': {
                'brazil': [
                    "br-gru",        # Sao Paulo, BR
                ]
            }
        }
        self.target_regions = []

    def list_available_regions(self):
        """Print all available regions organized by continent and country."""
        print("Available Regions:")
        for continent, countries in self.regions.items():
            print(f"\n{continent.replace('_', ' ').title()}:")
            for country, regions in countries.items():
                print(f"  {country.replace('_', ' ').title()}:")
                for region in regions:
                    print(f"    - {region}")

    def set_target_regions(self, selections: List[str]):
        """
        Set target regions for deployment. Can accept:
        - Continent names (e.g., 'asia_pacific')
        - Country names (e.g., 'japan')
        - Specific region codes (e.g., 'jp-osa')
        """
        self.target_regions = []
        
        for selection in selections:
            selection = selection.lower()
            
            # Check if it's a continent
            if selection in self.regions:
                for country in self.regions[selection].values():
                    self.target_regions.extend(country)
                continue
                
            # Check if it's a country
            for continent in self.regions.values():
                if selection in continent:
                    self.target_regions.extend(continent[selection])
                    break
            
            # Check if it's a specific region code
            found = False
            for continent in self.regions.values():
                for regions in continent.values():
                    if selection in regions:
                        self.target_regions.append(selection)
                        found = True
                        break
                if found:
                    break
            
            if not found and selection not in self.regions and selection not in self.target_regions:
                print(f"Warning: '{selection}' is not a valid region, country, or continent")

        # Remove duplicates while preserving order
        self.target_regions = list(dict.fromkeys(self.target_regions))
        
        print(f"Selected regions for deployment: {', '.join(self.target_regions)}")

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
        """Deploy instances in all target regions simultaneously."""
        if not self.target_regions:
            raise ValueError("No target regions specified. Use set_target_regions() first.")
            
        print(f"Starting parallel deployment in regions: {', '.join(self.target_regions)}")
        
        # Deploy instances in parallel
        instances = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.target_regions)) as executor:
            # Submit all deployment tasks
            future_to_region = {
                executor.submit(self.deploy_instance, region): region 
                for region in self.target_regions
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_region):
                region = future_to_region[future]
                try:
                    instance = future.result()
                    if instance:
                        instances.append(instance)
                        print(f"✅ Deployed instance in {region}: ID {instance['id']}")
                    else:
                        print(f"❌ Failed to deploy in {region}")
                except Exception as e:
                    print(f"❌ Error deploying in {region}: {str(e)}")
        
        print(f"\nDeployed {len(instances)} instances successfully")
        
        # Wait for instances to be running in parallel
        running_instances = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(instances)) as executor:
            # Submit all wait tasks
            future_to_instance = {
                executor.submit(self.wait_for_running, instance["id"]): instance 
                for instance in instances
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_instance):
                instance = future_to_instance[future]
                try:
                    if future.result():
                        running_instances.append(instance)
                        print(f"✅ Instance {instance['id']} in {instance['region']} is running")
                    else:
                        print(f"❌ Instance {instance['id']} in {instance['region']} failed to start")
                except Exception as e:
                    print(f"❌ Error waiting for instance {instance['id']}: {str(e)}")
        
        print(f"\n{len(running_instances)} instances are running")
        
        # Setup running instances in parallel
        successful_setups = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(running_instances)) as executor:
            # Submit all setup tasks
            future_to_instance = {
                executor.submit(self.setup_instance, instance["ip"]): instance 
                for instance in running_instances
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_instance):
                instance = future_to_instance[future]
                try:
                    if future.result():
                        successful_setups += 1
                        print(f"✅ Setup completed for {instance['region']} ({instance['ip']})")
                    else:
                        print(f"❌ Setup failed for {instance['region']} ({instance['ip']})")
                except Exception as e:
                    print(f"❌ Error during setup for {instance['region']}: {str(e)}")
        
        print(f"\nFinal Results:")
        print(f"Total regions selected: {len(self.target_regions)}")
        print(f"Successfully deployed: {len(instances)}")
        print(f"Successfully running: {len(running_instances)}")
        print(f"Successfully setup: {successful_setups}")
        
        if successful_setups > 0:
            print("\nDeployed Instances:")
            for instance in running_instances:
                print(f"- Region: {instance['region']:<12} IP: {instance['ip']}")

def display_menu(regions: Dict[str, Dict[str, list]]) -> List[str]:
    """Display a simple numbered list of all regions."""
    all_regions = []
    region_map = {}  # Map numbers to region codes
    
    print("\n=== Available Regions ===")
    print("Enter region numbers separated by spaces (e.g., '1 3 5')")
    print("Enter '0' to finish, 'q' to quit\n")
    
    counter = 1
    # Flatten the region structure into a simple numbered list
    for continent, countries in regions.items():
        for country, region_list in countries.items():
            for region in region_list:
                location = deployer.region_descriptions.get(region, "")
                print(f"{counter:2d}. {region:<12} - {location}")
                region_map[counter] = region
                counter += 1
    
    while True:
        choice = input("\nSelect regions (e.g., '1 3 5'): ").lower()
        
        if choice == 'q':
            exit(0)
        if choice == '0':
            break
            
        try:
            # Parse space-separated numbers
            selected_numbers = [int(x) for x in choice.split()]
            
            # Validate numbers
            if all(1 <= num < counter for num in selected_numbers):
                # Convert numbers to region codes
                return [region_map[num] for num in selected_numbers]
            else:
                print(f"Please enter numbers between 1 and {counter-1}")
        except ValueError:
            print("Invalid input. Please enter numbers separated by spaces.")
    
    return all_regions

def main():
    global deployer  # Make deployer accessible to display_menu
    import sys
    sys.path.insert(0, str(__import__('pathlib').Path(__file__).parents[4] / 'linux' / 'extra' / 'config'))
    from cred_loader import get_linode_token
    api_token = get_linode_token(0)
    deployer = LinodeDeployer(api_token)
    
    print("Welcome to Linode Deployer!")
    
    selected_regions = display_menu(deployer.regions)
    
    if not selected_regions:
        print("\nNo regions selected. Exiting...")
        return
        
    print("\nSelected regions:")
    for region in selected_regions:
        location = deployer.region_descriptions.get(region, "")
        print(f"- {region} ({location})")
        
    confirm = input("\nDo you want to proceed with deployment? (y/n): ").lower()
    
    if confirm == 'y':
        deployer.set_target_regions(selected_regions)
        deployer.deploy_all()
    else:
        print("Deployment cancelled.")

if __name__ == "__main__":
    main() 