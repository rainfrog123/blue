# SSR Deployment Script

This project provides a script to enable root login on a remote server and deploy a Shadowsocks-R (SSR) server using the same setup script from the Linode multi-region deployment tool.

## Features

- Automated root login enablement
- SSR server deployment with Docker
- TCP BBR congestion control for improved performance
- Secure SSH key-based authentication
- Uses the identical setup script from deploy_nodes.py for consistency

## Files

- `enable_root_and_deploy.sh`: Main deployment script
- `id_rsa`: SSH private key for authentication
- `public_key`: SSH public key
- `known_hosts`: SSH known hosts file

## Usage

1. Ensure you have the required SSH keys in this directory
2. Run the deployment script:

```bash
./enable_root_and_deploy.sh
```

3. The script will:
   - Connect to the server as a regular user
   - Enable root login with SSH key authentication
   - Deploy and configure the SSR server
   - Display connection details upon completion

## SSR Server Details

- Port: 19000
- Password: bxsnucrgk6hfish
- Method: chacha20-ietf
- Protocol: auth_aes128_sha1
- Obfs: plain

## Requirements

- Bash shell
- SSH client 