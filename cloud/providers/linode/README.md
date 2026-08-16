# Server Deployment Tools

This repository contains tools for server deployment and configuration.

## Projects

### SSR Deployment

The `ssr_deploy` directory contains scripts to deploy a Shadowsocks-R (SSR) server:

- Enables root login on a remote server
- Deploys and configures SSR with Docker
- Sets up TCP BBR for improved performance
- Configures secure SSH access
- Uses the same setup script as the archived Linode multi-region deployment tool

To use:
```bash
cd ssr_deploy
./enable_root_and_deploy.sh
```

### Archive

The `archive` directory contains older scripts and tools that are kept for reference:

- Linode multi-region deployment scripts
- Configuration files and utilities

## Repository Structure

```
.
├── README.md           # This file
├── ssr_deploy/         # SSR deployment tools
└── archive/            # Archived Linode scripts
``` 