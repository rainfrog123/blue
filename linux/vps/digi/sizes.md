# DigitalOcean Available Sizes

> Account Limited - Generated: 2026-03-30

## Account Limits


| Metric | Your Limit | DO Max (unlocked) |
| ------ | ---------- | ----------------- |
| vCPUs  | 4          | 32+               |
| RAM    | 8GB        | 192GB             |
| Price  | ~$68/mo    | $1,200+/mo        |


To unlock larger sizes, contact DO support for a limit increase.

## Size Prefixes


| Prefix | Type                   | Description                                |
| ------ | ---------------------- | ------------------------------------------ |
| `s-`   | Basic                  | Shared CPU, cheapest, good for low-traffic |
| `g-`   | General Purpose        | Dedicated CPU, balanced workloads          |
| `gd-`  | General Purpose + NVMe | Dedicated CPU + fast NVMe SSD              |
| `c-`   | CPU-Optimized          | High CPU:RAM ratio, compute-heavy          |
| `m-`   | Memory-Optimized       | High RAM:CPU ratio, databases              |
| `so-`  | Storage-Optimized      | Large NVMe, big data                       |


## Available Sizes (sorted by price)


| #   | Slug                      | Type     | vCPU | RAM   | Disk  | Price    |
| --- | ------------------------- | -------- | ---- | ----- | ----- | -------- |
| 1   | `gd-2vcpu-8gb`            | Gen+NVMe | 2    | 8GB   | 50GB  | $68/mo   |
| 2   | `s-4vcpu-8gb-240gb-intel` | Basic    | 4    | 8GB   | 240GB | $64/mo ⭐ |
| 3   | `g-2vcpu-8gb`             | General  | 2    | 8GB   | 25GB  | $63/mo   |
| 4   | `s-4vcpu-8gb-intel`       | Basic    | 4    | 8GB   | 160GB | $56/mo   |
| 5   | `s-2vcpu-8gb-160gb-intel` | Basic    | 2    | 8GB   | 160GB | $48/mo   |
| 6   | `s-4vcpu-8gb`             | Basic    | 4    | 8GB   | 160GB | $48/mo   |
| 7   | `c-2`                     | CPU-Opt  | 2    | 4GB   | 25GB  | $42/mo   |
| 8   | `s-2vcpu-4gb-120gb-intel` | Basic    | 2    | 4GB   | 120GB | $32/mo   |
| 9   | `s-2vcpu-4gb-intel`       | Basic    | 2    | 4GB   | 80GB  | $28/mo   |
| 10  | `s-2vcpu-2gb-90gb-intel`  | Basic    | 2    | 2GB   | 90GB  | $24/mo   |
| 11  | `s-2vcpu-4gb`             | Basic    | 2    | 4GB   | 80GB  | $24/mo   |
| 12  | `s-2vcpu-2gb-intel`       | Basic    | 2    | 2GB   | 60GB  | $21/mo   |
| 13  | `s-2vcpu-2gb`             | Basic    | 2    | 2GB   | 60GB  | $18/mo   |
| 14  | `s-1vcpu-2gb-70gb-intel`  | Basic    | 1    | 2GB   | 70GB  | $16/mo   |
| 15  | `s-1vcpu-2gb-intel`       | Basic    | 1    | 2GB   | 50GB  | $14/mo   |
| 16  | `s-1vcpu-2gb`             | Basic    | 1    | 2GB   | 50GB  | $12/mo   |
| 17  | `s-1vcpu-1gb-35gb-intel`  | Basic    | 1    | 1GB   | 35GB  | $8/mo    |
| 18  | `s-1vcpu-1gb-intel`       | Basic    | 1    | 1GB   | 25GB  | $7/mo    |
| 19  | `s-1vcpu-1gb`             | Basic    | 1    | 1GB   | 25GB  | $6/mo    |
| 20  | `s-1vcpu-512mb-10gb`      | Basic    | 1    | 512MB | 10GB  | $4/mo    |


## Best Value Picks


| Slug                      | Price  | Why                                          |
| ------------------------- | ------ | -------------------------------------------- |
| `s-4vcpu-8gb-240gb-intel` | $64/mo | **Best specs** - 4 vCPU, 8GB RAM, 240GB disk |
| `s-4vcpu-8gb`             | $48/mo | Same power, less disk, $16 cheaper           |
| `c-2`                     | $42/mo | Dedicated CPU for compute-heavy tasks        |
| `s-1vcpu-512mb-10gb`      | $4/mo  | Cheapest for tiny workloads                  |


## Notes

- `intel` suffix = Intel processor (vs AMD)
- Basic (`s-`) = Shared CPU (noisy neighbors possible)
- General/CPU-Opt = Dedicated CPU (guaranteed performance)
- Higher disk variants cost more but have same CPU/RAM

