# ali-jp hysteria

```bash
bash cloud/common/stacks/hysteria/up.sh ali-jp
```

- Shared: `common/stacks/hysteria/defaults.yaml` (no bandwidth — BBR; QUIC windows kept)
- This host: `site.yaml` + `acme/`
- Domain reserved: `hyjp.hyas.site` (self-signed until ACME)
