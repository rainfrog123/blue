# Decodo Public API (scratch)

Isolated from the gateway client in `../decodo/`.

## Run

```bash
cd C:\Users\jar71\blue\web\proxy\decodo\api
python test_api.py
python test_api.py --endpoint traffic
```

Loads `proxy.decodo.api_key` via `infra/scripts/cred_loader.get_proxy_decodo()`.

## Mobile proxies (Public API)

Mobile only supports **stats** endpoints (not sub-user management like residential):

| Endpoint | Method | `proxyType` |
| --- | --- | --- |
| `https://api.decodo.com/api/v2/statistics/traffic` | POST | `mobile_proxies` |
| `https://api.decodo.com/api/v2/statistics/targets` | POST | `mobile_proxies` |

Auth header: `Authorization: <api_key>`

```bash
python test_api.py --endpoint traffic_mobile
python test_api.py --endpoint targets_mobile
```

Guide: https://help.decodo.com/docs/mobile-proxy-statistics  
Auth limits: https://help.decodo.com/api-reference/public-api-key-authentication  
Mobile setup: https://help.decodo.com/docs/mobile-proxy-quick-start

Docs: https://help.decodo.com/reference · https://github.com/Decodo/Decodo-API
