import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parents[3] / 'linux' / 'extra' / 'config'))
from cred_loader import get_proxy_decodo

import requests
url = 'https://ip.decodo.com/json'
_decodo = get_proxy_decodo()
username = f"{_decodo['username']}-session-1-country-gb"
password = _decodo['password']
proxy = f"socks5h://{username}:{password}@gate.decodo.com:7000"
result = requests.get(url, proxies = {
    'http': proxy,
    'https': proxy
})
print(result.text)