import requests
url = 'https://ip.decodo.com/json'
username = 'user-sp3j58curv-session-1-country-gb'
password = '9oOoKQ8+z8pkcUsnv0'
proxy = f"socks5h://{username}:{password}@gate.decodo.com:7000"
result = requests.get(url, proxies = {
    'http': proxy,
    'https': proxy
})
print(result.text)