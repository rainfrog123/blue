import requests

# Define the IPQS API URL and API key
api_key = "740F92cS9nqqV41L0u7jfbSepB3dff08"
url_template = f"https://ipqualityscore.com/api/json/ip/{api_key}/{{}}"

# List of IP addresses to test
ip_list = ['217.210.114.62','83.187.178.55','77.53.190.10','78.69.8.84','83.187.178.55','83.187.178.76','83.188.34.189','87.227.61.75','81.235.31.167','81.235.253.230','94.191.152.182','79.127.249.233','217.210.114.62','94.191.152.182','94.191.152.182','94.234.99.47','185.113.97.217','94.191.152.182','94.234.99.47','78.69.8.84','81.235.253.230']


# Define parameters for the request with the highest strictness level
params = {
    "strictness": 3,
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "user_language": "en-US"
}

# Loop through each IP and check its fraud score
for ip in ip_list:
    url = url_template.format(ip)
    response = requests.get(url, params=params)
    
    # Check if the request was successful
    if response.status_code == 200:
        data = response.json()
        if data.get("success"):
            fraud_score = data.get("fraud_score", "N/A")
            print(f"IP: {ip} - Fraud Score: {fraud_score}")
        else:
            print(f"IP: {ip} - API request was not successful: {data.get('message')}")
    else:
        print(f"IP: {ip} - Failed to connect to the API: {response.status_code}")
