import requests, time, random

headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "origin": "https://tinder.com",
    "referer": "https://tinder.com/",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
    "platform": "web",
    "app-version": "1064400",
    "tinder-version": "6.44.0",
    "x-auth-token": "3db76caa-591f-42da-85af-63578088f503",
    "persistent-device-id": "d0cb6f53-c922-4160-8fe4-bbcec0171fc3",
}
MY_ID = "5bd5cac4f56a08b23bc4224a"

def get_matches():
    r = requests.get("https://api.gotinder.com/v2/matches", headers=headers, params={"locale": "en", "count": 60})
    return r.json().get("data", {}).get("matches", [])

def send_msg(match_id, other_id, msg):
    url = f"https://api.gotinder.com/user/matches/{match_id}"
    payload = {"userId": MY_ID, "otherId": other_id, "matchId": match_id, "sessionId": None, "message": msg}
    r = requests.post(url, json=payload, headers=headers, params={"locale": "en"})
    return r.status_code, r.json()

matches = get_matches()
no_chat = [m for m in matches if not m.get("messages")]
print(f"Found {len(matches)} matches, {len(no_chat)} with no chat")
for m in no_chat:
    mid = m["id"]
    oid = m["person"]["_id"]
    name = m["person"].get("name", "?")
    print(f"Sending to {name} ({oid})...")
    status, resp = send_msg(mid, oid, "heyhey")
    print(f"  {status}: {resp.get('message', resp)}")
    time.sleep(random.uniform(1, 3.9))
