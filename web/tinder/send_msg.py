#%% imports & config
import requests, time, random

headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "origin": "https://tinder.com",
    "referer": "https://tinder.com/",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
    "platform": "web",
    "app-version": "1064500",
    "tinder-version": "6.45.0",
    "x-auth-token": "4d81eb3b-6a11-4c6d-b553-9c3cfa6c3141",
    "persistent-device-id": "d0cb6f53-c922-4160-8fe4-bbcec0171fc3",
    "app-session-id": "88776ae9-789a-428f-9775-6178e299f034",
    "user-session-id": "673aa357-6393-4c15-9f80-b1b6a84e528e",
}
MY_ID = "5bd5cac4f56a08b23bc4224a"

#%% get all matches
all_matches, token = [], None
while True:
    params = {"locale": "en", "count": 60}
    if token:
        params["page_token"] = token
    data = requests.get("https://api.gotinder.com/v2/matches", headers=headers, params=params).json().get("data", {})
    all_matches.extend(data.get("matches", []))
    token = data.get("next_page_token")
    if not token:
        break
print(f"Found {len(all_matches)} matches")

#%% filter no chat
no_chat = [m for m in all_matches if not m.get("messages")]
print(f"{len(no_chat)} with no chat")

#%% test send message
m = no_chat[0]
mid = m["id"]
oid = m["person"]["_id"]
name = m["person"].get("name", "?")
print(f"Sending to {name} ({oid})...")
payload = {"userId": MY_ID, "otherId": oid, "matchId": mid, "sessionId": None, "message": "要约会吗？"}
r = requests.post(f"https://api.gotinder.com/user/matches/{mid}", json=payload, headers=headers, params={"locale": "en"})
print(f"  {r.status_code}: {r.json().get('message', r.text)}")

# %%
