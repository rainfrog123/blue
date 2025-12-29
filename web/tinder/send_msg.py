#%% imports & config
import requests, time, random, json
from pathlib import Path
from tqdm import tqdm

auth = json.loads((Path(__file__).parent / "auth.json").read_text())
MY_ID = auth.pop("my_id")
headers = {"accept": "application/json", "content-type": "application/json", "origin": "https://tinder.com",
           "referer": "https://tinder.com/", "platform": "web",
           "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", **auth}

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

#%% filter
no_chat = [m for m in all_matches if not m.get("messages")]
has_chat = [m for m in all_matches if m.get("messages")]
i_sent_only = [m for m in has_chat if all(msg.get("from") == MY_ID for msg in m.get("messages", []))]
they_sent = [m for m in has_chat if any(msg.get("from") != MY_ID for msg in m.get("messages", []))]
print(f"{len(no_chat)} no chat, {len(has_chat)} has chat ({len(i_sent_only)} i sent only, {len(they_sent)} they replied)")

#%% test send message (single)
m = no_chat[0]
mid, oid, name = m["id"], m["person"]["_id"], m["person"].get("name", "?")
print(f"Sending to {name} ({oid})...")
payload = {"userId": MY_ID, "otherId": oid, "matchId": mid, "sessionId": None, "message": "hey"}
r = requests.post(f"https://api.gotinder.com/user/matches/{mid}", json=payload, headers=headers, params={"locale": "en"})
print(f"  {r.status_code}: {r.json().get('message', r.text)}")

#%% send to no-chat matches
for m in tqdm(no_chat, desc="no-chat"):
    mid, oid, name = m["id"], m["person"]["_id"], m["person"].get("name", "?")
    payload = {"userId": MY_ID, "otherId": oid, "matchId": mid, "sessionId": None, "message": "heyy 你有在成都吗?"}
    r = requests.post(f"https://api.gotinder.com/user/matches/{mid}", json=payload, headers=headers, params={"locale": "en"})
    print(f"{name}: {r.status_code}")
    time.sleep(random.uniform(3, 6))

#%% send to has-chat matches (last msg before 12/28)
old_chat = [m for m in has_chat if m.get("last_activity_date", "") < "2025-12-28"]
print(f"{len(old_chat)} with old chat")
for m in tqdm(old_chat, desc="old-chat"):
    mid, oid, name = m["id"], m["person"]["_id"], m["person"].get("name", "?")
    payload = {"userId": MY_ID, "otherId": oid, "matchId": mid, "sessionId": None, "message": "我不是经常上，有空可以约咖啡或者喝酒呀"}
    r = requests.post(f"https://api.gotinder.com/user/matches/{mid}", json=payload, headers=headers, params={"locale": "en"})
    print(f"{name}: {r.status_code}")
    time.sleep(random.uniform(3, 6))

# %%
