#%% imports & config
import requests, time, random, json
from pathlib import Path

auth = json.loads((Path(__file__).parent / "auth.json").read_text())
MY_ID = auth.pop("my_id")
headers = {"accept": "application/json", "content-type": "application/json", "origin": "https://tinder.com",
           "referer": "https://tinder.com/", "platform": "web",
           "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", **auth}

#%% get all matches
matches, token = [], None
while True:
    params = {"locale": "en", "count": 60}
    if token:
        params["page_token"] = token
    data = requests.get("https://api.gotinder.com/v2/matches", headers=headers, params=params).json().get("data", {})
    matches.extend(data.get("matches", []))
    token = data.get("next_page_token")
    if not token:
        break
print(f"Found {len(matches)} matches")

#%% find no-reply matches (I sent but they didn't reply)
no_reply = []
for m in matches:
    msgs = m.get('messages', [])
    if not msgs:
        continue
    i_sent = any(msg.get('from') == MY_ID for msg in msgs)
    they_sent = any(msg.get('from') != MY_ID for msg in msgs)
    if i_sent and not they_sent:
        no_reply.append(m)

no_reply.sort(key=lambda m: m.get('last_activity_date', ''), reverse=True)
print(f"Found {len(no_reply)} no-reply matches")

#%% preview who will be unmatched
for i, m in enumerate(no_reply):
    name = m.get('person', {}).get('name', '?')
    date = m.get('last_activity_date', '')[:10]
    mid = m.get('id', '')
    my_msg = [msg['message'][:25] for msg in m.get('messages', []) if msg.get('from') == MY_ID]
    print(f"{i+1:2}. {name:15} | {date} | {my_msg}")

#%% unmatch all before date
def unmatch_before(matches_list, before_date="2026-01-01"):
    """Unmatch all matches with last_activity_date before the given date."""
    to_unmatch = [m for m in matches_list if m.get('last_activity_date', '') < before_date]
    print(f"Will unmatch {len(to_unmatch)} matches before {before_date}")
    
    for m in to_unmatch:
        mid = m.get('id')
        name = m.get('person', {}).get('name', '?')
        date = m.get('last_activity_date', '')[:10]
        print(f"Unmatching {name} ({date})...")
        r = requests.delete(f"https://api.gotinder.com/user/matches/{mid}", headers=headers, params={"locale": "en"})
        print(f"  {r.status_code}: {r.text}")
        time.sleep(random.uniform(1, 3))
    
    print(f"Done! Unmatched {len(to_unmatch)} matches")

# Run: unmatch all no-reply before 2026-01-01
unmatch_before(no_reply, "2026-01-01")

#%% DANGER: unmatch one (test with first one)
m = no_reply[-1]
mid = m.get('id')
name = m.get('person', {}).get('name', '?')
print(f"Unmatching {name} ({mid})...")
r = requests.delete(f"https://api.gotinder.com/user/matches/{mid}", headers=headers, params={"locale": "en"})
print(f"  {r.status_code}: {r.text}")

#%% DANGER: unmatch all no-reply (UNCOMMENT TO RUN)
for m in no_reply[1:]:
    mid = m.get('id')
    name = m.get('person', {}).get('name', '?')
    print(f"Unmatching {name}...")
    r = requests.delete(f"https://api.gotinder.com/user/matches/{mid}", headers=headers, params={"locale": "en"})
    print(f"  {r.status_code}: {r.text}")
    time.sleep(random.uniform(1, 3))


# %%
