#%% imports & config
import requests, time, random, json
from pathlib import Path

config = json.loads((Path(__file__).parent.parent / "config" / "auth.json").read_text())
MY_ID = config["my_id"]
headers = config["headers"]

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
BEFORE_DATE = "2026-01-20"
to_unmatch = [m for m in no_reply if m.get('last_activity_date', '') < BEFORE_DATE]
print(f"Will unmatch {len(to_unmatch)} matches before {BEFORE_DATE}:")
for i, m in enumerate(to_unmatch):
    name = m.get('person', {}).get('name', '?')
    date = m.get('last_activity_date', '')[:10]
    my_msg = [msg['message'][:25] for msg in m.get('messages', []) if msg.get('from') == MY_ID]
    print(f"{i+1:2}. {name:15} | {date} | {my_msg}")

#%% unmatch all (uses to_unmatch from preview)
for m in to_unmatch:
    mid = m.get('id')
    name = m.get('person', {}).get('name', '?')
    date = m.get('last_activity_date', '')[:10]
    print(f"Unmatching {name} ({date})...")
    r = requests.delete(f"https://api.gotinder.com/user/matches/{mid}", headers=headers, params={"locale": "en"})
    print(f"  {r.status_code}: {r.text}")
    time.sleep(random.uniform(1, 3))

print(f"Done! Unmatched {len(to_unmatch)} matches")

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
