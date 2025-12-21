#%% imports & config
import requests, time, random, ast

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

#%% load matches from file
with open('/allah/blue/web/tinder/matches.py') as f:
    matches = ast.literal_eval(f.read())
print(f"Loaded {len(matches)} matches")

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
