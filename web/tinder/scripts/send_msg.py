#%% imports & config
import requests, time, random, json
from pathlib import Path
from tqdm import tqdm

config = json.loads((Path(__file__).parent.parent / "config" / "auth.json").read_text())
MY_ID = config["my_id"]
headers = config["headers"]

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

#%% extract individual profile info
from datetime import datetime

def extract_profile(m):
    """Extract all available info for a single match."""
    p = m.get("person", {})
    msgs = m.get("messages", [])
    photos = p.get("photos", [])
    
    # Calculate age from birth_date
    age = None
    if bd := p.get("birth_date"):
        try:
            birth = datetime.fromisoformat(bd.replace("Z", "+00:00"))
            age = (datetime.now(birth.tzinfo) - birth).days // 365
        except: pass
    
    # Message stats
    my_msgs = [msg for msg in msgs if msg.get("from") == MY_ID]
    their_msgs = [msg for msg in msgs if msg.get("from") != MY_ID]
    
    # Photo scores (Tinder's internal attractiveness ranking)
    photo_scores = [ph.get("score", 0) for ph in photos]
    avg_photo_score = sum(photo_scores) / len(photo_scores) if photo_scores else 0
    
    return {
        # Match info
        "match_id": m.get("id"),
        "created_date": m.get("created_date"),
        "last_activity": m.get("last_activity_date"),
        "is_closed": m.get("closed", False),
        "is_dead": m.get("dead", False),
        
        # Match type flags
        "is_super_like": m.get("is_super_like", False),
        "is_boost_match": m.get("is_boost_match", False),
        "is_fast_match": m.get("is_fast_match", False),
        "is_opener": m.get("is_opener", False),  # you sent first
        
        # Person info
        "user_id": p.get("_id"),
        "name": p.get("name"),
        "bio": p.get("bio", ""),
        "birth_date": p.get("birth_date"),
        "age": age,
        "gender": p.get("gender"),  # 0=male, 1=female
        "hide_age": p.get("hide_age", False),
        "hide_distance": p.get("hide_distance", False),
        
        # Photos
        "photo_count": len(photos),
        "photo_urls": [ph.get("url") for ph in photos],
        "photo_scores": photo_scores,
        "avg_photo_score": avg_photo_score,
        "has_verified_photo": any(ph.get("selfie_verified") for ph in photos),
        
        # Messages
        "message_count": len(msgs),
        "my_message_count": len(my_msgs),
        "their_message_count": len(their_msgs),
        "messages": msgs,
        "last_message": msgs[-1].get("message") if msgs else None,
        "last_message_from_me": msgs[-1].get("from") == MY_ID if msgs else None,
        
        # Social
        "common_friends": m.get("common_friend_count", 0),
        "common_likes": m.get("common_like_count", 0),
        
        # Settings
        "subscription_tier": m.get("subscription_tier"),
        "following": m.get("following", False),
    }

# Extract all profiles
profiles = [extract_profile(m) for m in all_matches]

# Quick stats
print(f"\n=== Profile Summary ===")
ages = [p["age"] for p in profiles if p["age"]]
print(f"Age range: {min(ages)}-{max(ages)}, avg: {sum(ages)/len(ages):.1f}" if ages else "No ages")
print(f"Avg photo score: {sum(p['avg_photo_score'] for p in profiles)/len(profiles):.3f}")
print(f"With bio: {sum(1 for p in profiles if p['bio'])}/{len(profiles)}")
print(f"Super likes: {sum(1 for p in profiles if p['is_super_like'])}")
print(f"Verified photos: {sum(1 for p in profiles if p['has_verified_photo'])}")

#%% explore profiles
# Access individual profile
p = profiles[0]
print(f"{p['name']}, {p['age']}yo - {p['bio'][:50]}")
print(f"Photo score: {p['avg_photo_score']:.2f}, {p['photo_count']} photos")

# Find highest photo scores
top = sorted(profiles, key=lambda x: x['avg_photo_score'], reverse=True)[:5]

# Find matches with replies
replied = [p for p in profiles if p['their_message_count'] > 0]

# Download all photos for a profile
for url in p['photo_urls']:
    print(url)

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
    payload = {"userId": MY_ID, "otherId": oid, "matchId": mid, "sessionId": None, "message": "hello 有在成都吗?"}
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
