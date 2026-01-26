# %% Activation Flow - HeroSMS
"""
Complete SMS activation workflow for Philippines "Any other" service
"""
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import herosms
import time

# %% Configuration
COUNTRY_ID = 4  # Philippines
SERVICE = "ot"  # Any other

# %% Step 1: Check Balance
balance = herosms.get_balance()
print(f"Current Balance: ${balance}")

# %% Step 2: Get a Number
print(f"\nRequesting number for service '{SERVICE}' in country {COUNTRY_ID}...")
activation_id, phone = herosms.get_number(service=SERVICE, country=COUNTRY_ID)
print(f"Activation ID: {activation_id}")
print(f"Phone Number: +{phone}")

# %% Step 3: Mark Ready (optional - some services auto-ready)
result = herosms.mark_ready(activation_id)
print(f"Mark ready: {result}")

# %% Step 4: Check Status (run this cell repeatedly)
status = herosms.get_status(activation_id)
print(f"Status: {status}")

if status.startswith("STATUS_OK:"):
    code = status.split(":")[1]
    print(f"\n*** CODE RECEIVED: {code} ***")

# %% Step 5a: Complete (after receiving code)
# Uncomment to complete activation
# result = herosms.complete(activation_id)
# print(f"Complete: {result}")

# %% Step 5b: Cancel (if no code or don't need anymore)
# Uncomment to cancel and get refund
# result = herosms.cancel(activation_id)
# print(f"Cancel: {result}")

# %% Auto-Poll for Code (wait up to 3 minutes)
print(f"\nPolling for SMS code...")
print(f"Phone: +{phone}")
print(f"Activation ID: {activation_id}")
print("-" * 40)

for i in range(36):  # 36 x 5s = 3 minutes
    status = herosms.get_status(activation_id)
    print(f"[{i*5:3d}s] {status}")
    
    if status.startswith("STATUS_OK:"):
        code = status.split(":")[1]
        print(f"\n*** CODE RECEIVED: {code} ***")
        # Auto-complete
        herosms.complete(activation_id)
        print("Activation completed!")
        break
    elif status == "STATUS_CANCEL":
        print("\nActivation was cancelled")
        break
    
    time.sleep(5)
else:
    print("\nTimeout - no code received")
    # Cancel and refund
    herosms.cancel(activation_id)
    print("Cancelled and refunded")

# %% Check Final Balance
balance = herosms.get_balance()
print(f"Final Balance: ${balance}")

# %% Get Status V2 (detailed info)
try:
    status_v2 = herosms.get_status_v2(activation_id)
    print(status_v2)
except Exception as e:
    print(f"Error: {e}")

# %% View Active Activations
active = herosms.get_active_activations()
print(active)
