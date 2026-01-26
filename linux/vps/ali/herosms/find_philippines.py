# %% Find Philippines Services and Prices
"""
Find available SMS services and prices for Philippines

Price filtering when purchasing:
  - max_price: Maximum price you're willing to pay (filter)
  - fixed_price: Buy at exact price (use with max_price)
  
Example: get_number(service="tg", country=4, max_price=0.25)
         Will only succeed if number available at $0.25 or less
"""
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import herosms

# Philippines = Country ID 4
COUNTRY_ID = 4
print(f"Philippines Country ID: {COUNTRY_ID}")

# %% Get Operators for Philippines
print("\n" + "="*50)
print("Available Operators in Philippines:")
print("="*50)

operators = herosms.get_operators(country=COUNTRY_ID)
if isinstance(operators, dict) and operators.get("status") == "success":
    ops = operators.get("countryOperators", {}).get(str(COUNTRY_ID), [])
    print(f"  Operators: {', '.join(ops)}")
    print("\n  Use operator param to select specific carrier:")
    print("  e.g., get_number('tg', 4, operator='globe_telecom')")

# %% Get Services for Philippines
print("\n" + "="*50)
print("Available Services in Philippines:")
print("="*50)

services = herosms.get_services(country=COUNTRY_ID)
if isinstance(services, dict) and services.get("status") == "success":
    svc_list = services.get("services", [])
    for svc in svc_list[:30]:
        print(f"  {svc['code']:12} - {svc['name']}")
elif isinstance(services, dict):
    # Different format - might be nested
    print(f"Services response format: {type(services)}")
    print(services)

# %% Get Prices for Philippines
print("\n" + "="*50)
print("Prices for Philippines (base price per service):")
print("="*50)

prices = herosms.get_prices(country=COUNTRY_ID)

# Handle different response formats
if isinstance(prices, dict):
    # Format: {country_id: {service: {cost, count, physicalCount}}}
    country_prices = prices.get(str(COUNTRY_ID), prices)
    if isinstance(country_prices, dict):
        items = []
        for svc, data in country_prices.items():
            if isinstance(data, dict):
                items.append({
                    "service": svc,
                    "price": data.get("cost", data.get("price", "?")),
                    "count": data.get("count", "?")
                })
        # Sort by price
        items.sort(key=lambda x: float(x["price"]) if isinstance(x["price"], (int, float)) else 999)
        for p in items[:40]:
            print(f"  {p['service']:12} - ${p['price']:>8}  (available: {p['count']})")
elif isinstance(prices, list):
    sorted_prices = sorted(prices, key=lambda x: float(x.get("price", x.get("cost", 999))))
    for p in sorted_prices[:40]:
        service = p.get("service", "?")
        price = p.get("price", p.get("cost", "?"))
        count = p.get("count", "?")
        print(f"  {service:12} - ${price:>8}  (available: {count})")
else:
    print(f"Raw response: {prices}")

# %% Get Specific Service Prices (Popular services)
print("\n" + "="*50)
print("Popular Services - Philippines Prices:")
print("="*50)

popular = [
    ("tg", "Telegram"),
    ("wa", "WhatsApp"),
    ("ig", "Instagram"),
    ("fb", "Facebook"),
    ("go", "Google"),
    ("tw", "Twitter"),
    ("vi", "Viber"),
    ("ds", "Discord"),
    ("tt", "TikTok"),
    ("ot", "Other"),
]

for svc_code, svc_name in popular:
    try:
        price_data = herosms.get_prices(service=svc_code, country=COUNTRY_ID)
        
        if isinstance(price_data, dict):
            # Nested format
            country_data = price_data.get(str(COUNTRY_ID), {})
            svc_data = country_data.get(svc_code, {})
            if svc_data:
                print(f"  {svc_name:12} ({svc_code}) - ${svc_data.get('cost', '?'):>6}  (available: {svc_data.get('count', '?')})")
            else:
                print(f"  {svc_name:12} ({svc_code}) - Not available")
        elif isinstance(price_data, list) and len(price_data) > 0:
            p = price_data[0]
            print(f"  {svc_name:12} ({svc_code}) - ${p.get('price', p.get('cost', '?')):>6}  (available: {p.get('count', '?')})")
        else:
            print(f"  {svc_name:12} ({svc_code}) - Not available")
    except Exception as e:
        print(f"  {svc_name:12} ({svc_code}) - Error: {e}")

# %% Check Balance
print("\n" + "="*50)
print(f"Current Balance: ${herosms.get_balance()}")
print("="*50)

# %% Example: Get a number with price limit
print("\n" + "="*50)
print("Example Usage (not executed):")
print("="*50)
print("""
# Get any Telegram number for Philippines (base price)
activation_id, phone = herosms.get_number(service="tg", country=4)

# Get number ONLY if price <= $0.25 (will fail if cheapest > $0.25)
activation_id, phone = herosms.get_number(service="tg", country=4, max_price=0.25)

# Get number from specific operator
activation_id, phone = herosms.get_number(service="tg", country=4, operator="globe_telecom")

# Combine: specific operator + price cap
activation_id, phone = herosms.get_number(service="tg", country=4, operator="smart", max_price=0.30)
""")
