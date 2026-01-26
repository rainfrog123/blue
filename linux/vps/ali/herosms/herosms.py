# %% HeroSMS API Wrapper
"""
HeroSMS API Wrapper - SMS Activation Service
Compatible with SMS-Activate API protocol
https://hero-sms.com/api
"""

import requests
import json
from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass
from enum import IntEnum

# %% Configuration
BASE_URL = "https://hero-sms.com/stubs/handler_api.php"

# Load API key from credentials
def load_api_key() -> str:
    import os
    cred_path = os.path.expanduser("~/Documents/api_cred.json")
    with open(cred_path) as f:
        creds = json.load(f)
    return creds["hero_sms"]["api_key"]

API_KEY = load_api_key()

# %% Enums
class ActivationStatus(IntEnum):
    """Activation status codes for setStatus"""
    SMS_SENT = 1        # Ready to receive SMS
    REQUEST_RESEND = 3  # Request SMS resend
    COMPLETE = 6        # Activation completed
    CANCEL = 8          # Cancel and refund

# %% Core Request Function
def _request(action: str, **params) -> Union[str, Dict, List]:
    """Make API request to HeroSMS"""
    params["action"] = action
    params["api_key"] = API_KEY
    
    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}
    
    response = requests.get(BASE_URL, params=params, timeout=30)
    response.raise_for_status()
    
    text = response.text.strip()
    
    # Try parsing as JSON first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text

# %% Balance
def get_balance() -> float:
    """
    Get current account balance
    Returns: Balance amount as float
    """
    result = _request("getBalance")
    # Format: ACCESS_BALANCE:<amount>
    if isinstance(result, str) and result.startswith("ACCESS_BALANCE:"):
        return float(result.split(":")[1])
    raise ValueError(f"Unexpected response: {result}")

# %% Get NumberP
def get_number(
    service: str,
    country: int,
    operator: Optional[str] = None,
    max_price: Optional[float] = None,
    fixed_price: Optional[float] = None,
    ref: Optional[str] = None
) -> tuple[int, str]:
    """
    Request a phone number for SMS activation
    
    Args:
        service: Service code (e.g., 'tg', 'wa', 'ig')
        country: Country ID
        operator: Operators (comma-separated, e.g., 'tele2,beeline')
        max_price: Maximum price limit
        fixed_price: Purchase at exact price (use with max_price)
        ref: Referral identifier
    
    Returns:
        Tuple of (activation_id, phone_number)
    """
    result = _request(
        "getNumber",
        service=service,
        country=country,
        operator=operator,
        maxPrice=max_price,
        fixedPrice=fixed_price,
        ref=ref
    )
    # Format: ACCESS_NUMBER:<activation_id>:<number>
    if isinstance(result, str) and result.startswith("ACCESS_NUMBER:"):
        parts = result.split(":")
        return int(parts[1]), parts[2]
    raise ValueError(f"Unexpected response: {result}")

# %% Get Number V2
def get_number_v2(
    service: str,
    country: int,
    operator: Optional[str] = None,
    max_price: Optional[float] = None,
    fixed_price: Optional[float] = None,
    ref: Optional[str] = None
) -> Dict[str, Any]:
    """
    Request a phone number (V2 - returns JSON with more details)
    
    Returns dict with:
        activationId, phoneNumber, activationCost, currency,
        countryCode, canGetAnotherSms, activationTime, activationOperator
    """
    return _request(
        "getNumberV2",
        service=service,
        country=country,
        operator=operator,
        maxPrice=max_price,
        fixedPrice=fixed_price,
        ref=ref
    )

# %% Set Status
def set_status(activation_id: int, status: ActivationStatus) -> str:
    """
    Change activation status
    
    Args:
        activation_id: Activation ID
        status: ActivationStatus enum value
            1 = SMS_SENT (ready to receive)
            3 = REQUEST_RESEND
            6 = COMPLETE
            8 = CANCEL (refund)
    
    Returns:
        Status string (e.g., 'ACCESS_READY', 'ACCESS_CANCEL')
    """
    return _request("setStatus", id=activation_id, status=int(status))

# Convenience methods
def mark_ready(activation_id: int) -> str:
    """Mark activation as ready to receive SMS"""
    return set_status(activation_id, ActivationStatus.SMS_SENT)

def request_resend(activation_id: int) -> str:
    """Request SMS resend"""
    return set_status(activation_id, ActivationStatus.REQUEST_RESEND)

def complete(activation_id: int) -> str:
    """Complete activation (code received)"""
    return set_status(activation_id, ActivationStatus.COMPLETE)

def cancel(activation_id: int) -> str:
    """Cancel activation and get refund"""
    return set_status(activation_id, ActivationStatus.CANCEL)

# %% Get Status
def get_status(activation_id: int) -> str:
    """
    Get current activation status
    
    Returns:
        Status string: STATUS_WAIT_CODE, STATUS_OK:<code>, STATUS_CANCEL, etc.
    """
    return _request("getStatus", id=activation_id)

def get_status_v2(activation_id: int) -> Dict[str, Any]:
    """
    Get activation status (V2 - structured JSON)
    
    Returns dict with:
        verificationType, sms (dateTime, code, text), call info
    """
    return _request("getStatusV2", id=activation_id)

# %% Active Activations
def get_active_activations(
    start: Optional[int] = None,
    limit: Optional[int] = None
) -> Dict[str, Any]:
    """
    Get list of active activations
    
    Args:
        start: Offset (default 0)
        limit: Max records (max 100)
    """
    return _request("getActiveActivations", start=start, limit=limit)

# %% History
def get_history(
    start: Optional[int] = None,
    end: Optional[int] = None,
    offset: Optional[int] = None,
    size: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Get activation history
    
    Args:
        start: Start of period (Unix timestamp)
        end: End of period (Unix timestamp)
        offset: Offset (default 0)
        size: Max records (max 100)
    """
    return _request("getHistory", start=start, end=end, offset=offset, size=size)

# %% Reference Data
def get_countries() -> List[Dict[str, Any]]:
    """Get list of available countries"""
    return _request("getCountries")

def get_services(
    country: Optional[int] = None,
    lang: str = "en"
) -> Dict[str, Any]:
    """
    Get list of available services
    
    Args:
        country: Filter by country ID
        lang: Language (ru, en, cn, es, pt, fr)
    """
    return _request("getServicesList", country=country, lang=lang)

def get_operators(country: Optional[int] = None) -> Dict[str, Any]:
    """Get list of operators (optionally filtered by country)"""
    return _request("getOperators", country=country)

def get_prices(
    service: Optional[str] = None,
    country: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Get current prices and available numbers
    
    Args:
        service: Filter by service code
        country: Filter by country ID
    """
    return _request("getPrices", service=service, country=country)

def get_top_countries(
    service: Optional[str] = None,
    free_price: Optional[bool] = None
) -> List[Dict[str, Any]]:
    """Get top countries by service with available numbers"""
    return _request(
        "getTopCountriesByService",
        service=service,
        freePrice=free_price
    )

def get_top_countries_by_rank(
    service: Optional[str] = None,
    free_price: Optional[bool] = None
) -> List[Dict[str, Any]]:
    """Get top countries by service based on user rank"""
    return _request(
        "getTopCountriesByServiceRank",
        service=service,
        freePrice=free_price
    )

# %% Example Usage
if __name__ == "__main__":
    # Check balance
    print(f"Balance: ${get_balance()}")
    
    # List countries
    # countries = get_countries()
    # print(f"Countries: {len(countries)}")
    
    # Get services for Kazakhstan (country=2)
    # services = get_services(country=2)
    # print(services)
    
    # %% Test - Balance
    print(f"Balance: ${get_balance()}")

    # %% Test - Countries
    countries = get_countries()
    for c in countries[:10]:
        print(f"{c['id']}: {c['eng']}")

    # %% Test - Services (Kazakhstan)
    services = get_services(country=2)
    if services.get("status") == "success":
        for svc in services["services"][:20]:
            print(f"{svc['code']}: {svc['name']}")

    # %% Test - Prices for Telegram in Kazakhstan
    prices = get_prices(service="tg", country=2)
    print(prices)

# %% Full Activation Flow Example
"""
# 1. Get a number for Telegram in Kazakhstan
activation_id, phone = get_number(service="tg", country=2)
print(f"Got number: {phone} (ID: {activation_id})")

# 2. Mark ready to receive SMS
mark_ready(activation_id)

# 3. Poll for code
import time
for _ in range(60):  # Wait up to 5 minutes
    status = get_status(activation_id)
    print(f"Status: {status}")
    
    if status.startswith("STATUS_OK:"):
        code = status.split(":")[1]
        print(f"Received code: {code}")
        complete(activation_id)
        break
    elif status == "STATUS_CANCEL":
        print("Activation cancelled")
        break
    
    time.sleep(5)
else:
    # Timeout - cancel and refund
    cancel(activation_id)
    print("Timeout - cancelled")
"""
