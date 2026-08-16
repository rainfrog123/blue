#!/usr/bin/env python3
"""
Caixin Authentication Script

Manually retrieves auth cookies from Caixin login API.
"""

import re
import json
import time
import subprocess
from urllib.parse import quote
import requests


def encrypt_password(password: str) -> str:
    """
    Encrypt password using AES-128-ECB.
    Uses openssl command since pycryptodome may not be installed.
    
    Key: G3JH98Y8MY9GWKWG
    Mode: ECB
    Padding: PKCS7
    """
    key_hex = "G3JH98Y8MY9GWKWG".encode().hex()
    
    result = subprocess.run(
        ["openssl", "enc", "-aes-128-ecb", "-K", key_hex, "-a"],
        input=password.encode(),
        capture_output=True
    )
    
    if result.returncode != 0:
        raise RuntimeError(f"OpenSSL encryption failed: {result.stderr.decode()}")
    
    encrypted_b64 = result.stdout.decode().strip()
    return quote(encrypted_b64)


def parse_jsonp(response_text: str) -> dict:
    """Extract JSON from JSONP response."""
    match = re.search(r'__caixincallback\d+\((.*)\)', response_text, re.DOTALL)
    if not match:
        raise ValueError(f"Failed to parse JSONP response: {response_text[:200]}")
    return json.loads(match.group(1))


def build_cookies_from_response(data: dict) -> dict:
    """
    Build auth cookies from login response data.
    
    The browser JS normally sets these cookies after receiving the JSONP response.
    We reconstruct them manually here.
    """
    user_data = data.get("data", {})
    
    cookies = {
        "SA_USER_auth": user_data.get("userAuth", ""),
        "UID": user_data.get("uid", ""),
        "SA_USER_UID": user_data.get("uid", ""),
        "SA_USER_NICK_NAME": quote(user_data.get("nickname", ""), safe=""),
        "SA_USER_USER_NAME": user_data.get("mobile", ""),
        "SA_USER_UNIT": user_data.get("unit", "1"),
        "SA_USER_DEVICE_TYPE": user_data.get("deviceType", "5"),
        "USER_LOGIN_CODE": user_data.get("code", ""),
        "SA_AUTH_TYPE": quote(user_data.get("authType", ""), safe=""),
    }
    
    return cookies


def login(account: str, password: str, area_code: str = "+86") -> dict:
    """
    Login to Caixin and retrieve auth cookies.
    
    Args:
        account: Phone number
        password: Plaintext password (will be encrypted)
        area_code: Country code (default: +86 for China)
    
    Returns:
        dict with 'cookies', 'user_info', and 'response'
    """
    session = requests.Session()
    
    # Set common headers
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en-GB;q=0.9,en;q=0.8",
        "Referer": "https://u.caixin.com/",
    })
    
    # Encrypt password
    encrypted_password = encrypt_password(password)
    
    # Build login request
    callback = f"__caixincallback{int(time.time() * 1000)}"
    params = {
        "account": account,
        "password": encrypted_password,
        "deviceType": "5",
        "unit": "1",
        "areaCode": area_code,
        "extend": json.dumps({"resource_article": ""}),
        "callback": callback,
    }
    
    url = "https://gateway.caixin.com/api/ucenter/user/v1/loginJsonp"
    
    print(f"[*] Logging in as {account}...")
    response = session.get(url, params=params)
    
    if response.status_code != 200:
        raise RuntimeError(f"Login request failed: HTTP {response.status_code}")
    
    # Parse JSONP response
    data = parse_jsonp(response.text)
    
    if data.get("code") != 0:
        raise RuntimeError(f"Login failed: {data.get('msg')} (code: {data.get('code')})")
    
    print(f"[+] Login successful!")
    
    # Build cookies from response data
    cookies = build_cookies_from_response(data)
    
    # Set cookies in session for subsequent requests
    for name, value in cookies.items():
        session.cookies.set(name, value, domain=".caixin.com")
    
    # Fetch user info with auth cookies
    print("[*] Fetching user info...")
    userinfo_url = f"https://gateway.caixin.com/api/ucenter/userinfo/get?_t={int(time.time() * 1000)}"
    userinfo_response = session.get(userinfo_url)
    userinfo = userinfo_response.json() if userinfo_response.status_code == 200 else None
    
    return {
        "cookies": cookies,
        "user_info": userinfo,
        "login_response": data,
    }


def check_session_valid(cookies: dict) -> tuple[bool, str]:
    """
    Check if session is still valid.
    
    Returns:
        (is_valid, message)
    
    Error codes:
        600 - Not logged in
        500 - Session invalid / please login
        601 - Session kicked by another device (unconfirmed)
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    })
    
    # Set cookies
    for name, value in cookies.items():
        session.cookies.set(name, value, domain=".caixin.com")
    
    # Check via userinfo API
    url = f"https://gateway.caixin.com/api/ucenter/userinfo/get?_t={int(time.time() * 1000)}"
    response = session.get(url)
    
    try:
        data = response.json()
        code = data.get("code", -1)
        msg = data.get("msg", "")
        
        if code == 0:
            return True, "Session valid"
        elif code == 600:
            return False, "Not logged in (code 600)"
        elif code == 500:
            return False, "Session invalid (code 500)"
        elif code in (601, 602, 603):
            return False, f"Session kicked - {msg} (code {code})"
        else:
            return False, f"Unknown error: {msg} (code {code})"
    except Exception as e:
        return False, f"Error checking session: {e}"


def print_auth_info(auth: dict):
    """Pretty print authentication info."""
    print("\n" + "=" * 60)
    print("AUTHENTICATION COOKIES")
    print("=" * 60)
    
    for name, value in auth["cookies"].items():
        print(f"{name}: {value}")
    
    print("\n" + "=" * 60)
    print("LOGIN RESPONSE")
    print("=" * 60)
    print(json.dumps(auth["login_response"], indent=2, ensure_ascii=False))
    
    if auth.get("user_info"):
        print("\n" + "=" * 60)
        print("USER INFO")
        print("=" * 60)
        print(json.dumps(auth["user_info"], indent=2, ensure_ascii=False))
    
    # Export as cookie string for use in requests/curl
    print("\n" + "=" * 60)
    print("COOKIE STRING (for curl/requests)")
    print("=" * 60)
    cookie_str = "; ".join([f"{k}={v}" for k, v in auth["cookies"].items()])
    print(cookie_str)


def monitor_session(cookies: dict, interval: int = 60, auto_relogin: bool = False,
                     account: str = None, password: str = None):
    """
    Monitor session and detect kicks.
    
    Args:
        cookies: Auth cookies to monitor
        interval: Check interval in seconds
        auto_relogin: If True, automatically re-login when kicked
        account: Account for re-login
        password: Password for re-login
    """
    print(f"\n[*] Monitoring session (interval: {interval}s)...")
    print("[*] Press Ctrl+C to stop\n")
    
    while True:
        try:
            is_valid, message = check_session_valid(cookies)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            
            if is_valid:
                print(f"[{timestamp}] ✓ {message}")
            else:
                print(f"[{timestamp}] ✗ {message}")
                
                if auto_relogin and account and password:
                    print(f"[{timestamp}] → Auto re-login...")
                    try:
                        auth = login(account, password)
                        cookies.update(auth["cookies"])
                        print(f"[{timestamp}] ✓ Re-login successful")
                        
                        # Save new cookies
                        with open("auth_cookies.json", "w") as f:
                            json.dump({"cookies": cookies}, f, indent=2)
                    except Exception as e:
                        print(f"[{timestamp}] ✗ Re-login failed: {e}")
                else:
                    print(f"[{timestamp}] ! Session lost. Re-run script to login.")
                    break
            
            time.sleep(interval)
            
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped")
            break


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Caixin Authentication")
    parser.add_argument("--monitor", action="store_true", help="Monitor session after login")
    parser.add_argument("--interval", type=int, default=60, help="Monitor interval in seconds")
    parser.add_argument("--auto-relogin", action="store_true", help="Auto re-login when kicked")
    parser.add_argument("--check", action="store_true", help="Check existing session from auth_cookies.json")
    args = parser.parse_args()
    
    # Configuration
    ACCOUNT = "19282708311"
    PASSWORD = "Aa@19282708311"
    AREA_CODE = "+86"
    
    try:
        if args.check:
            # Check existing session
            with open("auth_cookies.json", "r") as f:
                data = json.load(f)
            cookies = data.get("cookies", {})
            is_valid, message = check_session_valid(cookies)
            print(f"Session status: {message}")
            
            if args.monitor:
                monitor_session(cookies, args.interval, args.auto_relogin, ACCOUNT, PASSWORD)
        else:
            # Login and get new session
            auth = login(ACCOUNT, PASSWORD, AREA_CODE)
            print_auth_info(auth)
            
            # Save to file
            with open("auth_cookies.json", "w") as f:
                json.dump(auth, f, indent=2, ensure_ascii=False)
            print(f"\n[+] Auth data saved to auth_cookies.json")
            
            if args.monitor:
                monitor_session(auth["cookies"], args.interval, args.auto_relogin, ACCOUNT, PASSWORD)
        
    except FileNotFoundError:
        print("[!] auth_cookies.json not found. Run without --check to login first.")
    except Exception as e:
        print(f"[!] Error: {e}")
        raise


if __name__ == "__main__":
    main()
