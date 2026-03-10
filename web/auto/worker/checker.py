#!/usr/bin/env python3
"""
Cloudflare Usage Checker - Check KV, D1, and Worker limits/usage
Uses cred_loader to get credentials from cred.json
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "linux" / "extra"))
from cred_loader import get_cloudflare


FREE_TIER_LIMITS = {
    "workers": {
        "requests": 100_000,
        "description": "Worker Requests/day"
    },
    "kv": {
        "reads": 100_000,
        "writes": 1_000,
        "storage_gb": 1,
        "description": "KV Operations/day"
    },
    "d1": {
        "rows_read": 5_000_000,
        "rows_written": 100_000,
        "storage_gb": 5,
        "description": "D1 Database/day"
    }
}


class CloudflareChecker:
    def __init__(self):
        creds = get_cloudflare()
        self.api_key = creds.get("global_api_key")
        self.email = creds.get("email")
        self.base_url = "https://api.cloudflare.com/client/v4"
        
        if not self.api_key or not self.email:
            raise ValueError("Missing global_api_key or email in credentials")
        
        self.headers = {
            "X-Auth-Email": self.email,
            "X-Auth-Key": self.api_key,
            "Content-Type": "application/json"
        }

    def _get(self, endpoint: str, params: dict = None) -> dict:
        url = f"{self.base_url}{endpoint}"
        resp = requests.get(url, headers=self.headers, params=params)
        resp.raise_for_status()
        return resp.json()

    def get_account_id(self) -> str:
        data = self._get("/accounts")
        if data["result"]:
            return data["result"][0]["id"]
        raise ValueError("No accounts found")

    def get_user_info(self) -> dict:
        return self._get("/user")

    def list_kv_namespaces(self, account_id: str) -> list:
        data = self._get(f"/accounts/{account_id}/storage/kv/namespaces")
        return data.get("result", [])

    def list_d1_databases(self, account_id: str) -> list:
        data = self._get(f"/accounts/{account_id}/d1/database")
        return data.get("result", [])

    def list_workers(self, account_id: str) -> list:
        data = self._get(f"/accounts/{account_id}/workers/scripts")
        return data.get("result", [])

    def get_worker_analytics(self, account_id: str, script_name: str = None) -> dict:
        """Get Worker analytics for the last 24 hours."""
        now = datetime.now(timezone.utc)
        since = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        until = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        
        endpoint = f"/accounts/{account_id}/workers/analytics/stored"
        params = {
            "since": since,
            "until": until,
        }
        if script_name:
            params["scriptName"] = script_name
        
        try:
            data = self._get(endpoint, params)
            return data.get("result", {})
        except requests.HTTPError:
            return {}

    def get_account_analytics(self, account_id: str) -> dict:
        """Get account-level analytics."""
        now = datetime.now(timezone.utc)
        since = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        until = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        
        query = """
        query {
          viewer {
            accounts(filter: {accountTag: "%s"}) {
              workersInvocationsAdaptive(limit: 1000, filter: {datetime_geq: "%s", datetime_leq: "%s"}) {
                sum {
                  requests
                  subrequests
                  errors
                }
              }
            }
          }
        }
        """ % (account_id, since, until)
        
        try:
            resp = requests.post(
                "https://api.cloudflare.com/client/v4/graphql",
                headers=self.headers,
                json={"query": query}
            )
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError:
            return {}

    def check_all(self) -> dict:
        """Check all usage and limits."""
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "account": {},
            "workers": [],
            "kv_namespaces": [],
            "d1_databases": [],
            "usage_summary": {},
            "free_tier_limits": FREE_TIER_LIMITS
        }
        
        # Get account info
        account_id = self.get_account_id()
        results["account"]["id"] = account_id
        
        user_info = self.get_user_info()
        results["account"]["email"] = user_info.get("result", {}).get("email", "N/A")
        
        # List Workers
        workers = self.list_workers(account_id)
        for w in workers:
            results["workers"].append({
                "name": w.get("id"),
                "created": w.get("created_on"),
                "modified": w.get("modified_on")
            })
        
        # List KV namespaces
        kv_ns = self.list_kv_namespaces(account_id)
        for ns in kv_ns:
            results["kv_namespaces"].append({
                "id": ns.get("id"),
                "title": ns.get("title")
            })
        
        # List D1 databases
        d1_dbs = self.list_d1_databases(account_id)
        for db in d1_dbs:
            results["d1_databases"].append({
                "uuid": db.get("uuid"),
                "name": db.get("name"),
                "created": db.get("created_at")
            })
        
        # Get analytics (GraphQL)
        analytics = self.get_account_analytics(account_id)
        
        total_requests = 0
        if analytics.get("data"):
            accounts = analytics["data"].get("viewer", {}).get("accounts", [])
            if accounts:
                invocations = accounts[0].get("workersInvocationsAdaptive", [])
                for inv in invocations:
                    total_requests += inv.get("sum", {}).get("requests", 0)
        
        results["usage_summary"] = {
            "worker_requests_24h": total_requests,
            "worker_requests_limit": FREE_TIER_LIMITS["workers"]["requests"],
            "worker_requests_remaining": FREE_TIER_LIMITS["workers"]["requests"] - total_requests,
            "worker_requests_percent_used": round(total_requests / FREE_TIER_LIMITS["workers"]["requests"] * 100, 2),
            "kv_namespaces_count": len(kv_ns),
            "d1_databases_count": len(d1_dbs),
            "workers_count": len(workers)
        }
        
        return results


def print_report(results: dict):
    """Print a formatted usage report."""
    print("\n" + "=" * 60)
    print("  CLOUDFLARE FREE TIER USAGE REPORT")
    print("=" * 60)
    print(f"  Timestamp: {results['timestamp']}")
    print(f"  Account ID: {results['account']['id']}")
    print(f"  Email: {results['account']['email']}")
    print("=" * 60)
    
    # Usage Summary
    usage = results["usage_summary"]
    print("\n📊 USAGE SUMMARY (Last 24 Hours)")
    print("-" * 40)
    
    # Worker Requests
    req_used = usage["worker_requests_24h"]
    req_limit = usage["worker_requests_limit"]
    req_remain = usage["worker_requests_remaining"]
    req_pct = usage["worker_requests_percent_used"]
    bar = progress_bar(req_pct)
    print(f"\n  Worker Requests:")
    print(f"    Used:      {req_used:,} / {req_limit:,}")
    print(f"    Remaining: {req_remain:,}")
    print(f"    {bar} {req_pct}%")
    
    # Free Tier Limits
    print("\n📋 FREE TIER LIMITS")
    print("-" * 40)
    limits = results["free_tier_limits"]
    
    print("\n  Workers:")
    print(f"    • Requests/day: {limits['workers']['requests']:,}")
    
    print("\n  KV (Key-Value):")
    print(f"    • Read ops/day:  {limits['kv']['reads']:,}")
    print(f"    • Write ops/day: {limits['kv']['writes']:,}")
    print(f"    • Storage:       {limits['kv']['storage_gb']} GB")
    
    print("\n  D1 (SQL Database):")
    print(f"    • Rows read/day:    {limits['d1']['rows_read']:,}")
    print(f"    • Rows written/day: {limits['d1']['rows_written']:,}")
    print(f"    • Storage:          {limits['d1']['storage_gb']} GB")
    
    # Resources
    print("\n📦 RESOURCES")
    print("-" * 40)
    print(f"\n  Workers ({usage['workers_count']}):")
    for w in results["workers"]:
        print(f"    • {w['name']}")
    
    print(f"\n  KV Namespaces ({usage['kv_namespaces_count']}):")
    for ns in results["kv_namespaces"]:
        print(f"    • {ns['title']} ({ns['id'][:8]}...)")
    
    print(f"\n  D1 Databases ({usage['d1_databases_count']}):")
    for db in results["d1_databases"]:
        print(f"    • {db['name']} ({db['uuid'][:8]}...)")
    
    print("\n" + "=" * 60)
    print("  💡 TIP: Use Webhooks to minimize KV/D1 writes")
    print("=" * 60 + "\n")


def progress_bar(percent: float, width: int = 20) -> str:
    """Create a progress bar."""
    filled = int(width * percent / 100)
    empty = width - filled
    if percent < 50:
        color = "🟢"
    elif percent < 80:
        color = "🟡"
    else:
        color = "🔴"
    return f"[{'█' * filled}{'░' * empty}] {color}"


def main():
    try:
        checker = CloudflareChecker()
        results = checker.check_all()
        print_report(results)
        return results
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
