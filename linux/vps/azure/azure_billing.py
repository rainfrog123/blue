#%% Imports and Setup
import os
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

# Find blue root (contains cred.json) and add to path for imports
_file = Path(__file__).resolve()
for parent in _file.parents:
    if (parent / "cred.json").exists():
        sys.path.insert(0, str(parent / "linux" / "extra"))
        break
from cred_loader import get_azure

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.subscription import SubscriptionClient
    from azure.mgmt.costmanagement import CostManagementClient
    from azure.mgmt.consumption import ConsumptionManagementClient
    from azure.mgmt.billing import BillingManagementClient
except ImportError:
    print("Installing Azure billing packages...")
    os.system("pip install azure-identity azure-mgmt-subscription azure-mgmt-costmanagement azure-mgmt-consumption azure-mgmt-billing")
    from azure.identity import ClientSecretCredential
    from azure.mgmt.subscription import SubscriptionClient
    from azure.mgmt.costmanagement import CostManagementClient
    from azure.mgmt.consumption import ConsumptionManagementClient
    from azure.mgmt.billing import BillingManagementClient

#%% Load Credentials
creds = get_azure()

CLIENT_ID = creds["client_id"]
TENANT_ID = creds["tenant_id"]
CLIENT_SECRET = creds["client_secret"]

credential = ClientSecretCredential(
    tenant_id=TENANT_ID,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET
)

print(f"Authenticated with Azure (Tenant: {TENANT_ID[:8]}...)")

#%% Get Subscription
SUBSCRIPTION_ID = creds.get("subscription_id")

if not SUBSCRIPTION_ID:
    sub_client = SubscriptionClient(credential)
    subscriptions = list(sub_client.subscriptions.list())
    SUBSCRIPTION_ID = subscriptions[0].subscription_id if subscriptions else None

print(f"Using subscription: {SUBSCRIPTION_ID}")

#%% Initialize Billing Clients
if SUBSCRIPTION_ID:
    cost_client = CostManagementClient(credential)
    consumption_client = ConsumptionManagementClient(credential, SUBSCRIPTION_ID)
    billing_client = BillingManagementClient(credential, SUBSCRIPTION_ID)

#%% Helper functions
def _now():
    """Get current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)

def _format_date(dt):
    """Format datetime as ISO 8601 string for Azure API."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

#%% Check Credit Balance
def get_credit_balance():
    """Check remaining Azure credits (for free trial/sponsored accounts)."""
    print(f"\n{'='*60}")
    print("Azure Credit Balance:")
    print(f"{'='*60}")
    
    # First, check subscription details
    try:
        sub_client = SubscriptionClient(credential)
        sub = sub_client.subscriptions.get(SUBSCRIPTION_ID)
        print(f"  Subscription: {sub.display_name}")
        print(f"  State: {sub.state}")
        if hasattr(sub, 'subscription_policies') and sub.subscription_policies:
            policies = sub.subscription_policies
            if hasattr(policies, 'spending_limit'):
                print(f"  Spending Limit: {policies.spending_limit}")
            if hasattr(policies, 'quota_id'):
                quota = policies.quota_id
                print(f"  Offer Type: {quota}")
                if 'FreeTrial' in str(quota) or 'MSDN' in str(quota) or 'Sponsored' in str(quota):
                    print("  (This appears to be a credit-based subscription)")
    except Exception as e:
        print(f"  Could not get subscription details: {e}")
    
    # Try to get credit info from billing accounts
    try:
        print("\n  Checking billing accounts...")
        accounts = list(billing_client.billing_accounts.list())
        
        if not accounts:
            print("  No billing accounts accessible (normal for some subscription types)")
        
        for account in accounts:
            account_name = account.name
            print(f"  Found billing account: {account.display_name}")
            
            # Try to get billing profiles
            try:
                profiles = list(billing_client.billing_profiles.list_by_billing_account(account_name))
                for profile in profiles:
                    profile_name = profile.name
                    print(f"    Billing profile: {profile.display_name}")
                    
                    # Try available balance
                    try:
                        balance = billing_client.available_balances.get_by_billing_profile(
                            account_name, profile_name
                        )
                        if balance and balance.amount:
                            print(f"\n  *** Available Credit: ${balance.amount.value:.2f} {balance.amount.currency} ***")
                            return balance.amount.value
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception as e:
        print(f"  Billing API error: {type(e).__name__}")
    
    # Fallback: estimate from usage
    print("\n  Estimating from usage data...")
    
    try:
        today = _now()
        start_date = _format_date(today - timedelta(days=30))
        end_date = _format_date(today)
        
        query = {
            "type": "ActualCost",
            "timeframe": "Custom",
            "time_period": {"from": start_date, "to": end_date},
            "dataset": {
                "granularity": "None",
                "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}}
            }
        }
        
        result = cost_client.query.usage(f"/subscriptions/{SUBSCRIPTION_ID}", query)
        if result.rows and result.rows[0][0] > 0:
            spent = result.rows[0][0]
            FREE_TRIAL_CREDIT = 200.0
            remaining = FREE_TRIAL_CREDIT - spent
            print(f"  Usage (last 30 days): ${spent:.2f}")
            print(f"  *** Estimated remaining (of $200): ${max(0, remaining):.2f} ***")
            return remaining
        else:
            print("  No usage recorded - full $200 credit likely available")
            print("\n  TIP: To see exact credit balance, check Azure Portal:")
            print("       https://portal.azure.com/#view/Microsoft_Azure_GTM/ModernBillingMenuBlade/~/BillingAccounts")
            return 200.0
    except Exception as e:
        print(f"  Error: {e}")
        print("\n  TIP: Check credit balance in Azure Portal:")
        print("       https://portal.azure.com/#view/Microsoft_Azure_GTM/ModernBillingMenuBlade/~/BillingAccounts")
        return None

#%% Get Current Month Cost
def get_current_month_cost():
    """Get cost for current billing period."""
    today = _now()
    start_dt = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    start_date = _format_date(start_dt)
    end_date = _format_date(today)
    
    scope = f"/subscriptions/{SUBSCRIPTION_ID}"
    
    query = {
        "type": "ActualCost",
        "timeframe": "Custom",
        "time_period": {
            "from": start_date,
            "to": end_date
        },
        "dataset": {
            "granularity": "None",
            "aggregation": {
                "totalCost": {
                    "name": "Cost",
                    "function": "Sum"
                }
            }
        }
    }
    
    print(f"\n{'='*60}")
    print(f"Current Month Cost ({start_dt.strftime('%Y-%m-%d')} to {today.strftime('%Y-%m-%d')}):")
    print(f"{'='*60}")
    
    try:
        result = cost_client.query.usage(scope, query)
        if result.rows:
            cost = result.rows[0][0]
            currency = result.columns[0].name if result.columns else "USD"
            print(f"  Total: ${cost:.2f}")
            return cost
        else:
            print("  No cost data available")
            return 0
    except Exception as e:
        print(f"  Error: {e}")
        return None

#%% Get Cost by Service
def get_cost_by_service(days: int = 30):
    """Get cost breakdown by service for last N days."""
    today = _now()
    start_date = _format_date(today - timedelta(days=days))
    end_date = _format_date(today)
    
    scope = f"/subscriptions/{SUBSCRIPTION_ID}"
    
    query = {
        "type": "ActualCost",
        "timeframe": "Custom",
        "time_period": {
            "from": start_date,
            "to": end_date
        },
        "dataset": {
            "granularity": "None",
            "aggregation": {
                "totalCost": {
                    "name": "Cost",
                    "function": "Sum"
                }
            },
            "grouping": [
                {
                    "type": "Dimension",
                    "name": "ServiceName"
                }
            ]
        }
    }
    
    print(f"\n{'='*60}")
    print(f"Cost by Service (last {days} days):")
    print(f"{'='*60}")
    
    try:
        result = cost_client.query.usage(scope, query)
        services = []
        if result.rows:
            for row in sorted(result.rows, key=lambda x: x[0], reverse=True):
                cost, service = row[0], row[1]
                if cost > 0.01:
                    print(f"  ${cost:>10.2f}  {service}")
                    services.append({"service": service, "cost": cost})
        else:
            print("  No cost data available")
        return services
    except Exception as e:
        print(f"  Error: {e}")
        return []

#%% Get Cost by Resource Group
def get_cost_by_resource_group(days: int = 30):
    """Get cost breakdown by resource group for last N days."""
    today = _now()
    start_date = _format_date(today - timedelta(days=days))
    end_date = _format_date(today)
    
    scope = f"/subscriptions/{SUBSCRIPTION_ID}"
    
    query = {
        "type": "ActualCost",
        "timeframe": "Custom",
        "time_period": {
            "from": start_date,
            "to": end_date
        },
        "dataset": {
            "granularity": "None",
            "aggregation": {
                "totalCost": {
                    "name": "Cost",
                    "function": "Sum"
                }
            },
            "grouping": [
                {
                    "type": "Dimension",
                    "name": "ResourceGroup"
                }
            ]
        }
    }
    
    print(f"\n{'='*60}")
    print(f"Cost by Resource Group (last {days} days):")
    print(f"{'='*60}")
    
    try:
        result = cost_client.query.usage(scope, query)
        groups = []
        if result.rows:
            for row in sorted(result.rows, key=lambda x: x[0], reverse=True):
                cost, rg = row[0], row[1] or "(unassigned)"
                if cost > 0.01:
                    print(f"  ${cost:>10.2f}  {rg}")
                    groups.append({"resource_group": rg, "cost": cost})
        else:
            print("  No cost data available")
        return groups
    except Exception as e:
        print(f"  Error: {e}")
        return []

#%% Get Daily Cost Trend
def get_daily_cost(days: int = 7):
    """Get daily cost for last N days."""
    today = _now()
    start_date = _format_date(today - timedelta(days=days))
    end_date = _format_date(today)
    
    scope = f"/subscriptions/{SUBSCRIPTION_ID}"
    
    query = {
        "type": "ActualCost",
        "timeframe": "Custom",
        "time_period": {
            "from": start_date,
            "to": end_date
        },
        "dataset": {
            "granularity": "Daily",
            "aggregation": {
                "totalCost": {
                    "name": "Cost",
                    "function": "Sum"
                }
            }
        }
    }
    
    print(f"\n{'='*60}")
    print(f"Daily Cost (last {days} days):")
    print(f"{'='*60}")
    
    try:
        result = cost_client.query.usage(scope, query)
        daily = []
        if result.rows:
            for row in result.rows:
                cost = row[0]
                date_val = row[1]
                if isinstance(date_val, int):
                    date_str = str(date_val)
                    date_str = f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:8]}"
                else:
                    date_str = str(date_val)[:10]
                print(f"  {date_str}  ${cost:>8.2f}")
                daily.append({"date": date_str, "cost": cost})
        else:
            print("  No cost data available")
        return daily
    except Exception as e:
        print(f"  Error: {e}")
        return []

#%% Get Usage Details
def get_usage_details(days: int = 7, top: int = 20):
    """Get detailed usage for last N days."""
    today = _now()
    start_date = (today - timedelta(days=days)).strftime("%Y-%m-%d")
    end_date = today.strftime("%Y-%m-%d")
    
    print(f"\n{'='*60}")
    print(f"Usage Details (last {days} days, top {top}):")
    print(f"{'='*60}")
    
    try:
        usage_list = list(consumption_client.usage_details.list(
            scope=f"/subscriptions/{SUBSCRIPTION_ID}",
            filter=f"properties/usageStart ge '{start_date}' and properties/usageEnd le '{end_date}'",
            top=top
        ))
        
        if not usage_list:
            print("  No usage data available")
            return []
        
        details = []
        for usage in usage_list:
            props = usage.as_dict()
            cost = props.get("cost_in_billing_currency") or props.get("cost") or 0
            resource = props.get("resource_name") or props.get("instance_name") or "Unknown"
            meter = props.get("meter_name") or props.get("meter_category") or "Unknown"
            print(f"  ${cost:>8.2f}  {resource[:30]:<30}  {meter[:25]}")
            details.append(props)
        
        return details
    except Exception as e:
        print(f"  Error: {e}")
        return []

#%% Get Budgets
def list_budgets():
    """List all budgets for the subscription."""
    print(f"\n{'='*60}")
    print("Budgets:")
    print(f"{'='*60}")
    
    try:
        scope = f"/subscriptions/{SUBSCRIPTION_ID}"
        budgets = list(consumption_client.budgets.list(scope))
        
        if not budgets:
            print("  No budgets configured")
            return []
        
        for budget in budgets:
            print(f"  {budget.name}:")
            print(f"    Amount: ${budget.amount:.2f}")
            print(f"    Time Grain: {budget.time_grain}")
            if budget.current_spend:
                print(f"    Current Spend: ${budget.current_spend.amount:.2f}")
        
        return budgets
    except Exception as e:
        print(f"  Error: {e}")
        return []

#%% Get Billing Accounts
def list_billing_accounts():
    """List billing accounts."""
    print(f"\n{'='*60}")
    print("Billing Accounts:")
    print(f"{'='*60}")
    
    try:
        accounts = list(billing_client.billing_accounts.list())
        
        if not accounts:
            print("  No billing accounts found")
            return []
        
        for account in accounts:
            print(f"  {account.display_name}")
            print(f"    ID: {account.name}")
            print(f"    Type: {account.account_type}")
        
        return accounts
    except Exception as e:
        print(f"  Error: {e}")
        return []

#%% Get Invoices
def list_invoices(top: int = 5):
    """List recent invoices."""
    print(f"\n{'='*60}")
    print(f"Recent Invoices (top {top}):")
    print(f"{'='*60}")
    
    try:
        invoices = list(billing_client.invoices.list_by_billing_subscription(
            period_start_date=None,
            period_end_date=None
        ))[:top]
        
        if not invoices:
            print("  No invoices found")
            return []
        
        for inv in invoices:
            status = inv.status or "Unknown"
            amount = inv.total_amount.value if inv.total_amount else 0
            currency = inv.total_amount.currency if inv.total_amount else "USD"
            print(f"  {inv.name}: ${amount:.2f} {currency} ({status})")
        
        return invoices
    except Exception as e:
        print(f"  Error: {e}")
        return []

#%% Cost Forecast
def get_forecast(days: int = 30):
    """Get cost forecast for next N days."""
    today = _now()
    start_date = _format_date(today)
    end_date = _format_date(today + timedelta(days=days))
    
    scope = f"/subscriptions/{SUBSCRIPTION_ID}"
    
    query = {
        "type": "ActualCost",
        "timeframe": "Custom",
        "time_period": {
            "from": start_date,
            "to": end_date
        },
        "dataset": {
            "granularity": "Daily",
            "aggregation": {
                "totalCost": {
                    "name": "Cost",
                    "function": "Sum"
                }
            }
        },
        "include_actual_cost": True,
        "include_fresh_partial_cost": True
    }
    
    print(f"\n{'='*60}")
    print(f"Cost Forecast (next {days} days):")
    print(f"{'='*60}")
    
    try:
        result = cost_client.forecast.usage(scope, query)
        forecast = []
        total = 0
        if result.rows:
            for row in result.rows[-7:]:
                cost = row[0]
                total += cost
            print(f"  Projected total: ${total:.2f}")
        else:
            print("  No forecast data available")
        return total
    except Exception as e:
        print(f"  Forecast not available: {e}")
        return None

#%% Billing Summary
def billing_summary():
    """Show complete billing summary."""
    if not SUBSCRIPTION_ID:
        print("No subscription available!")
        return
    
    get_credit_balance()
    get_current_month_cost()
    get_daily_cost(7)
    get_cost_by_service(30)
    get_cost_by_resource_group(30)
    list_budgets()

#%% Interactive Usage
if __name__ == "__main__":
    print("\n" + "="*60)
    print("Azure Billing Management Ready")
    print("="*60)
    print("""
Usage Examples:
    billing_summary()                # Full billing overview
    get_credit_balance()             # Check remaining credits
    
    get_current_month_cost()         # Current month total
    get_daily_cost(7)                # Daily cost for 7 days
    get_daily_cost(30)               # Daily cost for 30 days
    
    get_cost_by_service(30)          # Cost breakdown by service
    get_cost_by_resource_group(30)   # Cost by resource group
    
    get_usage_details(7, 20)         # Detailed usage (7 days, top 20)
    get_forecast(30)                 # 30-day forecast
    
    list_budgets()                   # Show configured budgets
    list_billing_accounts()          # List billing accounts
    list_invoices(5)                 # Recent invoices
    """)
    # billing_summary() 
    get_credit_balance()             # Check remaining credits

    