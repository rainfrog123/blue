#!/usr/bin/env python3
"""Azure manager - unified management for VMs, resources, billing, and proxies."""
import sys
import time
import argparse
from datetime import datetime, timedelta, timezone

from core import get_clients

# Unique ClientType moves our calls out of the shared (empty-ClientType) throttle
# pool that Azure Cost Management rate-limits globally across all anonymous callers.
_CLIENT_TYPE = "blue-vps-cli"
_COST_HEADERS = {
    "ClientType": _CLIENT_TYPE,
    "x-ms-command-name": f"{_CLIENT_TYPE}/cost",
}


def _retry_429(fn, *args, retries=5, **kwargs):
    """Call fn with exponential backoff on Azure 429 throttling responses."""
    for attempt in range(retries):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            if "429" in str(e) and attempt < retries - 1:
                wait = 15 * (2 ** attempt)
                print(f"  Rate limited, retrying in {wait}s...", flush=True)
                time.sleep(wait)
            else:
                raise


def _last_calendar_month(today=None):
    """Return (label, from_iso, to_iso) for the previous calendar month."""
    today = today or datetime.now(timezone.utc)
    first_this_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    last_prev = first_this_month - timedelta(days=1)
    first_prev = last_prev.replace(day=1)
    label = first_prev.strftime("%B %Y")
    return (
        label,
        first_prev.strftime("%Y-%m-%dT00:00:00Z"),
        first_this_month.strftime("%Y-%m-%dT00:00:00Z"),
    )


def _cost_query(clients, sub_id, query, retries=5):
    """Run a cost query with backoff on rate limits and a unique ClientType."""
    scope = f"/subscriptions/{sub_id}"
    return _retry_429(
        clients.cost.query.usage,
        scope,
        query,
        headers=dict(_COST_HEADERS),
        retries=retries,
    )


def _build_cost_query(date_from, date_to, granularity="None", group_by=None):
    dataset = {
        "granularity": granularity,
        "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}},
    }
    if group_by:
        dataset["grouping"] = [{"type": "Dimension", "name": group_by}]
    return {
        "type": "ActualCost",
        "timeframe": "Custom",
        "time_period": {"from": date_from, "to": date_to},
        "dataset": dataset,
    }


def cmd_status(args):
    """Show VM status."""
    clients = get_clients(args.account)
    vms = list(clients.compute.virtual_machines.list_all())
    
    if not vms:
        print("No VMs found.")
        return
    
    for vm in vms:
        rg = vm.id.split('/')[4]
        instance = clients.compute.virtual_machines.get(rg, vm.name, expand='instanceView')
        statuses = instance.instance_view.statuses if instance.instance_view else []
        power = next((s.display_status for s in statuses if s.code.startswith('PowerState')), 'Unknown')
        
        public_ip = private_ip = None
        if instance.network_profile and instance.network_profile.network_interfaces:
            nic_id = instance.network_profile.network_interfaces[0].id
            nic_name, nic_rg = nic_id.split('/')[-1], nic_id.split('/')[4]
            try:
                nic = clients.network.network_interfaces.get(nic_rg, nic_name)
                if nic.ip_configurations:
                    ip_cfg = nic.ip_configurations[0]
                    private_ip = ip_cfg.private_ip_address
                    if ip_cfg.public_ip_address:
                        pip_id = ip_cfg.public_ip_address.id
                        pip = clients.network.public_ip_addresses.get(pip_id.split('/')[4], pip_id.split('/')[-1])
                        public_ip = pip.ip_address
            except Exception:
                pass
        
        os_type = instance.storage_profile.os_disk.os_type if instance.storage_profile else "Unknown"
        disk_size = instance.storage_profile.os_disk.disk_size_gb if instance.storage_profile and instance.storage_profile.os_disk else None
        
        print(f"\n{'='*50}")
        print(f"VM: {vm.name}")
        print(f"{'='*50}")
        print(f"  Resource Group: {rg}")
        print(f"  Location:       {vm.location}")
        print(f"  Size:           {vm.hardware_profile.vm_size}")
        print(f"  Status:         {power}")
        print(f"  OS:             {os_type}")
        print(f"  OS Disk:        {disk_size or 'N/A'} GB")
        print(f"  Private IP:     {private_ip or 'N/A'}")
        print(f"  Public IP:      {public_ip or '(not allocated)'}")
        if public_ip:
            print(f"  SSH:            ssh azureuser@{public_ip}")


def cmd_start(args):
    """Start all VMs."""
    clients = get_clients(args.account)
    vms = list(clients.compute.virtual_machines.list_all())
    if not vms:
        print("No VMs found.")
        return
    for vm in vms:
        rg = vm.id.split('/')[4]
        print(f"Starting {vm.name}...", end=" ", flush=True)
        clients.compute.virtual_machines.begin_start(rg, vm.name).result()
        print("done")


def cmd_stop(args):
    """Deallocate all VMs (stops billing)."""
    clients = get_clients(args.account)
    vms = list(clients.compute.virtual_machines.list_all())
    if not vms:
        print("No VMs found.")
        return
    for vm in vms:
        rg = vm.id.split('/')[4]
        print(f"Deallocating {vm.name}...", end=" ", flush=True)
        clients.compute.virtual_machines.begin_deallocate(rg, vm.name).result()
        print("done")


def cmd_restart(args):
    """Restart all VMs."""
    clients = get_clients(args.account)
    vms = list(clients.compute.virtual_machines.list_all())
    if not vms:
        print("No VMs found.")
        return
    for vm in vms:
        rg = vm.id.split('/')[4]
        print(f"Restarting {vm.name}...", end=" ", flush=True)
        clients.compute.virtual_machines.begin_restart(rg, vm.name).result()
        print("done")


def cmd_sub(args):
    """Show subscription information."""
    clients = get_clients(args.account)
    sub = clients.subscription.subscriptions.get(clients.subscription_id)
    
    print(f"\n{'='*50}")
    print("Subscription")
    print(f"{'='*50}")
    print(f"  Account:        {clients.account}")
    print(f"  Name:           {sub.display_name}")
    print(f"  ID:             {sub.subscription_id}")
    print(f"  State:          {sub.state}")
    
    if hasattr(sub, 'subscription_policies') and sub.subscription_policies:
        p = sub.subscription_policies
        if hasattr(p, 'spending_limit'):
            print(f"  Spending Limit: {p.spending_limit}")
        if hasattr(p, 'quota_id'):
            print(f"  Offer Type:     {p.quota_id}")


def cmd_resources(args):
    """List all resources."""
    clients = get_clients(args.account)
    
    print(f"\n{'='*50}")
    print("Resource Groups")
    print(f"{'='*50}")
    rgs = list(clients.resource.resource_groups.list())
    if not rgs:
        print("  None")
    else:
        for rg in rgs:
            print(f"  {rg.name} ({rg.location})")
    
    print(f"\n{'='*50}")
    print("Resources")
    print(f"{'='*50}")
    resources = list(clients.resource.resources.list())
    if not resources:
        print("  None")
    else:
        by_type = {}
        for r in resources:
            t = r.type.split('/')[-1]
            by_type.setdefault(t, []).append(r.name)
        for t, names in sorted(by_type.items()):
            print(f"  {t}: {len(names)}")
            for n in names:
                print(f"    - {n}")


def _usage_detail_fields(item):
    """Normalize Legacy/Modern usage-detail rows to (name, meter, cost)."""
    name = (
        getattr(item, "resource_name", None)
        or getattr(item, "instance_name", None)
        or "(unknown resource)"
    )
    # instance_name is often a full resource ID; show only the resource name.
    if isinstance(name, str) and "/" in name:
        name = name.rstrip("/").split("/")[-1]
    meter = (
        getattr(item, "meter_name", None)
        or getattr(item, "product", None)
        or ""
    )
    cost = getattr(item, "cost", None)
    if cost is None:
        cost = getattr(item, "cost_in_billing_currency", None)
    if cost is None:
        cost = getattr(item, "cost_in_usd", None)
    return name, meter, float(cost or 0)


def cmd_cost(args):
    """Show cost information."""
    clients = get_clients(args.account)
    sub_id = clients.subscription_id
    today = datetime.now(timezone.utc)

    month_label, month_from, month_to = _last_calendar_month(today)
    print(f"\n{'='*50}")
    print(f"Billed Last Month ({month_label})")
    print(f"{'='*50}")
    print(f"  Period: {month_from[:10]} to {month_to[:10]}")

    try:
        result = _cost_query(
            clients,
            sub_id,
            _build_cost_query(month_from, month_to, group_by="ServiceName"),
        )
        if not result.rows:
            print("  No billing data")
        else:
            total = 0.0
            for row in sorted(result.rows, key=lambda r: float(r[0] or 0), reverse=True):
                cost = float(row[0] or 0)
                if cost == 0:
                    continue
                svc = row[1] if len(row) > 1 else "Unknown"
                print(f"  {svc}: ${cost:.2f}")
                total += cost
            print(f"  {'-'*40}")
            print(f"  Total: ${total:.2f}")
    except Exception as e:
        print(f"  Error: {e}")

    if getattr(args, "details", False):
        print(f"\n{'='*50}")
        print(f"Per-Resource Detail ({month_label})")
        print(f"{'='*50}")
        scope = f"/subscriptions/{sub_id}"
        # usageEnd is exclusive of month_to's day; filter the full prior month.
        last_day = (datetime.strptime(month_to[:10], "%Y-%m-%d") - timedelta(days=1)).strftime("%Y-%m-%d")
        flt = (
            f"properties/usageStart ge '{month_from[:10]}' and "
            f"properties/usageEnd le '{last_day}'"
        )
        try:
            items = _retry_429(
                lambda: list(
                    clients.consumption.usage_details.list(
                        scope, filter=flt, metric="ActualCost"
                    )
                )
            )
            if not items:
                print("  No line items")
            else:
                agg = {}
                for it in items:
                    name, meter, cost = _usage_detail_fields(it)
                    key = (name, meter)
                    agg[key] = agg.get(key, 0.0) + cost
                total = 0.0
                for (name, meter), cost in sorted(
                    agg.items(), key=lambda kv: kv[1], reverse=True
                ):
                    if cost == 0:
                        continue
                    label = f"{name} / {meter}" if meter else name
                    print(f"  {label}: ${cost:.4f}")
                    total += cost
                print(f"  {'-'*40}")
                print(f"  Total: ${total:.4f}  ({len(items)} line items)")
        except Exception as e:
            print(f"  Error: {e}")

    if getattr(args, "recent", False):
        print(f"\n{'='*50}")
        print("Cost (Last 30 Days)")
        print(f"{'='*50}")
        try:
            result = _cost_query(
                clients,
                sub_id,
                _build_cost_query(
                    (today - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00Z"),
                    today.strftime("%Y-%m-%dT%H:%M:%SZ"),
                ),
            )
            total = float(result.rows[0][0]) if result.rows else 0
            print(f"  Total: ${total:.2f}")
        except Exception as e:
            print(f"  Error: {e}")

        print(f"\n{'='*50}")
        print("Daily Cost (Last 7 Days)")
        print(f"{'='*50}")
        try:
            result = _cost_query(
                clients,
                sub_id,
                _build_cost_query(
                    (today - timedelta(days=7)).strftime("%Y-%m-%dT00:00:00Z"),
                    today.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    granularity="Daily",
                ),
            )
            if result.rows:
                for row in result.rows:
                    c, d = row[0], row[1]
                    if isinstance(d, int):
                        d = f"{str(d)[:4]}-{str(d)[4:6]}-{str(d)[6:8]}"
                    else:
                        d = str(d)[:10]
                    print(f"  {d}: ${float(c):.2f}")
            else:
                print("  No data")
        except Exception as e:
            print(f"  Error: {e}")


def _billing_internet_egress_mtd(clients):
    """Calendar-month MTD internet egress from Consumption usageDetails.

    Rule (Bandwidth pricing): first 100 GB/month internet egress is free.
    That is the only ceiling — NOT 100+15. The free-services "15 GB / 12 months"
    line is not an extra pool on top of the 100 GB internet band.

    Azure splits the same internet-egress usage across two meters (UoM = 1 GB):
      - Standard Data Transfer Out - Free  (named free meter; often hard-stops
        near 15 GB, then spills — labeling only, not +15 GB allowance)
      - Standard Data Transfer Out         (spillover; Cost $0 while watched ≤ 100)

    Unbilled watch = free_gb + standard_gb against 100 GB.
    Monitor Network Out Total is NOT the bill and overstates free-tier burn.
    """
    today = datetime.now(timezone.utc)
    month_start = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    scope = f"/subscriptions/{clients.subscription_id}"
    flt = (
        f"properties/usageStart ge '{month_start.strftime('%Y-%m-%d')}' and "
        f"properties/usageEnd le '{today.strftime('%Y-%m-%d')}'"
    )
    items = _retry_429(
        lambda: list(
            clients.consumption.usage_details.list(
                scope, filter=flt, metric="ActualCost"
            )
        )
    )
    free_gb = 0.0
    standard_gb = 0.0
    standard_cost = 0.0
    other_bw = {}  # meter -> [qty, cost]
    for it in items:
        _name, meter, cost = _usage_detail_fields(it)
        meter_l = (meter or "").strip().lower()
        qty = float(
            getattr(it, "quantity", None)
            or getattr(it, "usage_quantity", None)
            or 0
        )
        if meter_l == "standard data transfer out - free":
            free_gb += qty
        elif meter_l == "standard data transfer out":
            standard_gb += qty
            standard_cost += cost
        elif "data transfer" in meter_l or "bandwidth" in meter_l:
            if qty or cost:
                q, c = other_bw.get(meter, [0.0, 0.0])
                other_bw[meter] = [q + qty, c + cost]
    other_list = [(m, q, c) for m, (q, c) in other_bw.items()]
    return (
        free_gb,
        standard_gb,
        standard_cost,
        month_start.strftime("%Y-%m-%d"),
        today.strftime("%Y-%m-%d"),
        other_list,
    )


def cmd_traffic(args):
    """Show VM NIC traffic + internet-egress billing vs the 100 GB free ceiling."""
    from azure.mgmt.monitor import MonitorManagementClient

    clients = get_clients(args.account)
    vms = list(clients.compute.virtual_machines.list_all())

    # Subscription-wide internet egress (billing meters), calendar month MTD
    # Ceiling = 100 GB only (not 100+15). See _billing_internet_egress_mtd docstring.
    print(f"\n{'='*50}")
    print("Internet Egress — stay unbilled (billing meters)")
    print(f"{'='*50}")
    free_limit_gb = 100.0  # always-free internet egress; NOT 100+15
    try:
        free_gb, standard_gb, standard_cost, d_from, d_to, other_bw = (
            _billing_internet_egress_mtd(clients)
        )
        watched = free_gb + standard_gb
        remaining = max(0.0, free_limit_gb - watched)
        pct_used = (watched / free_limit_gb) * 100 if free_limit_gb else 0.0
        print(f"  Period:     {d_from} -> {d_to} (calendar month MTD)")
        print(f"  Rule:       first {free_limit_gb:.0f} GB/month internet egress free")
        print(f"              (ceiling is {free_limit_gb:.0f} GB total — NOT 100+15)")
        print()
        print(f"  Free meter (Standard Data Transfer Out - Free):")
        print(f"    {free_gb:.3f} GB")
        print(f"    (labeling only; often hard-stops ~15 GB then spills — not +15 allowance)")
        print(f"  Spillover (Standard Data Transfer Out):")
        print(f"    {standard_gb:.3f} GB  ${standard_cost:.6f}")
        print(f"    ($0 = not charged yet; still counts toward the {free_limit_gb:.0f} GB ceiling)")
        print()
        print(f"  Watched (Free + Spillover): {watched:.3f} GB ({pct_used:.1f}% of {free_limit_gb:.0f})")
        print(f"  Headroom to stay unbilled:  {remaining:.3f} GB")
        if standard_cost > 0 or watched > free_limit_gb:
            print("  WARNING: internet egress may be billing — check Cost / invoice")
        if other_bw:
            print()
            print("  Other bandwidth meters (NOT part of the 100 GB internet ceiling):")
            for meter, qty, cost in sorted(other_bw, key=lambda x: (-x[2], -x[1])):
                print(f"    {meter}: {qty:.6f} GB  ${cost:.6f}")
    except Exception as e:
        print(f"  Error reading billing meters: {e}")

    if not vms:
        print("\nNo VMs found.")
        return

    monitor = MonitorManagementClient(clients.credential, clients.subscription_id)
    end_time = datetime.now(timezone.utc)
    start_30d = end_time - timedelta(days=30)
    start_7d = end_time - timedelta(days=7)

    end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    start_30d_str = start_30d.strftime("%Y-%m-%dT%H:%M:%SZ")
    start_7d_str = start_7d.strftime("%Y-%m-%dT%H:%M:%SZ")

    for vm in vms:
        print(f"\n{'='*50}")
        print(f"VM: {vm.name}")
        print(f"{'='*50}")

        # 30-day NIC totals (ops signal — not the free-allowance counter)
        print(f"\nNIC Traffic via Monitor (Last 30 Days):")
        print("  (all outbound bytes; overstates free-tier vs billing)")
        try:
            metrics = monitor.metrics.list(
                vm.id,
                timespan=f"{start_30d_str}/{end_str}",
                interval="P1D",
                metricnames="Network In Total,Network Out Total",
                aggregation="Total"
            )

            totals = {}
            for metric in metrics.value:
                total = sum(d.total for ts in metric.timeseries for d in ts.data if d.total)
                totals[metric.name.localized_value] = total

            net_in = totals.get("Network In Total", 0)
            net_out = totals.get("Network Out Total", 0)

            print(f"  In:    {net_in / (1024**3):.2f} GB ({net_in / (1024**2):.0f} MB)")
            print(f"  Out:   {net_out / (1024**3):.2f} GB ({net_out / (1024**2):.0f} MB)")
            print(f"  Total: {(net_in + net_out) / (1024**3):.2f} GB")

        except Exception as e:
            print(f"  Error: {e}")

        # Daily breakdown
        print(f"\nDaily Breakdown (Last 7 Days):")
        try:
            metrics = monitor.metrics.list(
                vm.id,
                timespan=f"{start_7d_str}/{end_str}",
                interval="P1D",
                metricnames="Network In Total,Network Out Total",
                aggregation="Total"
            )

            data_by_date = {}
            for metric in metrics.value:
                for ts in metric.timeseries:
                    for data in ts.data:
                        if data.total and data.time_stamp:
                            date = data.time_stamp.strftime("%Y-%m-%d")
                            if date not in data_by_date:
                                data_by_date[date] = {"in": 0, "out": 0}
                            if "In" in metric.name.localized_value:
                                data_by_date[date]["in"] = data.total / (1024**2)
                            else:
                                data_by_date[date]["out"] = data.total / (1024**2)

            if data_by_date:
                print(f"  {'Date':<12} {'In (MB)':>10} {'Out (MB)':>10}")
                print(f"  {'-'*34}")
                for date in sorted(data_by_date.keys()):
                    d = data_by_date[date]
                    print(f"  {date:<12} {d['in']:>10.1f} {d['out']:>10.1f}")
            else:
                print("  No data")

        except Exception as e:
            print(f"  Error: {e}")


def cmd_quota(args):
    """Check compute quota for a location."""
    clients = get_clients(args.account)
    location = args.location
    
    print(f"\n{'='*60}")
    print(f"Compute Quota: {location}")
    print(f"{'='*60}")
    
    try:
        usages = list(clients.compute.usage.list(location))
        usages = [u for u in usages if any(x in u.name.localized_value.lower() for x in ['core', 'cpu', 'vcpu'])]
        
        print(f"\n{'Resource':<40} {'Used':>8} {'Limit':>8} {'Avail':>8}")
        print("-" * 66)
        
        for usage in sorted(usages, key=lambda x: x.name.localized_value):
            name = usage.name.localized_value[:40]
            avail = usage.limit - usage.current_value
            flag = " *" if "lowpriority" in name.lower().replace(" ", "") else ""
            print(f"{name:<40} {usage.current_value:>8} {usage.limit:>8} {avail:>8}{flag}")
    except Exception as e:
        print(f"  Error: {e}")


def cmd_delete_all(args):
    """Delete all resource groups (removes all resources)."""
    clients = get_clients(args.account)
    
    if not args.confirm:
        print("WARNING: This will delete ALL resources!")
        print("Run with --confirm to proceed.")
        return
    
    rgs = list(clients.resource.resource_groups.list())
    if not rgs:
        print("No resource groups to delete.")
        return
    
    for rg in rgs:
        print(f"Deleting {rg.name}...", end=" ", flush=True)
        try:
            clients.resource.resource_groups.begin_delete(rg.name)
            print("started")
        except Exception as e:
            print(f"error: {e}")
    
    print("\nDeletion initiated. Resources will be removed in background.")


def cmd_proxy_deploy(args):
    """Deploy SOCKS5 proxy container."""
    from azure.mgmt.containerinstance.models import (
        ContainerGroup, Container, ContainerPort, ResourceRequirements,
        ResourceRequests, IpAddress, Port, EnvironmentVariable, OperatingSystemTypes
    )
    
    clients = get_clients(args.account)
    location = args.location
    rg_name = f"socks5-{location[:3]}"
    cg_name = f"socks5-{location[:3]}"
    
    print(f"Creating resource group '{rg_name}'...")
    clients.resource.resource_groups.create_or_update(rg_name, {"location": location})
    
    container = Container(
        name=cg_name,
        image="serjs/go-socks5-proxy",
        resources=ResourceRequirements(requests=ResourceRequests(cpu=1.0, memory_in_gb=1.0)),
        ports=[ContainerPort(port=1080, protocol="TCP")],
        environment_variables=[
            EnvironmentVariable(name="PROXY_USER", value=args.user),
            EnvironmentVariable(name="PROXY_PASSWORD", secure_value=args.password),
        ],
    )
    
    group = ContainerGroup(
        location=location,
        containers=[container],
        os_type=OperatingSystemTypes.linux,
        ip_address=IpAddress(ports=[Port(port=1080, protocol="TCP")], type="Public"),
        restart_policy="Always",
    )
    
    print(f"Deploying container...")
    result = clients.container.container_groups.begin_create_or_update(rg_name, cg_name, group).result()
    ip = result.ip_address.ip if result.ip_address else "(pending)"
    
    print(f"\n{'='*50}")
    print("SOCKS5 Proxy Deployed")
    print(f"{'='*50}")
    print(f"  Host:     {ip}")
    print(f"  Port:     1080")
    print(f"  User:     {args.user}")
    print(f"  Password: {args.password}")
    print(f"\n  curl --socks5-hostname {ip}:1080 --proxy-user {args.user}:{args.password} http://ifconfig.me")


def cmd_proxy_status(args):
    """Show SOCKS5 proxy status."""
    clients = get_clients(args.account)
    
    print(f"\n{'='*50}")
    print("SOCKS5 Proxy Containers")
    print(f"{'='*50}")
    
    found = False
    for rg in clients.resource.resource_groups.list():
        if rg.name.startswith("socks5-"):
            try:
                cgs = list(clients.container.container_groups.list_by_resource_group(rg.name))
                for cg in cgs:
                    found = True
                    ip = cg.ip_address.ip if cg.ip_address else "(none)"
                    state = cg.provisioning_state
                    print(f"\n  {cg.name} [{rg.name}]")
                    print(f"    Location: {cg.location}")
                    print(f"    State:    {state}")
                    print(f"    IP:       {ip}:1080")
            except Exception:
                pass
    
    if not found:
        print("  No proxy containers found.")


def cmd_proxy_delete(args):
    """Delete SOCKS5 proxy."""
    clients = get_clients(args.account)
    
    for rg in list(clients.resource.resource_groups.list()):
        if rg.name.startswith("socks5-"):
            print(f"Deleting {rg.name}...", end=" ", flush=True)
            try:
                clients.resource.resource_groups.begin_delete(rg.name)
                print("started")
            except Exception as e:
                print(f"error: {e}")


def _iter_nsgs(clients):
    for nsg in clients.network.network_security_groups.list_all():
        rg = nsg.id.split("/")[4]
        yield rg, nsg


def cmd_nsg(args):
    """List NSGs and inbound rules, or open a port."""
    clients = get_clients(args.account)
    from azure.mgmt.network.models import SecurityRule

    if args.action == "open":
        protocol = args.protocol.capitalize() if args.protocol.lower() != "any" else "*"
        port = str(args.port)
        name = args.name or f"Allow-{protocol}-{port}"
        priority = args.priority
        source = args.source
        opened = 0
        for rg, nsg in _iter_nsgs(clients):
            if args.nsg and nsg.name != args.nsg and args.nsg not in nsg.id:
                continue
            existing = {r.name: r for r in (nsg.security_rules or [])}
            used = {r.priority for r in existing.values() if r.direction == "Inbound"}
            pri = priority
            while pri in used:
                pri += 1
            rule = SecurityRule(
                name=name,
                protocol=protocol,
                source_port_range="*",
                destination_port_range=port,
                source_address_prefix=source,
                destination_address_prefix="*",
                access="Allow",
                priority=pri,
                direction="Inbound",
            )
            print(
                f"Opening {protocol}/{port} on {nsg.name} ({rg}) as {name} pri={pri}...",
                end=" ",
                flush=True,
            )
            clients.network.security_rules.begin_create_or_update(
                rg, nsg.name, name, rule
            ).result()
            print("done")
            opened += 1
        if not opened:
            print("No matching NSG found.")
        return

    nsgs = list(_iter_nsgs(clients))
    if not nsgs:
        print("No NSGs found.")
        return
    for rg, nsg in nsgs:
        print(f"\n{'='*50}")
        print(f"NSG: {nsg.name}  (rg={rg})")
        print(f"{'='*50}")
        rules = sorted(
            nsg.security_rules or [],
            key=lambda r: (r.direction or "", r.priority or 0),
        )
        if not rules:
            print("  (no custom rules)")
            continue
        for r in rules:
            ports = r.destination_port_range or ",".join(r.destination_port_ranges or [])
            src = r.source_address_prefix or ",".join(r.source_address_prefixes or [])
            print(
                f"  [{r.priority:>4}] {r.direction:<8} {r.access:<6} "
                f"{r.protocol:<4} dst={ports:<12} src={src}  {r.name}"
            )


def cmd_create_free(args):
    """Create a completely free Azure VM with IPv6-only (no public IPv4 charges)."""
    from azure.mgmt.compute.models import (
        VirtualMachine, HardwareProfile, StorageProfile, OSDisk,
        ImageReference, NetworkProfile, NetworkInterfaceReference,
        OSProfile, LinuxConfiguration, SshConfiguration, SshPublicKey,
        DiskCreateOptionTypes, CachingTypes, DeleteOptions
    )
    from azure.mgmt.network.models import (
        VirtualNetwork, Subnet, AddressSpace, PublicIPAddress,
        NetworkInterface, NetworkInterfaceIPConfiguration,
        NetworkSecurityGroup, SecurityRule
    )
    
    clients = get_clients(args.account)
    location = args.location
    rg_name = args.name
    vm_name = args.name
    username = args.username
    
    import os
    # Read SSH public key
    ssh_key_path = os.path.expanduser(args.ssh_key)
    try:
        with open(ssh_key_path, 'r') as f:
            ssh_pub_key = f.read().strip()
    except FileNotFoundError:
        print(f"Error: SSH key not found at {ssh_key_path}")
        print("Generate one with: ssh-keygen -t ed25519")
        return
    
    vm_size = args.size
    
    print(f"\n{'='*60}")
    print("Creating FREE Azure VM")
    print(f"{'='*60}")
    print(f"  Name:     {vm_name}")
    print(f"  Location: {location}")
    print(f"  Size:     {vm_size}")
    print(f"  Disk:     64 GB Premium SSD (P6)")
    print(f"  IP:       IPv6 only (free)")
    print()
    
    # 1. Create Resource Group
    print("1. Creating resource group...", end=" ", flush=True)
    clients.resource.resource_groups.create_or_update(rg_name, {"location": location})
    print("done")
    
    # 2. Create Network Security Group
    print("2. Creating network security group...", end=" ", flush=True)
    nsg_name = f"{vm_name}-nsg"
    nsg = clients.network.network_security_groups.begin_create_or_update(
        rg_name, nsg_name,
        NetworkSecurityGroup(
            location=location,
            security_rules=[
                SecurityRule(
                    name="AllowSSH",
                    protocol="Tcp",
                    source_port_range="*",
                    destination_port_range="22",
                    source_address_prefix="*",
                    destination_address_prefix="*",
                    access="Allow",
                    priority=1000,
                    direction="Inbound"
                ),
                SecurityRule(
                    name="AllowSSH-IPv6",
                    protocol="Tcp",
                    source_port_range="*",
                    destination_port_range="22",
                    source_address_prefix="::/0",
                    destination_address_prefix="::/0",
                    access="Allow",
                    priority=1001,
                    direction="Inbound"
                )
            ]
        )
    ).result()
    print("done")
    
    # 3. Create VNet with IPv4 + IPv6
    print("3. Creating virtual network with IPv6...", end=" ", flush=True)
    vnet_name = f"{vm_name}-vnet"
    subnet_name = "default"
    
    vnet = clients.network.virtual_networks.begin_create_or_update(
        rg_name, vnet_name,
        VirtualNetwork(
            location=location,
            address_space=AddressSpace(
                address_prefixes=["10.0.0.0/16", "fd00:db8:deca::/48"]
            ),
            subnets=[
                Subnet(
                    name=subnet_name,
                    address_prefixes=["10.0.0.0/24", "fd00:db8:deca:deed::/64"],
                    network_security_group={"id": nsg.id}
                )
            ]
        )
    ).result()
    subnet_id = vnet.subnets[0].id
    print("done")
    
    # 4. Create Public IPv6 Address (FREE!)
    print("4. Creating public IPv6 address (free)...", end=" ", flush=True)
    ipv6_name = f"{vm_name}-ipv6"
    ipv6 = clients.network.public_ip_addresses.begin_create_or_update(
        rg_name, ipv6_name,
        PublicIPAddress(
            location=location,
            sku={"name": "Standard"},
            public_ip_allocation_method="Static",
            public_ip_address_version="IPv6"
        )
    ).result()
    print("done")
    
    # 5. Create Network Interface with IPv4 (private) + IPv6 (public)
    print("5. Creating network interface...", end=" ", flush=True)
    nic_name = f"{vm_name}-nic"
    nic = clients.network.network_interfaces.begin_create_or_update(
        rg_name, nic_name,
        NetworkInterface(
            location=location,
            ip_configurations=[
                NetworkInterfaceIPConfiguration(
                    name="ipconfig-ipv4",
                    subnet={"id": subnet_id},
                    private_ip_allocation_method="Dynamic",
                    private_ip_address_version="IPv4",
                    primary=True
                ),
                NetworkInterfaceIPConfiguration(
                    name="ipconfig-ipv6",
                    subnet={"id": subnet_id},
                    private_ip_allocation_method="Dynamic",
                    private_ip_address_version="IPv6",
                    public_ip_address={"id": ipv6.id}
                )
            ]
        )
    ).result()
    print("done")
    
    # 6. Create VM
    print("6. Creating virtual machine (this takes 2-3 minutes)...", end=" ", flush=True)
    zone = args.zone
    vm_params = VirtualMachine(
        location=location,
        zones=[zone] if zone else None,
        hardware_profile=HardwareProfile(vm_size=vm_size),
        storage_profile=StorageProfile(
            image_reference=ImageReference(
                publisher="Canonical",
                offer="ubuntu-24_04-lts",
                sku="server",
                version="latest"
            ),
            os_disk=OSDisk(
                name=f"{vm_name}-osdisk",
                caching=CachingTypes.READ_WRITE,
                create_option=DiskCreateOptionTypes.FROM_IMAGE,
                disk_size_gb=64,
                managed_disk={"storage_account_type": "Premium_LRS"},
                delete_option=DeleteOptions.DELETE
            )
        ),
        network_profile=NetworkProfile(
            network_interfaces=[
                NetworkInterfaceReference(
                    id=nic.id,
                    delete_option=DeleteOptions.DELETE
                )
            ]
        ),
        os_profile=OSProfile(
            computer_name=vm_name,
            admin_username=username,
            linux_configuration=LinuxConfiguration(
                disable_password_authentication=True,
                ssh=SshConfiguration(
                    public_keys=[
                        SshPublicKey(
                            path=f"/home/{username}/.ssh/authorized_keys",
                            key_data=ssh_pub_key
                        )
                    ]
                )
            )
        )
    )
    vm = clients.compute.virtual_machines.begin_create_or_update(
        rg_name, vm_name, vm_params
    ).result()
    print("done")
    
    # Get the actual IPv6 address
    ipv6_updated = clients.network.public_ip_addresses.get(rg_name, ipv6_name)
    ipv6_addr = ipv6_updated.ip_address or "(pending - check in a minute)"
    
    print(f"\n{'='*60}")
    print("FREE VM Created Successfully!")
    print(f"{'='*60}")
    print(f"  Resource Group: {rg_name}")
    print(f"  VM Name:        {vm_name}")
    print(f"  Location:       {location}")
    print(f"  Size:           {vm_size}")
    print(f"  OS Disk:        64 GB Premium SSD (P6)")
    print(f"  IPv6 Address:   {ipv6_addr}")
    print(f"  Username:       {username}")
    print()
    print("Cost: $0/month (750 free hours + 64GB P6 + free IPv6)")
    print()
    print("Connect via SSH:")
    print(f"  ssh -6 {username}@{ipv6_addr}")
    print()
    print("IMPORTANT: After first login, create swap (1GB RAM is low):")
    print("  sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile")
    print("  sudo mkswap /swapfile && sudo swapon /swapfile")
    print("  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab")


def main():
    parser = argparse.ArgumentParser(description="Azure manager", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--account", "-a",
        default="azure",
        help="cred.json key: azure (default), azure2, or aliases az / az2",
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # VM commands
    subparsers.add_parser("status", help="Show VM status")
    subparsers.add_parser("start", help="Start all VMs")
    subparsers.add_parser("stop", help="Deallocate all VMs")
    subparsers.add_parser("restart", help="Restart all VMs")
    
    # Account commands
    subparsers.add_parser("sub", help="Show subscription info")
    subparsers.add_parser("resources", help="List all resources")
    cost_p = subparsers.add_parser("cost", help="Show last month's billed cost")
    cost_p.add_argument(
        "--recent",
        action="store_true",
        help="Also show last 30 days and daily last-7-day costs (extra API calls)",
    )
    cost_p.add_argument(
        "--details",
        action="store_true",
        help="Show per-resource line items from the Consumption usageDetails API",
    )
    subparsers.add_parser(
        "traffic",
        help="Show internet egress vs 100 GB free ceiling (Free+Spillover) and VM NIC stats",
    )
    
    # Quota
    quota_p = subparsers.add_parser("quota", help="Check compute quota")
    quota_p.add_argument("location", nargs="?", default="southeastasia", help="Azure region")
    
    # Cleanup
    delete_p = subparsers.add_parser("delete-all", help="Delete all resources")
    delete_p.add_argument("--confirm", action="store_true", help="Confirm deletion")
    
    # Proxy commands
    proxy_deploy = subparsers.add_parser("proxy-deploy", help="Deploy SOCKS5 proxy")
    proxy_deploy.add_argument("--location", default="germanywestcentral", help="Azure region")
    proxy_deploy.add_argument("--user", default="blue", help="Proxy username")
    proxy_deploy.add_argument("--password", default="proxypass123", help="Proxy password")
    
    subparsers.add_parser("proxy-status", help="Show proxy status")
    subparsers.add_parser("proxy-delete", help="Delete proxy")

    # NSG
    nsg_p = subparsers.add_parser("nsg", help="List NSG rules or open a port")
    nsg_p.add_argument(
        "action",
        nargs="?",
        default="list",
        choices=["list", "open"],
        help="list (default) or open",
    )
    nsg_p.add_argument("--port", type=int, help="Destination port (required for open)")
    nsg_p.add_argument("--protocol", default="Udp", help="Tcp, Udp, or Any (default: Udp)")
    nsg_p.add_argument("--name", help="Rule name (default: Allow-<proto>-<port>)")
    nsg_p.add_argument("--priority", type=int, default=1100, help="Inbound priority")
    nsg_p.add_argument("--source", default="*", help="Source prefix (default: *)")
    nsg_p.add_argument("--nsg", help="Only this NSG name (default: all)")
    
    # Free VM creation
    free_p = subparsers.add_parser("create-free", help="Create FREE VM (IPv6-only)")
    free_p.add_argument("--name", default="free-sg", help="VM and resource group name")
    free_p.add_argument("--location", default="southeastasia", help="Azure region (default: Singapore)")
    free_p.add_argument("--zone", default="1", help="Availability zone (1, 2, or 3)")
    free_p.add_argument("--size", default="Standard_B2ats_v2", help="VM size (default: B2ats_v2 - 2vCPU/1GB, free tier)")
    free_p.add_argument("--username", default="azureuser", help="Admin username")
    free_p.add_argument("--ssh-key", default="~/.ssh/id_ed25519.pub", help="Path to SSH public key")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return

    if args.command == "nsg" and args.action == "open" and not args.port:
        nsg_p.error("--port is required for nsg open")
    
    commands = {
        "status": cmd_status,
        "start": cmd_start,
        "stop": cmd_stop,
        "restart": cmd_restart,
        "sub": cmd_sub,
        "resources": cmd_resources,
        "cost": cmd_cost,
        "traffic": cmd_traffic,
        "quota": cmd_quota,
        "delete-all": cmd_delete_all,
        "proxy-deploy": cmd_proxy_deploy,
        "proxy-status": cmd_proxy_status,
        "proxy-delete": cmd_proxy_delete,
        "nsg": cmd_nsg,
        "create-free": cmd_create_free,
    }
    
    commands[args.command](args)


if __name__ == "__main__":
    main()
