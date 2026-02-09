#!/usr/bin/python3
"""Clash Proxy Manager - Switch nodes via API"""


# %% Configuration
import requests
from urllib.parse import quote

CLASH_API = "http://127.0.0.1:17650"
SECRET = "0ce2f533-f94b-4780-af2d-33eabc291f4c"
SELECTOR_GROUP = "🔰 节点选择"

HEADERS = {
    "Authorization": f"Bearer {SECRET}",
    "Content-Type": "application/json"
}

# %% Helper functions
def get_proxies():
    """Get all proxy groups and nodes"""
    resp = requests.get(f"{CLASH_API}/proxies", headers=HEADERS)
    resp.raise_for_status()
    return resp.json()["proxies"]

def get_group(name: str = SELECTOR_GROUP):
    """Get info about a specific proxy group"""
    encoded = quote(name, safe='')
    resp = requests.get(f"{CLASH_API}/proxies/{encoded}", headers=HEADERS)
    resp.raise_for_status()
    return resp.json()

def get_current_node(group: str = SELECTOR_GROUP) -> str:
    """Get currently selected node in a group"""
    return get_group(group).get("now", "")

def list_nodes(group: str = SELECTOR_GROUP) -> list:
    """List all available nodes in a group"""
    return get_group(group).get("all", [])

def switch_node(node_name: str, group: str = SELECTOR_GROUP) -> bool:
    """Switch to a specific node. Returns True on success."""
    encoded = quote(group, safe='')
    resp = requests.put(
        f"{CLASH_API}/proxies/{encoded}",
        headers=HEADERS,
        json={"name": node_name}
    )
    return resp.status_code == 204

def test_delay(node_name: str, timeout: int = 5000) -> int | None:
    """Test delay for a node. Returns delay in ms or None on error."""
    encoded = quote(node_name, safe='')
    url = f"{CLASH_API}/proxies/{encoded}/delay?timeout={timeout}&url=http://www.gstatic.com/generate_204"
    resp = requests.get(url, headers=HEADERS)
    if resp.status_code == 200:
        data = resp.json()
        return data.get("delay")
    return None

def get_version() -> dict:
    """Get Clash version info"""
    resp = requests.get(f"{CLASH_API}/version", headers=HEADERS)
    resp.raise_for_status()
    return resp.json()

# %% Node filtering helpers
def get_hk_nodes() -> list:
    """Get Hong Kong nodes"""
    return [n for n in list_nodes() if "香港" in n or "🇭🇰" in n]

def get_us_nodes() -> list:
    """Get US nodes"""
    return [n for n in list_nodes() if "美国" in n or "🇺🇸" in n]

def get_jp_nodes() -> list:
    """Get Japan nodes"""
    return [n for n in list_nodes() if "日本" in n or "🇯🇵" in n]

def get_sg_nodes() -> list:
    """Get Singapore nodes"""
    return [n for n in list_nodes() if "新加坡" in n or "🇸🇬" in n]

def get_tw_nodes() -> list:
    """Get Taiwan nodes"""
    return [n for n in list_nodes() if "台湾" in n or "🇹🇼" in n]

def get_iplc_nodes() -> list:
    """Get IPLC (premium) nodes"""
    return [n for n in list_nodes() if "IPLC" in n]

# %% Quick switch functions
def switch_to_auto():
    """Switch to auto select"""
    return switch_node("🎁 自动选择")

def switch_to_hk():
    """Switch to first HK IPLC node"""
    nodes = [n for n in get_hk_nodes() if "IPLC" in n]
    if nodes:
        return switch_node(nodes[0])
    return False

def switch_to_us():
    """Switch to first US IPLC node"""
    nodes = [n for n in get_us_nodes() if "IPLC" in n]
    if nodes:
        return switch_node(nodes[0])
    return False

def switch_to_jp():
    """Switch to first Japan IPLC node"""
    nodes = [n for n in get_jp_nodes() if "IPLC" in n]
    if nodes:
        return switch_node(nodes[0])
    return False

def switch_to_sg():
    """Switch to first Singapore IPLC node"""
    nodes = [n for n in get_sg_nodes() if "IPLC" in n]
    if nodes:
        return switch_node(nodes[0])
    return False

# %% GLOBAL mode switching (for TUN mode)
def switch_global(node_name: str) -> bool:
    """Switch GLOBAL selector directly - use this in TUN mode"""
    return switch_node(node_name, group="GLOBAL")

def switch_global_to_selector():
    """Set GLOBAL to use '🔰 节点选择' (respects your node choice)"""
    return switch_global("🔰 节点选择")

def switch_global_to_hk():
    """Switch GLOBAL to first HK IPLC node"""
    nodes = [n for n in get_hk_nodes() if "IPLC" in n]
    if nodes:
        return switch_global(nodes[0])
    return False

def switch_global_to_us():
    """Switch GLOBAL to first US IPLC node"""
    nodes = [n for n in get_us_nodes() if "IPLC" in n]
    if nodes:
        return switch_global(nodes[0])
    return False

def switch_global_to_jp():
    """Switch GLOBAL to first Japan IPLC node"""
    nodes = [n for n in get_jp_nodes() if "IPLC" in n]
    if nodes:
        return switch_global(nodes[0])
    return False

def switch_global_to_sg():
    """Switch GLOBAL to first Singapore IPLC node"""
    nodes = [n for n in get_sg_nodes() if "IPLC" in n]
    if nodes:
        return switch_global(nodes[0])
    return False

# %% Status display
def show_status():
    """Print current status"""
    version = get_version()
    current = get_current_node()
    global_node = get_current_node("GLOBAL")
    nodes = list_nodes()
    
    print(f"Clash Version: {version.get('version', 'unknown')}")
    print(f"GLOBAL Node: {global_node}")
    print(f"Selector Node: {current}")
    print(f"Total Nodes: {len(nodes)}")
    print()
    
    # Group by region
    regions = {
        "🇭🇰 Hong Kong": get_hk_nodes(),
        "🇺🇸 USA": get_us_nodes(),
        "🇯🇵 Japan": get_jp_nodes(),
        "🇸🇬 Singapore": get_sg_nodes(),
        "🇹🇼 Taiwan": get_tw_nodes(),
    }
    
    print("Available by region:")
    for region, region_nodes in regions.items():
        iplc = [n for n in region_nodes if "IPLC" in n]
        print(f"  {region}: {len(region_nodes)} nodes ({len(iplc)} IPLC)")

def list_all_nodes():
    """Print all available nodes"""
    current = get_current_node()
    nodes = list_nodes()
    
    print(f"Current: {current}\n")
    print("All nodes:")
    for i, node in enumerate(nodes, 1):
        marker = " *" if node == current else ""
        print(f"  {i:2}. {node}{marker}")

# %% Test all nodes
import json
import time
from datetime import datetime

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

def get_ip_info(timeout: int = 10) -> dict | None:
    """Get current IP info from ippure.com"""
    try:
        resp = requests.get("https://my.ippure.com/v1/info", timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        return {"error": str(e)}
    return None

def test_all_nodes(group: str = "GLOBAL", delay_between: float = 2.0, skip_non_proxy: bool = True) -> list:
    """Test all nodes and collect IP info for each"""
    all_nodes = list_nodes(group)
    results = []
    
    # Filter out non-proxy entries (info lines, selector groups, etc.)
    skip_keywords = [
        "剩余流量", "距离下次", "套餐到期", "过滤掉", "DIRECT", "REJECT",
        "节点选择", "全球直连", "全球拦截", "漏网之鱼", "电报信息",
        "国外媒体", "国内媒体", "微软服务", "苹果服务", "自动选择", "故障转移",
        "如遇节点", "永久地址", "大陆访问", "Telegram", "欢迎加入"
    ]
    nodes = [n for n in all_nodes if not any(kw in n for kw in skip_keywords)] if skip_non_proxy else all_nodes
    
    # Progress bar setup
    if HAS_TQDM:
        pbar = tqdm(nodes, desc="Testing nodes", unit="node", 
                    bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]")
    else:
        pbar = nodes
        print(f"Testing {len(nodes)} nodes...")
    
    successful = 0
    failed = 0
    
    for node in pbar:
        # Update progress bar description
        if HAS_TQDM:
            short_name = node[:30] + "..." if len(node) > 33 else node
            pbar.set_postfix_str(f"✓{successful} ✗{failed} | {short_name}")
        
        # Switch to node
        if not switch_node(node, group):
            results.append({
                "node": node,
                "success": False,
                "error": "Failed to switch"
            })
            failed += 1
            continue
        
        time.sleep(1)  # Wait for switch
        
        # Get IP info
        ip_info = get_ip_info()
        
        if ip_info and "error" not in ip_info:
            results.append({
                "node": node,
                "success": True,
                "ip": ip_info.get("ip"),
                "country": ip_info.get("country"),
                "countryCode": ip_info.get("countryCode"),
                "city": ip_info.get("city"),
                "asn": ip_info.get("asn"),
                "asOrganization": ip_info.get("asOrganization"),
                "isResidential": ip_info.get("isResidential"),
                "fraudScore": ip_info.get("fraudScore"),
            })
            successful += 1
            if not HAS_TQDM:
                print(f"  [{successful+failed}/{len(nodes)}] {node[:40]} -> {ip_info.get('ip')} ({ip_info.get('countryCode')})")
        else:
            results.append({
                "node": node,
                "success": False,
                "error": ip_info.get("error") if ip_info else "No response"
            })
            failed += 1
            if not HAS_TQDM:
                print(f"  [{successful+failed}/{len(nodes)}] {node[:40]} -> FAILED")
        
        time.sleep(delay_between)
    
    if HAS_TQDM:
        pbar.close()
    
    return results

def test_and_export(output_file: str = "clash_nodes_test.json", group: str = "GLOBAL"):
    """Test all nodes and export results to JSON"""
    print(f"Testing all nodes in {group}...")
    print(f"Started at: {datetime.now().isoformat()}")
    print()
    
    results = test_all_nodes(group)
    
    # Summary
    successful = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    
    export_data = {
        "tested_at": datetime.now().isoformat(),
        "group": group,
        "total_tested": len(results),
        "successful": len(successful),
        "failed": len(failed),
        "nodes": results
    }
    
    # Save to file
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(export_data, f, ensure_ascii=False, indent=2)
    
    print()
    print(f"Results: {len(successful)} OK, {len(failed)} Failed")
    print(f"Exported to: {output_file}")
    
    return export_data

# %% Main
if __name__ == "__main__":
    show_status()
    print()
    print("For TUN mode, use GLOBAL commands:")
    print("  switch_global_to_hk()       - Hong Kong")
    print("  switch_global_to_us()       - USA")
    print("  switch_global_to_jp()       - Japan")
    print("  switch_global_to_sg()       - Singapore")
    print("  switch_global_to_selector() - Use '节点选择'")
    print()
    print("Or switch '节点选择' (when GLOBAL -> 节点选择):")
    print("  switch_to_hk/us/jp/sg()     - Set node choice")
    print()
    print("Test all nodes:")
    print("  test_and_export()           - Test & save to JSON")

# %% Switch GLOBAL (TUN mode)
# switch_global_to_us()
# switch_global_to_hk()
# switch_global("🇭🇰TJ|香港C01|NF解锁")
