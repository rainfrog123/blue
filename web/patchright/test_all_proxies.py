#!/usr/bin/env python3
import asyncio
import random
import os
import shutil
import json
from datetime import datetime
from patchright.async_api import async_playwright

# Configuration
NUM_PORTS_TO_TEST = 63  # Change this number to test more/fewer ports

async def test_proxy_port(port):
    """Test a specific proxy port and return the result"""
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                channel="chrome",
                proxy={
                    "server": f"https://gb.decodo.com:{port}",
                    "username": "sp3j58curv",
                    "password": "9oOoKQ8+z8pkcUsnv0"
                }
            )
            page = await browser.new_page()
            
            # Set timeout and try to load the page
            await page.goto("https://www.google.com/search?q=1", wait_until="load", timeout=15_000)
            
            # Get page info
            title = await page.title()
            current_url = page.url
            page_content = await page.content()
            
            # Check for block indicators
            block_indicators = [
                "unusual traffic",
                "captcha",
                "sorry/index",
                "verify you're not a robot",
                "automated queries"
            ]
            
            found_blocks = []
            for indicator in block_indicators:
                if indicator.lower() in page_content.lower() or indicator.lower() in current_url.lower():
                    found_blocks.append(indicator)
            
            # Check if we got search results
            search_results = await page.query_selector_all("[data-ved]")
            
            # Take screenshot and save with port number (directory already created)
            screenshot_path = os.path.join("test", f"port_{port}_screenshot.png")
            await page.screenshot(path=screenshot_path, full_page=True)
            
            await browser.close()
            
            result = {
                'port': port,
                'success': True,
                'blocked': len(found_blocks) > 0,
                'block_reasons': found_blocks,
                'search_results_count': len(search_results),
                'final_url': current_url,
                'title': title[:100] + "..." if len(title) > 100 else title,
                'screenshot_path': screenshot_path
            }
            
            return result
            
    except Exception as e:
        return {
            'port': port,
            'success': False,
            'blocked': None,
            'error': str(e),
            'block_reasons': [],
            'search_results_count': 0,
            'final_url': None,
            'title': None,
            'screenshot_path': None
        }

async def test_all_proxies():
    """Test randomly selected proxy ports from 30001 to 49999 concurrently"""
    
    # Clear and recreate test directory for fresh screenshots
    test_dir = "test"
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
        print(f"🗑️  Cleared existing {test_dir}/ directory")
    
    os.makedirs(test_dir)
    print(f"📁 Created fresh {test_dir}/ directory for screenshots")
    
    # Clear previous JSON report if it exists
    report_path = "test_report.json"
    if os.path.exists(report_path):
        os.remove(report_path)
        print(f"🗑️  Cleared existing {report_path}")
    
    # Randomly select ports from the range 30001-49999
    all_ports = list(range(30001, 50000))  # Exclude 50000 and above
    selected_ports = sorted(random.sample(all_ports, NUM_PORTS_TO_TEST))
    
    print(f"\n🚀 Testing {NUM_PORTS_TO_TEST} random proxy ports from 30001-49999 on gb.decodo.com...")
    print(f"Selected ports: {selected_ports}")
    print("="*80)
    print("Running all tests concurrently...")
    
    # Run all tests concurrently using asyncio.gather
    results = await asyncio.gather(
        *[test_proxy_port(port) for port in selected_ports],
        return_exceptions=True
    )
    
    # Process and display results
    print("\n" + "="*80)
    print("📋 INDIVIDUAL RESULTS")
    print("="*80)
    
    processed_results = []
    blocked_ports = []
    error_ports = []
    unblocked_ports = []
    
    for i, result in enumerate(results):
        port = selected_ports[i]
        if isinstance(result, Exception):
            result = {
                'port': port,
                'success': False,
                'blocked': None,
                'error': str(result),
                'block_reasons': [],
                'search_results_count': 0,
                'final_url': None,
                'title': None
            }
        
        processed_results.append(result)
        
        # Categorize results
        if result['success']:
            if result['blocked']:
                blocked_ports.append(result)
            else:
                unblocked_ports.append(result)
        else:
            error_ports.append(result)
    
    # Display unblocked ports (detailed)
    for result in unblocked_ports:
        print(f"Port {result['port']}: ✅ SUCCESS ({result['search_results_count']} results) - Screenshot: {result['screenshot_path']}")
    
    # Display blocked ports (concise)
    if blocked_ports:
        blocked_port_list = [str(r['port']) for r in blocked_ports]
        print(f"Ports {', '.join(blocked_port_list)}: 🚫 BLOCKED ({len(blocked_ports)} total)")
    
    # Display error ports (concise)
    if error_ports:
        error_port_list = [str(r['port']) for r in error_ports]
        print(f"Ports {', '.join(error_port_list)}: ❌ ERROR ({len(error_ports)} total)")
    
    results = processed_results
    print("\n" + "="*80)
    print("📊 SUMMARY REPORT")
    print("="*80)
    
    # Count results
    successful_tests = [r for r in results if r['success']]
    blocked_count = len(blocked_ports)
    unblocked_count = len(unblocked_ports)
    error_count = len(error_ports)
    
    print(f"Total ports tested: {len(results)}")
    print(f"✅ Successful connections: {len(successful_tests)}")
    print(f"🚫 Blocked by Google: {blocked_count}")
    print(f"🟢 Unblocked: {unblocked_count}" + (" ⭐ WORKING PROXIES FOUND!" if unblocked_count > 0 else ""))
    print(f"❌ Connection errors: {error_count}")
    
    # Show detailed results for blocked vs unblocked (concise)
    if blocked_count > 0:
        blocked_port_list = [str(r['port']) for r in blocked_ports]
        print(f"\n🚫 BLOCKED PORTS ({blocked_count}): {', '.join(blocked_port_list)}")
    
    if unblocked_count > 0:
        print(f"\n🟢 UNBLOCKED PORTS ({unblocked_count}) ⭐:")
        for result in unblocked_ports:
            print(f"   ✅ Port {result['port']}: {result['search_results_count']} search results found")
            print(f"      Screenshot: {result['screenshot_path']}")
    else:
        print(f"\n🟢 UNBLOCKED PORTS: None found")
    
    if error_count > 0:
        error_port_list = [str(r['port']) for r in error_ports]
        print(f"\n❌ ERROR PORTS ({error_count}): {', '.join(error_port_list)}")
    
    # Final conclusion
    print("\n" + "="*80)
    print("🎯 CONCLUSION:")
    if blocked_count == len(successful_tests) and len(successful_tests) > 0:
        print("   ALL working proxies show the SAME RESULT - Google blocks detected")
        print(f"   Random sample of {len(successful_tests)} proxies: 100% blocked")
    elif unblocked_count == len(successful_tests) and len(successful_tests) > 0:
        print("   ALL working proxies show the SAME RESULT - No Google blocks")
        print(f"   Random sample of {len(successful_tests)} proxies: 100% unblocked")
    elif blocked_count > 0 and unblocked_count > 0:
        print("   MIXED RESULTS - Some proxies blocked, others not")
        print(f"   Random sample: {blocked_count} blocked vs {unblocked_count} unblocked")
        percentage_blocked = (blocked_count / len(successful_tests)) * 100
        print(f"   Block rate: {percentage_blocked:.1f}%")
    else:
        print("   Unable to determine - too many connection errors")
    
    # Show screenshot info
    successful_screenshots = len([r for r in results if r['success'] and r.get('screenshot_path')])
    if successful_screenshots > 0:
        print(f"\n📷 SCREENSHOTS: {successful_screenshots} screenshots saved in ./test/ directory")
        print("   Files named: port_XXXXX_screenshot.png")
    
    # Use the already categorized results
    
    # Generate concise JSON report
    report_data = {
        "test_info": {
            "timestamp": datetime.now().isoformat(),
            "proxy_server": "gb.decodo.com",
            "port_range": "30001-49999",
            "ports_tested": len(selected_ports),
            "selected_ports": selected_ports
        },
        "summary": {
            "successful_connections": len(successful_tests),
            "blocked": blocked_count,
            "unblocked": unblocked_count,
            "errors": error_count,
            "block_rate": f"{(blocked_count / len(successful_tests) * 100) if len(successful_tests) > 0 else 0:.1f}%"
        },
        "unblocked_ports": [
            {
                "port": r['port'],
                "search_results": r['search_results_count'],
                "final_url": r['final_url'],
                "screenshot": r['screenshot_path']
            } for r in unblocked_ports
        ],
        "blocked_ports": [r['port'] for r in blocked_ports],
        "error_ports": [
            {
                "port": r['port'],
                "error": r.get('error', 'Unknown error')
            } for r in error_ports
        ],
        "conclusion": "ALL_BLOCKED" if blocked_count == len(successful_tests) and len(successful_tests) > 0 
                     else "ALL_UNBLOCKED" if unblocked_count == len(successful_tests) and len(successful_tests) > 0
                     else "MIXED_RESULTS" if blocked_count > 0 and unblocked_count > 0
                     else "INCONCLUSIVE"
    }
    
    # Save JSON report (overwrites previous report)
    report_path = "test_report.json"
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n📄 JSON REPORT: Saved detailed test report to {report_path}")
    print("="*80)

if __name__ == "__main__":
    asyncio.run(test_all_proxies())
