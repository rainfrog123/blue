#!/usr/bin/env python3
import asyncio
import random
import json
from datetime import datetime
from patchright.async_api import async_playwright

# Test configuration
TEST_RUNS = 3  # Number of test runs for averaging

class NetworkMonitor:
    def __init__(self):
        self.requests = []
        self.responses = []
        self.total_request_bytes = 0
        self.total_response_bytes = 0
        self.failed_requests = 0
    
    def on_request(self, request):
        # Estimate request size (headers + body)
        request_size = len(request.url.encode('utf-8'))
        for name, value in request.headers.items():
            request_size += len(f"{name}: {value}\r\n".encode('utf-8'))
        
        if request.post_data:
            request_size += len(request.post_data.encode('utf-8'))
        
        self.requests.append({
            'url': request.url,
            'method': request.method,
            'resource_type': request.resource_type,
            'size_bytes': request_size
        })
        self.total_request_bytes += request_size
    
    def on_response(self, response):
        # Get actual response size
        response_size = 0
        content_length = response.headers.get('content-length')
        if content_length:
            response_size = int(content_length)
        
        # Estimate headers size
        headers_size = 0
        for name, value in response.headers.items():
            headers_size += len(f"{name}: {value}\r\n".encode('utf-8'))
        
        total_response_size = response_size + headers_size
        
        self.responses.append({
            'url': response.url,
            'status': response.status,
            'content_type': response.headers.get('content-type', ''),
            'content_length': response_size,
            'headers_size': headers_size,
            'total_size': total_response_size
        })
        self.total_response_bytes += total_response_size
    
    def on_request_failed(self, request):
        self.failed_requests += 1
    
    def get_stats(self):
        return {
            'total_requests': len(self.requests),
            'total_responses': len(self.responses),
            'failed_requests': self.failed_requests,
            'total_request_bytes': self.total_request_bytes,
            'total_response_bytes': self.total_response_bytes,
            'total_bytes': self.total_request_bytes + self.total_response_bytes,
            'requests_by_type': self._group_by_resource_type(),
            'largest_responses': sorted(self.responses, key=lambda x: x['total_size'], reverse=True)[:5]
        }
    
    def _group_by_resource_type(self):
        types = {}
        for req in self.requests:
            resource_type = req['resource_type']
            if resource_type not in types:
                types[resource_type] = {'count': 0, 'bytes': 0}
            types[resource_type]['count'] += 1
            types[resource_type]['bytes'] += req['size_bytes']
        return types

async def measure_bandwidth(run_number, test_type="original"):
    """Measure bandwidth usage for direct network access"""
    print(f"📊 Measuring bandwidth for run {run_number} ({test_type} version)...")
    
    monitor = NetworkMonitor()
    
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                channel="chrome"
            )
            page = await browser.new_page()
            
            # Set up network monitoring
            page.on('request', monitor.on_request)
            page.on('response', monitor.on_response)
            page.on('requestfailed', monitor.on_request_failed)
            
            if test_type == "optimized":
                # Apply optimizations for comparison
                await page.route("**/*", lambda route: asyncio.create_task(
                    route.abort() if route.request.resource_type in {"image", "media", "font", "stylesheet"} 
                    else route.continue_()
                ))
                # Use lightweight search
                url = "https://www.google.com/search?q=1&gbv=1&num=1&hl=en&pws=0"
                wait_until = "domcontentloaded"
                timeout = 8000
            else:
                # Original version
                url = "https://www.google.com/search?q=1"
                wait_until = "load"
                timeout = 15000
            
            # Load the page and measure
            start_time = datetime.now()
            await page.goto(url, wait_until=wait_until, timeout=timeout)
            
            # Check for search results and blocking
            search_results = await page.query_selector_all("[data-ved]")
            page_content = await page.content()
            
            block_indicators = [
                "unusual traffic", "captcha", "sorry/index", 
                "verify you're not a robot", "automated queries"
            ]
            
            found_blocks = [indicator for indicator in block_indicators 
                          if indicator.lower() in page_content.lower()]
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            await browser.close()
            
            stats = monitor.get_stats()
            
            return {
                'run': run_number,
                'test_type': test_type,
                'success': True,
                'duration_seconds': duration,
                'blocked': len(found_blocks) > 0,
                'block_reasons': found_blocks,
                'search_results_count': len(search_results),
                'bandwidth': stats,
                'final_url': page.url
            }
            
    except Exception as e:
        return {
            'run': run_number,
            'test_type': test_type,
            'success': False,
            'error': str(e),
            'bandwidth': {'total_bytes': 0}
        }

async def run_bandwidth_test():
    """Run bandwidth measurement test"""
    print("🔬 BANDWIDTH MEASUREMENT TEST (Direct Network)")
    print("=" * 60)
    
    print(f"Running {TEST_RUNS} test runs for each version")
    print("Testing direct Google access (no proxy)")
    print("=" * 60)
    
    # Test original version
    print("\n📈 Testing ORIGINAL version (current script)...")
    original_results = []
    for run in range(1, TEST_RUNS + 1):
        result = await measure_bandwidth(run, "original")
        original_results.append(result)
        
        if result['success']:
            mb = result['bandwidth']['total_bytes'] / (1024 * 1024)
            print(f"  Run {run}: {mb:.2f} MB ({result['bandwidth']['total_bytes']:,} bytes)")
            print(f"    Requests: {result['bandwidth']['total_requests']}, Duration: {result['duration_seconds']:.1f}s")
            if result['blocked']:
                print(f"    🚫 BLOCKED: {result['block_reasons']}")
            else:
                print(f"    ✅ UNBLOCKED: {result['search_results_count']} search results")
        else:
            print(f"  Run {run}: ❌ ERROR - {result['error']}")
    
    # Test optimized version
    print("\n📉 Testing OPTIMIZED version (with bandwidth savings)...")
    optimized_results = []
    for run in range(1, TEST_RUNS + 1):
        result = await measure_bandwidth(run, "optimized")
        optimized_results.append(result)
        
        if result['success']:
            mb = result['bandwidth']['total_bytes'] / (1024 * 1024)
            print(f"  Run {run}: {mb:.2f} MB ({result['bandwidth']['total_bytes']:,} bytes)")
            print(f"    Requests: {result['bandwidth']['total_requests']}, Duration: {result['duration_seconds']:.1f}s")
            if result['blocked']:
                print(f"    🚫 BLOCKED: {result['block_reasons']}")
            else:
                print(f"    ✅ UNBLOCKED: {result['search_results_count']} search results")
        else:
            print(f"  Run {run}: ❌ ERROR - {result['error']}")
    
    # Calculate averages and savings
    print("\n" + "=" * 60)
    print("📊 BANDWIDTH COMPARISON RESULTS")
    print("=" * 60)
    
    original_successful = [r for r in original_results if r['success']]
    optimized_successful = [r for r in optimized_results if r['success']]
    
    if original_successful and optimized_successful:
        # Calculate averages
        orig_avg_bytes = sum(r['bandwidth']['total_bytes'] for r in original_successful) / len(original_successful)
        opt_avg_bytes = sum(r['bandwidth']['total_bytes'] for r in optimized_successful) / len(optimized_successful)
        
        orig_avg_mb = orig_avg_bytes / (1024 * 1024)
        opt_avg_mb = opt_avg_bytes / (1024 * 1024)
        
        savings_bytes = orig_avg_bytes - opt_avg_bytes
        savings_percent = (savings_bytes / orig_avg_bytes) * 100 if orig_avg_bytes > 0 else 0
        
        print(f"📈 ORIGINAL version average: {orig_avg_mb:.2f} MB ({orig_avg_bytes:,.0f} bytes) per port")
        print(f"📉 OPTIMIZED version average: {opt_avg_mb:.2f} MB ({opt_avg_bytes:,.0f} bytes) per port")
        print(f"💰 SAVINGS per port: {savings_bytes/1024/1024:.2f} MB ({savings_percent:.1f}% reduction)")
        
        # Calculate total for 63 ports
        orig_total_63 = (orig_avg_bytes * 63) / (1024 * 1024)
        opt_total_63 = (opt_avg_bytes * 63) / (1024 * 1024)
        total_savings = orig_total_63 - opt_total_63
        
        print(f"\n🎯 PROJECTED USAGE FOR 63 CONCURRENT TESTS:")
        print(f"   Original script: {orig_total_63:.1f} MB per run")
        print(f"   Optimized script: {opt_total_63:.1f} MB per run")
        print(f"   Total savings: {total_savings:.1f} MB per run ({savings_percent:.1f}% reduction)")
        
        # Show breakdown by resource type for original
        if original_successful:
            print(f"\n📋 TRAFFIC BREAKDOWN (Original version):")
            sample_result = original_successful[0]
            for resource_type, data in sample_result['bandwidth']['requests_by_type'].items():
                mb = data['bytes'] / (1024 * 1024)
                print(f"   {resource_type}: {data['count']} requests, {mb:.3f} MB")
    
    else:
        print("❌ Unable to calculate comparison - not enough successful tests")
    
    # Save detailed report
    report = {
        'timestamp': datetime.now().isoformat(),
        'test_config': {
            'test_runs': TEST_RUNS,
            'network_type': 'direct_network'
        },
        'original_results': original_results,
        'optimized_results': optimized_results,
        'summary': {
            'original_avg_mb': orig_avg_mb if 'orig_avg_mb' in locals() else 0,
            'optimized_avg_mb': opt_avg_mb if 'opt_avg_mb' in locals() else 0,
            'savings_percent': savings_percent if 'savings_percent' in locals() else 0
        }
    }
    
    with open('bandwidth_measurement_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📄 Detailed report saved to: bandwidth_measurement_report.json")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(run_bandwidth_test())
