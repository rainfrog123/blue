#%% Imports and Setup
"""
Check domain availability via Namecheap's WebSocket API
Edit namecheap.txt to change domains, then run: python3 check_namecheap.py
"""
import asyncio
import json
import time
import websockets
from pathlib import Path

#%% Load Domains from File
def load_domains(filepath: str = 'namecheap.txt') -> tuple[list[str], str]:
    """
    Load domain names from text file.
    
    File format:
        - One domain name per line (without TLD)
        - Lines starting with # are comments
        - tld=site sets the TLD to check
    
    Returns:
        (list of domain names, tld)
    """
    path = Path(__file__).parent / filepath
    if not path.exists():
        print(f"Error: {filepath} not found. Creating template...")
        path.write_text("# Add domain names here (one per line)\ntld=site\n\nexample\ntest\n")
        return ['example', 'test'], 'site'
    
    domains = []
    tld = 'site'  # default
    
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('tld='):
            tld = line.split('=', 1)[1].strip()
            continue
        domains.append(line.lower())
    
    return domains, tld

#%% Namecheap WebSocket Checker
async def check_domains_namecheap(domain_names: list[str], tld: str = 'site') -> dict:
    """
    Check domain availability via Namecheap's WebSocket API.
    
    Args:
        domain_names: List of domain names without TLD
        tld: Top-level domain to check
    
    Returns:
        Dict with 'available', 'taken', 'standard', 'premium' lists
    """
    domains_full = [f'{d}.{tld}' for d in domain_names]
    
    ws = await websockets.connect(
        'wss://domains-ws.revved.com/v1/ws?batch=false&whois=true&trace=true',
        additional_headers={
            'Origin': 'https://www.namecheap.com',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        }
    )
    
    # Send in batches of 30
    all_results = {}
    for i in range(0, len(domains_full), 30):
        batch = domains_full[i:i+30]
        req_id = str(int(time.time() * 1000)) + str(i)
        request = {
            'type': 'domainStatus',
            'reqID': req_id,
            'data': {'domains': batch}
        }
        await ws.send(json.dumps(request))
        
        received = 0
        while received < len(batch):
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=30.0)
                data = json.loads(msg)
                if data.get('type') == 'domainStatusResponse':
                    d = data.get('data', {})
                    name = d.get('name')
                    if name:
                        all_results[name] = d
                        received += 1
            except asyncio.TimeoutError:
                break
        
        if i + 30 < len(domains_full):
            await asyncio.sleep(0.3)
    
    await ws.close()
    
    # Organize results
    standard = []
    premium = []
    taken = []
    
    for name in sorted(all_results.keys()):
        r = all_results[name]
        is_available = r.get('available', False)
        is_premium = r.get('premium', False)
        fee = r.get('fee', {}).get('amount') if r.get('fee') else None
        registrar = r.get('extra', {}).get('registrar', '')
        year = r.get('whois', {}).get('createdYear') or r.get('extra', {}).get('createdYear')
        
        if is_available:
            if is_premium:
                premium.append({'name': name, 'fee': fee})
            else:
                standard.append({'name': name})
        else:
            taken.append({'name': name, 'registrar': registrar, 'year': year})
    
    return {
        'standard': standard,
        'premium': premium,
        'taken': taken,
        'raw': all_results
    }

#%% Print Results
def print_results(results: dict):
    """Pretty print domain check results"""
    standard = results['standard']
    premium = results['premium']
    taken = results['taken']
    
    print()
    print('=' * 60)
    print('STANDARD PRICE (Best Value!):')
    print('=' * 60)
    if standard:
        for d in standard:
            print(f"✓ {d['name']}")
    else:
        print("  (none found)")
    
    print()
    print('=' * 60)
    print('PREMIUM AVAILABLE:')
    print('=' * 60)
    for d in sorted(premium, key=lambda x: x['fee'] or 0):
        print(f"✓ {d['name']} - ${d['fee']}")
    
    print()
    print('=' * 60)
    print('TAKEN:')
    print('=' * 60)
    for d in taken:
        info = f"✗ {d['name']}"
        if d['year']:
            info += f" (since {d['year']})"
        if d['registrar']:
            info += f" [{d['registrar']}]"
        print(info)
    
    print()
    print(f'Summary: {len(standard)} standard, {len(premium)} premium, {len(taken)} taken')

#%% Main
async def main():
    """Load domains from namecheap.txt and check availability"""
    domains, tld = load_domains()
    
    print(f'Checking {len(domains)} domains with .{tld} ...')
    print('-' * 60)
    
    results = await check_domains_namecheap(domains, tld)
    print_results(results)
    
    return results

#%% Run
if __name__ == '__main__':
    asyncio.run(main())
