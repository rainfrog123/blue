#!/usr/bin/env python3
# %% Security Group Debugger
"""
Debug security group rules to find if port 443 is blocked.

Usage:
    python debug_security_group.py [instance_ip] [port]
    
Example:
    python debug_security_group.py 47.86.7.159 443
"""
import sys
from client import ecs_client, ecs_models, REGION_ID, print_header

def check_port_in_range(port: int, port_range: str) -> bool:
    """Check if a port is included in a port range string."""
    if not port_range or "/" not in port_range:
        return False
    
    parts = port_range.split("/")
    if len(parts) != 2:
        return False
    
    start, end = parts
    
    # -1/-1 means all ports
    if start == "-1" and end == "-1":
        return True
    
    # Check if port is in range
    if start.isdigit() and end.isdigit():
        return int(start) <= port <= int(end)
    
    return False


def analyze_security_group(instance_ip: str, check_port: int = 443):
    """Analyze security group rules for a specific instance and port."""
    
    print_header(f"SECURITY GROUP DEBUG - Port {check_port}")
    print(f"Target IP: {instance_ip}")
    print(f"Target Port: {check_port}")
    print()
    
    # List instances
    request = ecs_models.DescribeInstancesRequest(region_id=REGION_ID, page_size=100)
    response = ecs_client.describe_instances(request)
    
    if not response.body or not response.body.instances or not response.body.instances.instance:
        print("❌ No instances found")
        return False
    
    instances = response.body.instances.instance
    target_instance = None
    
    # Find target instance
    for inst in instances:
        ips = inst.public_ip_address.ip_address if inst.public_ip_address else []
        public_ip = ips[0] if ips else None
        
        if public_ip == instance_ip:
            target_instance = inst
            break
    
    if not target_instance:
        print(f"❌ No instance found with IP: {instance_ip}")
        print(f"\nAvailable instances:")
        for inst in instances:
            ips = inst.public_ip_address.ip_address if inst.public_ip_address else []
            public_ip = ips[0] if ips else "N/A"
            print(f"  - {inst.instance_name}: {public_ip}")
        return False
    
    print(f"✅ Found instance: {target_instance.instance_name}")
    print(f"   Instance ID: {target_instance.instance_id}")
    print(f"   Status: {target_instance.status}")
    print(f"   Security Groups: {target_instance.security_group_ids.security_group_id}")
    print()
    
    # Analyze each security group
    port_is_allowed = False
    
    for sg_id in target_instance.security_group_ids.security_group_id:
        print(f"{'='*70}")
        print(f"Security Group: {sg_id}")
        print(f"{'='*70}")
        
        # Get security group rules
        sg_request = ecs_models.DescribeSecurityGroupAttributeRequest(
            region_id=REGION_ID,
            security_group_id=sg_id
        )
        sg_response = ecs_client.describe_security_group_attribute(sg_request)
        
        if not sg_response.body or not sg_response.body.permissions:
            print("No permissions found for this security group")
            continue
        
        permissions = sg_response.body.permissions.permission
        
        # Separate ingress and egress
        ingress_rules = [p for p in permissions if p.direction == "ingress"]
        egress_rules = [p for p in permissions if p.direction == "egress"]
        
        print(f"\n📥 INGRESS RULES ({len(ingress_rules)} total):")
        print("-"*70)
        
        if not ingress_rules:
            print("  No ingress rules - ALL PORTS BLOCKED BY DEFAULT")
        else:
            port_rules = []
            
            for i, perm in enumerate(ingress_rules, 1):
                port_matches = check_port_in_range(check_port, perm.port_range)
                marker = "  👉" if port_matches else "    "
                
                print(f"\n{marker} [{i}] {perm.ip_protocol.upper()} {perm.port_range}")
                print(f"{marker}     Source: {perm.source_cidr_ip or perm.source_group_id or 'N/A'}")
                print(f"{marker}     Policy: {perm.policy}")
                print(f"{marker}     Priority: {perm.priority}")
                
                if port_matches:
                    port_rules.append(perm)
                    if perm.policy == "Accept":
                        port_is_allowed = True
        
            print(f"\n{'='*70}")
            print(f"PORT {check_port} ANALYSIS:")
            print(f"{'='*70}")
            
            if port_rules:
                print(f"\n✅ Found {len(port_rules)} rule(s) affecting port {check_port}:")
                for rule in port_rules:
                    status = "✅ ALLOWED" if rule.policy == "Accept" else "❌ DENIED"
                    print(f"\n  {status}")
                    print(f"    Protocol: {rule.ip_protocol.upper()}")
                    print(f"    Port Range: {rule.port_range}")
                    print(f"    Source: {rule.source_cidr_ip or rule.source_group_id or 'N/A'}")
                    print(f"    Priority: {rule.priority}")
            else:
                print(f"\n⚠️  NO RULES FOUND FOR PORT {check_port}")
                print(f"    Default behavior: BLOCKED")
        
        print(f"\n📤 EGRESS RULES ({len(egress_rules)} total):")
        print("-"*70)
        if egress_rules:
            for i, perm in enumerate(egress_rules, 1):
                print(f"  [{i}] {perm.ip_protocol.upper()} {perm.port_range}")
                print(f"      Dest: {perm.dest_cidr_ip or perm.dest_group_id or 'N/A'}")
                print(f"      Policy: {perm.policy}")
        else:
            print("  No egress rules defined")
        
        print()
    
    # Final summary
    print(f"\n{'#'*70}")
    print(f"# FINAL RESULT")
    print(f"{'#'*70}")
    
    if port_is_allowed:
        print(f"✅ Port {check_port} IS ALLOWED")
        print(f"   The security group has an Accept rule for this port.")
    else:
        print(f"❌ Port {check_port} IS BLOCKED")
        print(f"   No Accept rule found in the security group.")
        print(f"\n💡 SOLUTION:")
        print(f"   Add an ingress rule to allow port {check_port}:")
        print(f"   - Protocol: TCP")
        print(f"   - Port Range: {check_port}/{check_port}")
        print(f"   - Source: 0.0.0.0/0 (or specific IPs)")
        print(f"   - Priority: 1")
        print(f"   - Action: Accept")
        
        print(f"\n   Via Alibaba Cloud Console:")
        print(f"   1. Go to ECS Console → Security Groups")
        print(f"   2. Click on security group: {target_instance.security_group_ids.security_group_id[0]}")
        print(f"   3. Go to 'Inbound Rules' tab")
        print(f"   4. Click 'Add Rule'")
        print(f"   5. Set: Protocol=TCP, Port={check_port}, Source=0.0.0.0/0, Action=Allow")
    
    print(f"{'#'*70}")
    print()
    
    return port_is_allowed


# %% Main execution
if __name__ == "__main__":
    instance_ip = sys.argv[1] if len(sys.argv) > 1 else "47.86.7.159"
    check_port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    analyze_security_group(instance_ip, check_port)
