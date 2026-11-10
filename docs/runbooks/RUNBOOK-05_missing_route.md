# SRE Runbook: Missing Route / Gateway Egress Blackhole
**Fault Identifier**: `05_missing_route`  
**Classification**: Network Subsystem (Layer 3 Routing)  
**Default Severity**: SEV-1  

## 1. Symptoms & Initial Indicators
- Instance or container cannot communicate with external services or the internet.
- Network commands fail immediately with: `connect: Network is unreachable` (`ENETUNREACH`) or `No route to host` (`EHOSTUNREACH`).
- Package updates (`apt-get update`) or external API calls hang or fail immediately.

## 2. Fast Diagnostic Commands
```bash
# 1. Inspect kernel routing table
ip route show

# 2. Check ARP / Neighbor table for gateway resolution
ip neigh show

# 3. Test gateway reachability
ping -c 3 $(ip route | grep default | awk '{print $3}')

# 4. Traceroute to public IP (identifies where packets stop)
traceroute -n -m 5 8.8.8.8
```

## 3. Immediate Mitigation Steps
1. **Local Linux / Container**:
   Re-attach container to the bridge network or re-add default gateway:
   ```bash
   docker network connect stack_forge-net triageforge-app 2>/dev/null || true
   sudo ip route add default via 172.18.0.1 2>/dev/null || true
   ```
2. **AWS VPC Route Table**:
   If the subnet route table is missing an Internet Gateway route:
   ```bash
   aws ec2 create-route \
     --route-table-id rtb-xxxxxxxxx \
     --destination-cidr-block 0.0.0.0/0 \
     --gateway-id igw-xxxxxxxxx
   ```

## 4. Long-Term Remediation
- Separate subnets strictly into Public (with IGW default route) and Private (with NAT Gateway default route).
- Implement AWS Config rule `subnet-route-table-associated` to detect unassociated or misconfigured subnets.
