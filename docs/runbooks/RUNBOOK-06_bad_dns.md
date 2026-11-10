# SRE Runbook: DNS Resolution Failure (NXDOMAIN / SERVFAIL)
**Fault Identifier**: `06_bad_dns`  
**Classification**: Network Subsystem  
**Default Severity**: SEV-1  

## 1. Symptoms & Initial Indicators
- Client commands fail with: `curl: (6) Could not resolve host: ...`
- Application throws: `socket.gaierror: [Errno -2] Name or service not known` or `[Errno -3] Temporary failure in name resolution`.
- Ping returns: `ping: unknown host ...`.

## 2. Fast Diagnostic Commands
```bash
# 1. Inspect local resolver configuration
cat /etc/resolv.conf

# 2. Check systemd-resolved status (on modern Linux/Ubuntu systems)
resolvectl status

# 3. Perform explicit DNS query with trace
dig +trace api.triageforge.local

# 4. Query known public upstream resolvers directly (bypassing local cache)
dig @1.1.1.1 api.triageforge.local +short
dig @8.8.8.8 api.triageforge.local +short
```

## 3. Immediate Mitigation Steps
1. **Fix corrupted /etc/resolv.conf**:
   Ensure valid nameservers are defined:
   ```bash
   echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf
   echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
   ```
2. **Flush local resolver cache**:
   ```bash
   sudo resolvectl flush-caches
   ```

## 4. Long-Term Remediation
- For AWS environments: verify VPC DHCP Options Set has AmazonProvidedDNS (`10.x.x.2`).
- Set reasonable DNS TTLs (e.g. 60s for microservices, 300s for public ingress) to prevent stale cache lockouts during failovers.
