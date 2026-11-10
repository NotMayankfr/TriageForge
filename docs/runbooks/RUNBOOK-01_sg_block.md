# SRE Runbook: Security Group / Ingress Firewall Block
**Fault Identifier**: `01_sg_block`  
**Classification**: Network Transport & Security Subsystem  
**Default Severity**: SEV-1  

## 1. Symptoms & Initial Indicators
- Client requests hang and eventually time out after 10–60 seconds.
- `curl` returns: `curl: (28) Failed to connect to ... Connection timed out`.
- Ping (ICMP) may succeed or fail depending on ICMP rules, but TCP port 80/443 handshake fails to receive SYN-ACK.
- **Key Diagnostic Clue**: The connection times out (`ETIMEDOUT`) rather than being refused (`ECONNREFUSED`).

## 2. Fast Diagnostic Commands
```bash
# 1. Test TCP connect timeout with a short timeout window (3 seconds)
nc -zv -w 3 localhost 80
nc -zv -w 3 localhost 443

# 2. Trace route to destination
traceroute -n -T -p 443 localhost

# 3. Check local iptables DROP rules (if running Linux/Docker)
sudo iptables -L -n -v | grep -E 'DROP|REJECT'
sudo iptables -t nat -L -n -v

# 4. AWS Security Group query (if deployed to AWS EC2)
aws ec2 describe-security-groups \
  --group-ids sg-xxxxxxxxx \
  --query "SecurityGroups[0].IpPermissions"
```

## 3. Immediate Mitigation Steps
1. **Local Linux / Docker Stack**:
   Revert any blocking `iptables` rules or unpause the paused container:
   ```bash
   sudo iptables -D DOCKER-USER -p tcp -m multiport --dports 80,443 -j DROP 2>/dev/null || true
   sudo iptables -D INPUT -p tcp -m multiport --dports 80,443 -j DROP 2>/dev/null || true
   docker unpause triageforge-nginx 2>/dev/null || true
   ```
2. **AWS EC2 / ALB Environment**:
   Authorize ingress port 443/80 from client CIDR:
   ```bash
   aws ec2 authorize-security-group-ingress \
     --group-id sg-xxxxxxxxx \
     --protocol tcp --port 443 --cidr 0.0.0.0/0
   ```

## 4. Long-Term Remediation
- Use Infrastructure as Code (Terraform) with automated pull-request plan validation.
- Enable AWS Network Access Analyzer or VPC Flow Logs alarms to detect unexpected packet drops.
