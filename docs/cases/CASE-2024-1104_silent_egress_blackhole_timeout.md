# Support Case Report: CASE-2024-1104
**Severity Level**: SEV-1 (Critical System Outage)  
**Assigned Engineer**: Cloud Support Engineer II (Security & Core Networking)  
**Component**: Network Transport Layer (`VPC Security Group` / `iptables DROP` / `Routing`)  
**Status**: Resolved / Root Cause Identified  

---

## 1. Case Summary
At 09:14 UTC, external API traffic to the production ingress gateway ceased completely. Automated API test suites reported connection timeouts after 10,000ms. Monitoring graphs revealed a sharp drop in HTTP requests to zero, but DNS resolution remained functional. Critical client queries hung indefinitely without receiving any TCP rejection (RST) or HTTP error code.

---

## 2. Customer Impact
- **Affected Services**: Public API Ingress, External Webhook Processors.
- **Outage Duration**: 19 minutes total downtime.
- **Customer Experience**: Client applications hung for up to 60 seconds before timing out with `ETIMEDOUT` / `curl: (28) Failed to connect to ... Connection timed out`.

---

## 3. Incident Timeline
| Time (UTC) | Event |
|:---|:---|
| **09:12:00** | Infrastructure change applied via automated Terraform deployment pipeline (`v2.14.0`). |
| **09:14:15** | Synthetic edge monitors alerted on 100% packet loss to TCP port 443. PagerDuty SEV-1 paged. |
| **09:16:00** | Cloud Support Engineer engaged; ran `triageforge diagnose --url https://api.triageforge.local`. |
| **09:17:12** | TriageForge isolated failure to Layer 2 (TCP Timeout), diagnosing a silent packet drop firewall issue with 96% confidence and ruling out service crash. |
| **09:18:40** | `nc -zv` confirmed port 443 hanging; `tcpdump` captured outgoing SYN without SYN-ACK or RST. |
| **09:21:00** | Root cause identified: Terraform security group module omitted the inbound HTTPS rule during ingress CIDR refactoring. |
| **09:23:30** | Hotfix PR deployed restoring ingress rule `tcp/443` from `0.0.0.0/0`. |
| **09:25:00** | Full TCP connectivity verified; synthetic monitors green. Incident mitigated. |

---

## 4. Troubleshooting Steps & Technical Observations

### Step 1: Bottom-Up Triage via TriageForge
```bash
$ triageforge diagnose --url https://api.triageforge.local:443
```
- **Layer 1 (DNS)**: PASS (`api.triageforge.local` resolved to `10.0.2.14` in 1.2ms).
- **Layer 2 (TCP)**: **FAIL** (TCP connect to `10.0.2.14:443` TIMED OUT after 4.0s).
  - *Engine Observation*: SYN sent, zero response received (no SYN-ACK and no RST).
  - *Hypothesis*: `01_sg_block` (Firewall / Security Group Dropping Traffic, 96% Match).
  - *Distinction*: **NOT** `ECONNREFUSED`. The destination host is alive and DNS is functioning, but packets are dropped silently by a stateful packet filter.

### Step 2: Low-Level Socket Probing
Comparing connection attempts with short timeouts confirmed an un-responsive socket:
```bash
$ nc -zv -w 3 10.0.2.14 443
# (Hangs for 3 seconds, then exits with code 1)

$ nc -zv -w 3 10.0.2.14 22
Connection to 10.0.2.14 22 port [tcp/ssh] succeeded!
```
Port 22 connected instantly, proving the instance was alive and the VPC routing table / IGW was functional. Only port 443 was being dropped.

### Step 3: Packet Capture (tcpdump) Evidence
Running `tcpdump` while executing a probe request:
```bash
$ tcpdump -nn -i any port 443 -v
09:19:02.104231 IP 10.0.1.5.49812 > 10.0.2.14.443: Flags [S], seq 389104812, win 64240, options [mss 1460,sackOK,TS val 281920 ecr 0], length 0
09:19:03.108412 IP 10.0.1.5.49812 > 10.0.2.14.443: Flags [S], seq 389104812, win 64240, options [mss 1460,sackOK,TS val 282924 ecr 0], length 0
09:19:05.124801 IP 10.0.1.5.49812 > 10.0.2.14.443: Flags [S], seq 389104812, win 64240, options [mss 1460,sackOK,TS val 284940 ecr 0], length 0
```
Notice: The client retransmitted TCP SYN 3 times without a single ACK or RST packet returned. This is the unmistakable fingerprint of a stateful firewall DROP rule (Security Group or `iptables -j DROP`). If the web service had simply stopped, the Linux kernel would have emitted a `Flags [R.]` (RST) immediately.

### Step 4: AWS Security Group Rule Audit
Querying the active AWS Security Group rules via AWS CLI:
```bash
$ aws ec2 describe-security-groups --group-ids sg-0a91f42918bcde01 --query "SecurityGroups[0].IpPermissions"
[
    {
        "FromPort": 22,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
        "ToPort": 22
    }
]
```
The ingress permissions list was completely missing rules for port 80 and port 443.

---

## 5. Root Cause Analysis (5 Whys)
1. **Why did client requests time out?**  
   TCP SYN packets on port 443 were dropped by the AWS hypervisor security group filter.
2. **Why were packets dropped?**  
   Security Group `sg-0a91f42918bcde01` had no ingress rule permitting TCP 443.
3. **Why was the ingress rule missing?**  
   A Terraform module refactoring accidentally renamed `ingress_rules` to `custom_ingress_rules`, causing Terraform to evaluate an empty list and delete the HTTPS rule.
4. **Why was this change applied to production?**  
   The pull request lacked an automated `terraform plan` guardrail checking for security group rule deletions.
5. **Why was traffic not routed to a fallback?**  
   The architecture lacked a multi-region or secondary ALB failover path for external ingress.

---

## 6. Resolution & Immediate Corrective Actions
1. **Rule Restoration**: Manually restored the ingress rule via AWS CLI, followed by a Terraform state sync:
   ```bash
   aws ec2 authorize-security-group-ingress \
     --group-id sg-0a91f42918bcde01 \
     --protocol tcp --port 443 --cidr 0.0.0.0/0
   ```
2. **Local Lab Equivalence**: In local Docker test environments, verified that deleting the `iptables -I DOCKER-USER -p tcp --dport 443 -j DROP` rule restores nominal latency (< 2ms).

---

## 7. Prevention & Hardening Runbook
- [x] **CI/CD Conftest / OPA Policy**: Add Open Policy Agent (OPA) checks to reject Terraform plans that drop ingress rules on production security groups.
- [x] **VPC Flow Logs Alarming**: Provision a CloudWatch Metric Filter on VPC Flow Logs for `action = "REJECT"` on destination port 443, alarming if count > 50 in 1 minute.
- [x] **Automated Triage Harness**: Embed `triageforge diagnose` into pre-deployment canary smoke tests.
