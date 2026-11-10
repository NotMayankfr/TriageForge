# SRE Runbook: SSH Lockout (Key Permissions / Daemon Config)
**Fault Identifier**: `10_ssh_lockout`  
**Classification**: Security & Remote Access Subsystem  
**Default Severity**: SEV-1 (Management Lockout)  

## 1. Symptoms & Initial Indicators
- SSH login fails: `Permission denied (publickey,gssapi-keyex,gssapi-with-mic)`.
- Client `ssh -vvv` debug output shows: `debug1: Offering public key ... debug1: Authentications that can continue: publickey`.
- Bastion or instance rejects key authentication despite matching private key.

## 2. Fast Diagnostic Commands
```bash
# 1. Run SSH client in high-verbosity debug mode
ssh -vvv -i ~/.ssh/id_rsa forge_admin@localhost -p 2222

# 2. Inspect OpenSSH server logs on target host
journalctl -u sshd -n 30 --no-pager
# Look for: "Authentication refused: bad ownership or modes for file /home/.../.ssh/authorized_keys"

# 3. Inspect directory and file permissions
ls -ld /home/forge_admin
ls -ld /home/forge_admin/.ssh
ls -l /home/forge_admin/.ssh/authorized_keys
```

## 3. Immediate Mitigation Steps
1. **Fix Insecure Permissions (StrictModes requirement)**:
   OpenSSH will unconditionally reject keys if files are group- or world-writable:
   ```bash
   chmod 700 /home/forge_admin/.ssh
   chmod 600 /home/forge_admin/.ssh/authorized_keys
   chown -R forge_admin:forge_admin /home/forge_admin/.ssh
   ```
2. **Emergency Access (AWS EC2)**:
   If completely locked out of EC2:
   - Use AWS Systems Manager (SSM) Session Manager to obtain a root shell without SSH keys.
   - Or run EC2 Instance Connect: `aws ec2-instance-connect send-ssh-public-key`.

## 4. Long-Term Remediation
- Discontinue direct SSH keys in favor of AWS SSM Session Manager with IAM role auditing.
- Automate configuration compliance using Ansible or AWS Config to enforce file permissions.
