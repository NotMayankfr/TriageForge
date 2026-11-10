# SRE Runbook: Storage Exhaustion (Disk / Inode Full)
**Fault Identifier**: `03_disk_full`  
**Classification**: Storage Subsystem  
**Default Severity**: SEV-1  

## 1. Symptoms & Initial Indicators
- HTTP requests return `500 Internal Server Error`.
- Application logs contain: `OSError: [Errno 28] No space left on device` or `ENOSPC`.
- Database write operations fail: `PANIC: could not write to file ... No space left on device`.
- SSH login warnings: `Could not chdir to home directory ... No space left on device`.

## 2. Fast Diagnostic Commands
```bash
# 1. Check disk block usage across all mounts
df -h

# 2. Check inode table capacity (critical: disk can show 50% free while inodes are 100% full!)
df -i

# 3. Locate top 10 largest directories consuming storage
du -sh /var/log/* 2>/dev/null | sort -hr | head -n 10

# 4. Check for unlinked open file descriptors holding disk blocks (deleted but held open by processes)
lsof +L1
```

## 3. Immediate Mitigation Steps
1. **Truncate (do not delete) active log files**:
   ```bash
   # Truncating zeroes the file size immediately without breaking open file descriptors
   : > /var/log/nginx/access.log
   : > /var/log/app/runaway.log
   ```
2. **Reclaim space from unlinked open files**:
   If `lsof +L1` shows large deleted files held open by a process (e.g. gunicorn or nginx), reload or restart the service to release the disk blocks:
   ```bash
   systemctl reload nginx
   docker restart triageforge-app
   ```

## 4. Long-Term Remediation
- Configure log rotation in `/etc/logrotate.d/` with `maxsize 100M` and `rotate 5`.
- Mount `/var/log` onto a separate disk volume so runaway log growth cannot crash the root `/` partition.
- Add CloudWatch / Prometheus alert at 80% and 90% disk utilization.
