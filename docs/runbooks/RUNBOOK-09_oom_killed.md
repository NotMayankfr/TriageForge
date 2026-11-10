# SRE Runbook: Linux Kernel OOM Killer Invocation
**Fault Identifier**: `09_oom_killed`  
**Classification**: Compute & Memory Subsystem  
**Default Severity**: SEV-1  

## 1. Symptoms & Initial Indicators
- Container exits abruptly with exit code `137` (`128 + 9 = SIGKILL`).
- Process disappears from process table (`ps aux`) without clean shutdown logs.
- CloudWatch / Docker metrics show memory reaching 100% before steep cliff.

## 2. Fast Diagnostic Commands
```bash
# 1. Inspect kernel dmesg for OOM killer invocations
dmesg -T | grep -i -E 'oom[-_]killer|killed process' | tail -n 20

# 2. Inspect Docker container state for OOMKilled flag
docker inspect --format 'OOMKilled: {{.State.OOMKilled}}, ExitCode: {{.State.ExitCode}}' triageforge-app

# 3. Check current host memory and swap utilization
free -m
vmstat 1 5

# 4. Check cgroup memory limits and peak memory usage
cat /sys/fs/cgroup/memory.events 2>/dev/null || cat /sys/fs/cgroup/memory/memory.stat
```

## 3. Immediate Mitigation Steps
1. **Restart the container**:
   ```bash
   docker restart triageforge-app
   ```
2. **Increase cgroup memory limits**:
   In `docker-compose.yml`, raise `memory: 300M` to `memory: 1G` or appropriate sizing.

## 4. Long-Term Remediation
- Profile application memory with `tracemalloc` (Python) or heap dumps.
- Configure Gunicorn `--max-requests 1000 --max-requests-jitter 50` to periodically recycle worker processes, bounding slow memory leaks.
- Setup Prometheus / CloudWatch memory alarms at 75% and 85% limits.
