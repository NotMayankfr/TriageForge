# Support Case Report: CASE-2024-0891
**Severity Level**: SEV-2 (Degraded Production Service)  
**Assigned Engineer**: Cloud Support Engineer II (Networking & Compute)  
**Component**: Reverse Proxy & ASGI Application Tier (`Nginx` → `Gunicorn/FastAPI`)  
**Status**: Resolved / Post-Mortem Published  

---

## 1. Case Summary
At 14:22 UTC, enterprise monitoring flagged an elevated rate of HTTP 502 (Bad Gateway) errors returned by the front-facing Nginx reverse proxy tier. Client requests intermittently failed with `502 Bad Gateway` while edge latency spiked from a p95 of 42ms to over 2,100ms. Host-level healthchecks indicated the EC2/container host remained online, but downstream application sockets became unresponsive.

---

## 2. Customer Impact
- **Affected Services**: Core Customer Underwriting API (`/api/items`, `/api/db-check`).
- **User Experience**: Approximately 34% of end-user requests failed with browser 502 errors over a 28-minute degradation window.
- **Data Integrity**: Zero data corruption; read requests failed cleanly before transaction initiation.

---

## 3. Incident Timeline
| Time (UTC) | Event |
|:---|:---|
| **14:18:00** | Traffic spike observed following marketing batch notification (+310 req/sec). |
| **14:21:40** | First HTTP 502 recorded in edge Nginx access logs. |
| **14:22:15** | CloudWatch synthetic canary alarmed on 5xx error rate > 5%. PagerDuty alert triggered. |
| **14:24:30** | On-call engineer engaged; initiated `triageforge diagnose --url https://api.triageforge.local`. |
| **14:26:10** | TriageForge isolated failure to Layer 4 (HTTP 502) and Layer 5 (Host), identifying Gunicorn worker process starvation with 97% confidence. |
| **14:28:45** | Nginx `error.log` confirmed `111: Connection refused` while connecting to upstream `127.0.0.1:8000`. |
| **14:31:00** | Gunicorn master restarted with increased worker concurrency (`-w 4 -k uvicorn.workers.UvicornWorker`). |
| **14:33:15** | Synthetic probe returned HTTP 200 OK; error rate dropped to 0.00%. |
| **14:50:00** | Post-incident monitoring stable; incident resolved. |

---

## 4. Troubleshooting Steps & Technical Observations

### Step 1: Bottom-Up Diagnostic Probe via TriageForge
Running the automated diagnosis engine confirmed:
```bash
$ triageforge diagnose --url http://localhost:80
```
- **Layer 1 (DNS)**: PASS (`localhost` resolved to `127.0.0.1` in 0.4ms).
- **Layer 2 (TCP)**: PASS (Port 80 3-way handshake established in 1.1ms).
- **Layer 3 (TLS)**: SKIPPED (Plain HTTP probe).
- **Layer 4 (HTTP)**: **FAIL** (HTTP 502 Bad Gateway returned by `nginx/1.25.4`, TTFB: 2004.2ms).
- **Layer 5 (Host)**: **FAIL** (Application container process not listening on `0.0.0.0:8000`).

### Step 2: Nginx Upstream Socket Inspection
Inspecting the Nginx reverse proxy error log revealed explicit upstream connection refusals:
```bash
$ tail -n 20 /var/log/nginx/error.log
2024/11-10 14:22:45 [error] 142#142: *1092 connect() failed (111: Connection refused) while connecting to upstream, client: 172.18.0.1, server: localhost, request: "GET /api/items HTTP/1.1", upstream: "http://127.0.0.1:8000/api/items", host: "localhost"
```

### Step 3: Upstream Process & Listening Sockets Verification
Verifying listening sockets on the host:
```bash
$ ss -tulpn | grep 8000
# (No active listeners returned on TCP port 8000)
```
Inspecting the process table confirmed the Gunicorn master had terminated its worker pool after worker timeout thresholds were exceeded under high concurrency:
```bash
$ docker logs triageforge-app --tail 30
[2024-11-10 14:21:55 +0000] [1] [CRITICAL] WORKER TIMEOUT (pid:12)
[2024-11-10 14:21:55 +0000] [12] [INFO] Worker exiting (pid: 12)
[2024-11-10 14:21:56 +0000] [1] [WARNING] Worker with pid 12 was terminated due to signal 9
```

---

## 5. Root Cause Analysis (5 Whys)
1. **Why did clients receive HTTP 502 Bad Gateway?**  
   Nginx received an immediate `ECONNREFUSED` (TCP RST) when attempting to proxy requests to `127.0.0.1:8000`.
2. **Why was nothing listening on port 8000?**  
   All Gunicorn worker processes had exited and were being re-spawned synchronously.
3. **Why did the Gunicorn workers exit?**  
   The master process sent `SIGKILL` to worker PID 12 after it exceeded the 10-second worker heartbeat timeout.
4. **Why did the worker fail its heartbeat?**  
   The single sync worker was blocked waiting on an un-pooled database socket without an async event loop yield.
5. **Why was the deployment configured with insufficient workers?**  
   The default development configuration (`workers = 1`) was mistakenly promoted to the staging/production profile without concurrency tuning.

---

## 6. Resolution & Immediate Corrective Actions
1. **Worker Scaling**: Reconfigured `gunicorn_conf.py` to spawn `(2 * CPU cores) + 1` workers utilizing `uvicorn.workers.UvicornWorker` for non-blocking I/O.
2. **Upstream Keepalive**: Added `keepalive 32;` inside the Nginx `upstream` block to eliminate connection setup churn between Nginx and Gunicorn.
3. **Graceful Failover**: Configured `proxy_next_upstream error timeout invalid_header http_502;` in Nginx to transparently retry idempotent requests on alternate workers.

---

## 7. Prevention & Hardening Runbook
- [x] **Container Health Probe**: Configure Docker Compose / Kubernetes liveness probe pointing to `http://localhost:8000/health` with a 3s timeout and 2 failure thresholds.
- [x] **Synthetic Alarms**: Provision CloudWatch / Prometheus alert for `nginx_upstream_connect_time > 500ms`.
- [x] **Load Testing**: Incorporate a Locust / k6 load test into the CI pipeline asserting zero 502 errors at 500 concurrent connections.
