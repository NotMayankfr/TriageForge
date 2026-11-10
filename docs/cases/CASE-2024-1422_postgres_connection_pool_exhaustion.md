# Support Case Report: CASE-2024-1422
**Severity Level**: SEV-1 (Database Saturation / Cascading Application Failure)  
**Assigned Engineer**: Cloud Support Engineer II (Databases & Linux Systems)  
**Component**: Relational Database Tier (`PostgreSQL` / `FastAPI SQLAlchemy Pool`)  
**Status**: Resolved / Permanent Safeguards Applied  

---

## 1. Case Summary
At 18:05 UTC, all application endpoints querying the relational database tier began returning HTTP 500 Internal Server Errors. Microservice error logs displayed `psycopg2.OperationalError: FATAL: too many clients already`. Direct queries through the web application failed, while administrative access via `psql` required superuser connection reservations. The issue was triggered by connection leak behavior under background task execution.

---

## 2. Customer Impact
- **Affected Services**: Loan underwriting verification, user account history, billing lookup.
- **Transactions Lost**: 418 failed user transactions over an 11-minute incident window.
- **SLA Breach**: API availability dropped to 4.2% during the incident peak.

---

## 3. Incident Timeline
| Time (UTC) | Event |
|:---|:---|
| **18:01:00** | Nightly reconciliation batch job kicked off 50 concurrent worker threads. |
| **18:04:30** | Database active connections surged from nominal 4 to maximum limit (20). |
| **18:05:12** | API endpoints began throwing HTTP 500: `FATAL: too many clients already`. |
| **18:06:00** | PagerDuty alerted on DB Connection Pool Utilization > 95%. |
| **18:07:20** | On-call engineer executed `triageforge diagnose --url http://localhost:80/api/items`. |
| **18:08:15** | TriageForge flagged PostgreSQL connection pool exhaustion (98% match), identifying saturated `max_connections` and suggesting `pg_stat_activity` analysis. |
| **18:10:00** | On-call ran `pg_terminate_backend` on idle-in-transaction worker sessions. |
| **18:12:30** | Active connection count dropped to 3; application resumed serving traffic at 100% success rate. |
| **18:30:00** | Code patch deployed fixing unclosed DB sessions in background tasks. |

---

## 4. Troubleshooting Steps & Technical Observations

### Step 1: Bottom-Up Diagnostic Probe via TriageForge
Running the automated diagnostic engine against the failing endpoint:
```bash
$ triageforge diagnose --url http://localhost:80/api/items
```
- **Layer 1 (DNS)**: PASS (`localhost` -> `127.0.0.1` in 0.3ms).
- **Layer 2 (TCP)**: PASS (Port 80 connected in 1.2ms).
- **Layer 4 (HTTP)**: **FAIL** (HTTP 500 Internal Server Error).
  - *Response Body Signature*: `OperationalError: FATAL: too many clients already`.
- **Layer 5 (Host / Database)**: **FAIL** (`pg_stat_activity` reported `20/20` active sessions).
  - *Identified Root Cause*: `04_pg_connections` (PostgreSQL Connection Exhaustion, 98% Confidence).
  - *Next Best Diagnostic Command*:
    ```sql
    SELECT pid, usename, client_addr, state, age(clock_timestamp(), query_start), query 
    FROM pg_stat_activity WHERE state != 'idle';
    ```

### Step 2: Database Activity & Session Inspection
Connecting as superuser to inspect the PostgreSQL process activity table:
```bash
$ docker exec triageforge-db psql -U forge_user -d triageforge -c "
SELECT pid, usename, state, age(clock_timestamp(), state_change) as idle_age, query 
FROM pg_stat_activity 
ORDER BY query_start ASC;"
```
Output:
```
  pid  |   usename    |        state        |    idle_age     |                    query                     
-------+--------------+---------------------+-----------------+----------------------------------------------
   182 | forge_user   | idle in transaction | 00:08:12.418291 | SELECT * FROM items WHERE status = 'active';
   183 | forge_user   | idle in transaction | 00:08:11.891204 | SELECT * FROM items WHERE status = 'active';
   184 | forge_user   | idle in transaction | 00:08:10.129481 | SELECT * FROM items WHERE status = 'active';
   ... (16 additional sessions in 'idle in transaction')
(20 rows)
```
Analysis: 18 out of 20 connection slots were frozen in the `idle in transaction` state for over 8 minutes.

### Step 3: Application Code Stack Trace Review
Reviewing application worker logs for `triageforge-app`:
```bash
$ docker logs triageforge-app | grep -C 5 "OperationalError"
Traceback (most recent call last):
  File "/app/main.py", line 45, in get_items
    conn = get_db_connection()
  File "/usr/local/lib/python3.11/site-packages/psycopg2/__init__.py", line 122, in connect
    return _connect(dsn, connection_factory=connection_factory, **kwasync)
psycopg2.OperationalError: FATAL: too many clients already
```
Tracing the batch worker code revealed an unclosed connection bug in an exception handler:
```python
# The defective code snippet:
def reconcile_records():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("BEGIN;")
    cur.execute("SELECT * FROM items WHERE status = 'active';")
    # Exception occurred here during external HTTP call, omitting cur.close() and conn.close()!
```

---

## 5. Root Cause Analysis (5 Whys)
1. **Why did API calls return HTTP 500?**  
   The application could not establish new database connections to fulfill user queries.
2. **Why was PostgreSQL rejecting connections?**  
   All 20 available connection slots (`max_connections`) were occupied.
3. **Why were all 20 connection slots occupied?**  
   18 sessions were orphaned in the `idle in transaction` state by background worker threads.
4. **Why did the worker threads orphan the connections?**  
   An unhandled exception during a third-party HTTP call exited the thread before calling `conn.commit()` or `conn.close()`.
5. **Why was there no automated connection pool reclamation?**  
   The database server lacked an `idle_in_transaction_session_timeout` safeguard, allowing abandoned transactions to hold backend slots indefinitely.

---

## 6. Resolution & Immediate Corrective Actions
1. **Emergency Session Termination**: Executed `pg_terminate_backend` on all leaked worker PIDs:
   ```sql
   SELECT pg_terminate_backend(pid) 
   FROM pg_stat_activity 
   WHERE state = 'idle in transaction' 
     AND pid != pg_backend_pid();
   ```
2. **Python Code Fix**: Wrapped all database acquisitions in Python context managers (`with get_db_connection() as conn:`) ensuring guaranteed cleanup even on uncaught exceptions.
3. **Server Session Timeout**: Configured PostgreSQL runtime parameter:
   ```sql
   ALTER SYSTEM SET idle_in_transaction_session_timeout = '30s';
   SELECT pg_reload_conf();
   ```

---

## 7. Prevention & Hardening Runbook
- [x] **Connection Pooler (PgBouncer)**: Deploy PgBouncer in transaction-pooling mode in front of PostgreSQL to multiplex thousands of client connections into a controlled backend pool.
- [x] **Statement Timeouts**: Enforce `statement_timeout = '15s'` to prevent rogue queries from holding database locks.
- [x] **CloudWatch / Prometheus Alerts**: Provision an alert when `DatabaseConnections / max_connections > 0.80` for 3 consecutive data points.
