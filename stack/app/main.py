import os
import sys
import time
import requests
import psycopg2
from psycopg2 import pool
from fastapi import FastAPI, HTTPException, Response

app = FastAPI(title="TriageForge Core API", version="1.0.0")

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://forge_user:forge_password@db:5432/triageforge")
MOCK_S3_ENDPOINT = os.getenv("MOCK_S3_ENDPOINT", "http://mock-s3:9000")
S3_BUCKET = os.getenv("S3_BUCKET", "triageforge-assets")

# Global memory leak accumulator
_memory_leak_sink = []

# Optional DB connection pool
db_pool = None

def get_db_connection():
    return psycopg2.connect(DATABASE_URL, connect_timeout=3)

@app.on_event("startup")
def startup_event():
    print("[APP] TriageForge Core API initialized.", flush=True)

@app.get("/")
def read_root():
    return {
        "service": "TriageForge API",
        "status": "online",
        "timestamp": time.time(),
        "architecture": "Nginx -> Gunicorn (FastAPI) -> PostgreSQL",
    }

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "triageforge-app"}

@app.get("/api/items")
def get_items():
    """Queries Postgres database table."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, category, status FROM items LIMIT 10;")
            rows = cur.fetchall()
            items = [{"id": r[0], "name": r[1], "category": r[2], "status": r[3]} for r in rows]
        conn.close()
        return {"items": items, "count": len(items)}
    except psycopg2.OperationalError as e:
        err_msg = str(e)
        print(f"[DB ERROR] {err_msg}", flush=True)
        # Returns raw postgres message for triage inspection
        raise HTTPException(status_code=500, detail=f"Database connection error: {err_msg}")

@app.get("/api/db-check")
def db_check():
    """Validates PostgreSQL connectivity."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
        conn.close()
        return {"database": "connected", "status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database healthcheck failed: {e}")

@app.get("/api/s3-check")
def s3_check():
    """Simulates S3 access via mock storage."""
    try:
        url = f"{MOCK_S3_ENDPOINT}/{S3_BUCKET}/app-config.json"
        res = requests.get(url, timeout=3.0)
        if res.status_code == 403:
            return Response(content=res.text, status_code=403, media_type="application/xml")
        return {"status": "ok", "s3_response": res.json()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to communicate with storage service: {e}")

@app.post("/api/leak-memory")
def leak_memory(mb: int = 100):
    """Allocates specified MB into global heap to simulate runaway memory leak / OOM."""
    chunk = bytearray(mb * 1024 * 1024)
    _memory_leak_sink.append(chunk)
    total_leaked = len(_memory_leak_sink) * mb
    return {"message": f"Allocated {mb}MB into memory sink.", "total_leaked_mb": total_leaked}

@app.get("/api/disk-check")
def disk_check():
    """Checks local disk space."""
    import shutil
    usage = shutil.disk_usage("/")
    free_mb = usage.free / (1024 * 1024)
    if free_mb < 50:
        raise HTTPException(status_code=500, detail="No space left on device: /var/log/app partition exhausted.")
    return {"status": "ok", "free_mb": round(free_mb, 2)}
