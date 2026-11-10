FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    iproute2 \
    curl \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gunicorn_conf.py .
COPY main.py .

RUN mkdir -p /var/log/app

EXPOSE 8000

CMD ["gunicorn", "-c", "gunicorn_conf.py", "main:app"]
