import os

bind = "0.0.0.0:8000"
workers = 2
worker_class = "uvicorn.workers.UvicornWorker"
timeout = 10
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = "info"
