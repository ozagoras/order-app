# gunicorn.conf.py
# Gunicorn configuration for the NFC Beach Bar Flask app

import os

# Address and port
bind = f"0.0.0.0:{os.environ.get('PORT', '5000')}"

# Number of worker processes
# Rule of thumb: (2 x CPU cores) + 1
workers = 3

# Worker type — sync is fine for this app
worker_class = "sync"

# Timeout in seconds — how long a worker can take to handle a request
timeout = 30

# Restart workers after this many requests (prevents memory leaks)
max_requests = 1000
max_requests_jitter = 100

# Logging
accesslog = "-"   # stdout
errorlog  = "-"   # stdout
loglevel  = "info"