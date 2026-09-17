"""Run the audit middleware demo locally using Python's built-in WSGI server."""
import sys
import os

# ensure repo root is on the path so 'auditmiddleware' is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wsgiref.simple_server import make_server
from demo_app import app

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8282
print(f"Listening on http://127.0.0.1:{port}")
print("CADF events will appear below as JSON lines.\n")
with make_server('127.0.0.1', port, app) as httpd:
    httpd.serve_forever()
