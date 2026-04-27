
from http.server import SimpleHTTPRequestHandler
import socketserver
import os

PORT = int(os.environ.get("PORT", 10000))

Handler = SimpleHTTPRequestHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()
