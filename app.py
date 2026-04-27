import os
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer

PORT = int(os.environ.get("PORT", 10000))

class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # default file serve (index.html)
        if self.path == "/":
            self.path = "/index.html"
        return super().do_GET()

# Render friendly server
with TCPServer(("0.0.0.0", PORT), Handler) as httpd:
    print(f"Serving on port {PORT}")
    httpd.serve_forever()
