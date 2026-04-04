from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from stem.control import Controller

HOST = "127.0.0.1"
LOCAL_PORT = 8787
CONTROL_PORT = 9151
OUT_FILE = Path(__file__).resolve().parent / "onion_test_url.txt"


class ChatLikeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = """<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <title>DarkIntel Proof Chat</title>
  <style>
    body { font-family: Arial, sans-serif; background:#0b1020; color:#d9e6ff; margin:0; padding:24px; }
    .box { max-width: 760px; margin: 0 auto; border:1px solid #2b3a66; border-radius:12px; padding:20px; background:#121a33; }
    h1 { margin-top:0; color:#77e6ff; }
    .msg { border-left:3px solid #77e6ff; padding-left:12px; margin:10px 0; }
    code { color:#9bf8ff; }
  </style>
</head>
<body>
  <div class=\"box\">
    <h1>DarkIntel Onion Proof Room</h1>
    <p>This is a safe local onion proof endpoint for hackathon validation.</p>
    <div class=\"msg\">[user_alpha] selling fresh logs from Acme Corp, contact admin@acme.com</div>
    <div class=\"msg\">[user_beta] breach dump includes domain acme-corp.com and ip 203.0.113.10</div>
    <div class=\"msg\">[user_gamma] wallet for payment: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e</div>
    <p>Use this URL in your crawler and search company <code>Acme</code> in Company Lookup.</p>
  </div>
</body>
</html>
"""
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        return


def main() -> int:
    httpd = ThreadingHTTPServer((HOST, LOCAL_PORT), ChatLikeHandler)

    try:
        controller = Controller.from_port(port=CONTROL_PORT)
        controller.authenticate()
    except Exception as exc:
        print(f"ERROR: Tor control port {CONTROL_PORT} unavailable: {exc}")
        return 1

    hs = controller.create_ephemeral_hidden_service(
        {80: LOCAL_PORT},
        await_publication=True,
    )
    onion_url = f"http://{hs.service_id}.onion"

    OUT_FILE.write_text(onion_url + "\n", encoding="utf-8")
    print(f"ONION_URL={onion_url}")
    print("STATUS=running")
    sys.stdout.flush()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            controller.remove_ephemeral_hidden_service(hs.service_id)
        except Exception:
            pass
        try:
            controller.close()
        except Exception:
            pass
        httpd.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
