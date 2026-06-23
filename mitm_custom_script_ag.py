import json
import os
import time
from mitmproxy import http

# Usage
# pip install -r mitmproxy
# mitmproxy --listen-port 9453 -s mitm_custom_script_ag.py
#
# Then start OpenCode pointing at the mitmproxy
# Note: You need to add the CA cert otherwise it'll fail (Google it):
#
# NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem \
# HTTPS_PROXY=http://localhost:9453 \
# HTTP_PROXY=http://localhost:9453 \
# opencode

counter = 0

def request(flow: http.HTTPFlow):
    global counter
    try:
        body = json.loads(flow.request.get_text())
        messages = body.get("messages", [])
        for msg in messages:
            if msg.get("role") == "system":
                flow.marked = True
                os.makedirs("flows", exist_ok=True)
                counter += 1
                filename = f"flows/{flow.request.host}_{int(time.time())}_{counter}.json"
                flow.metadata["saved_filename"] = filename
                with open(filename, "w") as f:
                    json.dump({"request": body}, f, indent=2)
                break
    except (json.JSONDecodeError, AttributeError):
        pass

def response(flow: http.HTTPFlow):
    filename = flow.metadata.get("saved_filename")
    if filename and flow.response:
        try:
            with open(filename, "r") as f:
                data = json.load(f)
            data["response"] = {
                "status_code": flow.response.status_code,
                "headers": dict(flow.response.headers),
                "body": flow.response.get_text(),
            }
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass
