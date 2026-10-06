"""
test_server.py
----------------
A tiny, harmless local Flask server used ONLY to give generate_test_traffic.py
something to connect to on port 8080, so the HTTP, login-test, and
proof-of-life-signature Suricata rules have a real connection to inspect.

This server does nothing sensitive: it accepts any request on the two test
paths and returns a simple response. It is not meant to be secure or
production-like — it exists purely so test connections complete instead of
being refused.

Usage:
    python3 scripts/test_server.py
Then, in another terminal:
    python3 scripts/generate_test_traffic.py --all
"""

from flask import Flask, request

app = Flask(__name__)


@app.route("/codealpha-test-suspicious", methods=["GET"])
def suspicious():
    return "test endpoint reached\n", 200


@app.route("/codealpha-test-login", methods=["POST"])
def login_test():
    # Intentionally does NOT check the fake credentials against anything real -
    # this endpoint exists purely to receive the test POST requests so the
    # Suricata login-attempt rule has real traffic to match against.
    return "login test received (not a real auth system)\n", 401


@app.route("/", methods=["GET"])
def index():
    return "CodeAlpha IDS test server is running.\n", 200


if __name__ == "__main__":
    print("[INFO] Starting local test server on 127.0.0.1:8080 (for IDS testing only)")
    app.run(host="127.0.0.1", port=8080, debug=False)
