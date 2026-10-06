"""
dashboard/app.py
-----------------
Local-only Flask dashboard for the CodeAlpha IDS project.

Binds to 127.0.0.1 by default — NOT exposed to the network. All database
access goes through scripts/database.py, which uses parameterized queries.
"""

import os
import sys

from flask import Flask, jsonify, render_template, request

# Allow importing scripts/database.py from the dashboard directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import database  # noqa: E402

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/summary")
def api_summary():
    return jsonify(database.get_summary_counts())


@app.route("/api/timeline")
def api_timeline():
    hours = request.args.get("hours", default=24, type=int)
    return jsonify(database.get_alerts_over_time(limit_hours=hours))


@app.route("/api/top-sources")
def api_top_sources():
    limit = request.args.get("limit", default=5, type=int)
    return jsonify(database.get_top_source_ips(limit=limit))


@app.route("/api/top-ports")
def api_top_ports():
    limit = request.args.get("limit", default=5, type=int)
    return jsonify(database.get_top_dest_ports(limit=limit))


@app.route("/api/top-signatures")
def api_top_signatures():
    limit = request.args.get("limit", default=5, type=int)
    return jsonify(database.get_top_signatures(limit=limit))


@app.route("/api/alerts")
def api_alerts():
    limit = request.args.get("limit", default=100, type=int)
    search = request.args.get("search", default=None, type=str)
    severity = request.args.get("severity", default=None, type=int)
    return jsonify(database.get_recent_alerts(limit=limit, search=search, severity=severity))


if __name__ == "__main__":
    database.init_db()
    # host="127.0.0.1" -> local machine only, never exposed on the network.
    app.run(host="127.0.0.1", port=5000, debug=False)
