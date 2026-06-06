"""Flask application factory for the Wyvern dashboard."""

from __future__ import annotations

import logging

from flask import Flask, render_template

from .api import api

log = logging.getLogger("wyvern.web")


def create_app(monitor) -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config["MONITOR"] = monitor
    app.config["JSON_SORT_KEYS"] = False

    # Restrict CORS to the dashboard's own origin rather than "*", so a remote
    # page can't drive the (localhost) API even if the host is later exposed.
    port = getattr(monitor.config, "web_port", 8787)
    origins = [
        f"http://127.0.0.1:{port}",
        f"http://localhost:{port}",
        f"http://{getattr(monitor.config, 'web_host', '127.0.0.1')}:{port}",
    ]
    try:
        from flask_cors import CORS

        CORS(app, resources={r"/api/*": {"origins": origins}})
    except ImportError:  # pragma: no cover - optional dependency
        log.debug("flask-cors not installed; CORS disabled")

    app.register_blueprint(api)

    @app.after_request
    def _security_headers(response):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/healthz")
    def healthz():
        return {"status": "ok", "devices": len(monitor.registry)}

    return app


def run_dashboard(monitor, host: str = "127.0.0.1", port: int = 8787) -> None:
    """Serve the dashboard with Werkzeug's threaded dev server (fine for a
    single-operator, localhost home monitor). For any multi-user/exposed
    deployment, front ``create_app(monitor)`` with gunicorn/uvicorn instead."""
    app = create_app(monitor)
    log.info("dashboard on http://%s:%d", host, port)
    app.run(host=host, port=port, threaded=True, debug=False, use_reloader=False)
