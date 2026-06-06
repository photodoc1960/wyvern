"""JSON + SSE API blueprint backed by a :class:`Monitor`.

All endpoints are read-only except ``POST /api/devices/<id>/suspicious``, which
is the single user-initiated write the brief allows: flagging a device for
deeper monitoring. Nothing here changes the network or any device.
"""

from __future__ import annotations

import json
import queue
import time

from flask import Blueprint, Response, current_app, jsonify, request

api = Blueprint("api", __name__)


def _monitor():
    return current_app.config["MONITOR"]


@api.get("/api/stats")
def stats():
    return jsonify(_monitor().stats())


@api.get("/api/devices")
def devices():
    return jsonify(_monitor().devices())


@api.get("/api/alerts")
def alerts():
    limit = request.args.get("limit", default=200, type=int)
    limit = max(1, min(limit, 1000))     # clamp to avoid a huge single response
    return jsonify(_monitor().recent_alerts(limit=limit))


@api.get("/api/topology")
def topology():
    return jsonify(_monitor().topology())


@api.get("/api/assessment")
def assessment():
    return jsonify(_monitor().current_assessment().to_dict())


@api.post("/api/devices/<path:identifier>/suspicious")
def set_suspicious(identifier: str):
    body = request.get_json(silent=True) or {}
    value = bool(body.get("value", True))
    ok = _monitor().mark_suspicious(identifier, value)
    if not ok:
        return jsonify({"ok": False, "error": "device not found"}), 404
    return jsonify({"ok": True, "identifier": identifier, "suspicious": value})


@api.get("/api/export")
def export():
    fmt = request.args.get("format", default="json")
    mon = _monitor()
    alerts_data = mon.db.all_alerts()
    if fmt == "csv":
        from ..storage.export import _CSV_FIELDS  # reuse field order
        import csv
        import io

        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in alerts_data:
            writer.writerow({k: row.get(k, "") for k in _CSV_FIELDS})
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=wyvern-alerts.csv"},
        )
    bundle = {
        "tool": "wyvern",
        "generated_at": time.time(),
        "assessment": mon.current_assessment().to_dict(),
        "devices": mon.db.all_devices() or [d for d in mon.devices()],
        "alerts": alerts_data,
    }
    return Response(
        json.dumps(bundle, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=wyvern-forensics.json"},
    )


@api.get("/api/stream")
def stream():
    """Server-Sent-Events stream of live alerts, assessments and device updates."""
    mon = _monitor()
    bus = mon.bus
    try:
        q = bus.subscribe()
    except RuntimeError:
        return Response("Too many dashboard listeners", status=503)

    def gen():
        # Prime the client with the current assessment so the UI isn't blank.
        try:
            initial = {"type": "assessment", "assessment": mon.current_assessment().to_dict()}
            yield f"data: {json.dumps(initial)}\n\n"
            while True:
                try:
                    message = q.get(timeout=15)
                    yield f"data: {json.dumps(message)}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            bus.unsubscribe(q)

    return Response(
        gen(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
