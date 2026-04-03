from __future__ import annotations

from typing import Any, Dict, List

from flask import Blueprint, jsonify, request

from cloud.services.processing_service import process_and_store_logs


ingest_bp = Blueprint("ingest", __name__)


VALID_API_KEYS = ["agent123"]
MAX_LOGS_PER_REQUEST = 50


@ingest_bp.post("/ingest")
def ingest():
    api_key = request.headers.get("x-api-key")
    if api_key not in VALID_API_KEYS:
        return jsonify({"error": "unauthorized"}), 401

    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"error": "invalid_json"}), 400

    logs: List[Dict[str, Any]]
    if isinstance(body, list):
        logs = body
    else:
        logs = body.get("logs") if isinstance(body, dict) else None

    if not isinstance(logs, list):
        return jsonify({"error": "missing_logs"}), 400

    if len(logs) > MAX_LOGS_PER_REQUEST:
        return (
            jsonify({"error": "batch_too_large", "max": MAX_LOGS_PER_REQUEST}),
            400,
        )

    if not all(isinstance(item, dict) for item in logs):
        return jsonify({"error": "invalid_log_item"}), 400

    try:
        stored = process_and_store_logs(logs)
    except Exception:
        return jsonify({"error": "processing_failed"}), 503

    return jsonify({"status": "ok", "received": len(logs), "stored": stored})
