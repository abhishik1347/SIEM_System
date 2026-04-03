import os
import sys
from pathlib import Path

# Allow running as a script: `python cloud/server.py`
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask

from cloud.api.ingest import ingest_bp
from cloud.services.processing_service import ensure_logs_table


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = int(
        os.getenv("SIEM_MAX_CONTENT_LENGTH", str(2 * 1024 * 1024))
    )
    app.register_blueprint(ingest_bp)

    # Ensure the DB table exists before ingest.
    # For local testing we don't want to prevent the API from starting
    # if MySQL is temporarily down/misconfigured.
    try:
        ensure_logs_table()
    except Exception as exc:
        print(f"[WARN] Could not initialize DB table: {exc}")
    return app


if __name__ == "__main__":
    app = create_app()
    host = os.getenv("SIEM_SERVER_HOST", "0.0.0.0")
    port = int(os.getenv("SIEM_SERVER_PORT", "5000"))
    debug = os.getenv("SIEM_FLASK_DEBUG", "0").strip() in {"1", "true", "True"}
    app.run(host=host, port=port, debug=debug)
