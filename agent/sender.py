import argparse
import socket
import sys
import time
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Set, Tuple
from collections import deque

import requests
from requests import exceptions as requests_exceptions

# Allow running as a script: `python agent/sender.py`
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.config import (
    API_KEY,
    API_URL,
    BATCH_SIZE,
    COLLECT_LIMIT,
    DEDUPE_CACHE_SIZE,
    FAIL_RETRY_SECONDS,
    POLL_SECONDS,
    REQUEST_TIMEOUT_SECONDS,
)
from backend.collector.windows_logs import get_system_logs
from backend.normalizer.ocsf_mapper import to_ocsf
from backend.parser.windows_parser import parse_windows_event


UNKNOWN_USER = "UNKNOWN_USER"


REQUIRED_FIELDS = {"event_id", "time", "user", "action", "host", "ocsf"}


def _synthetic_raw_logs() -> List[Dict[str, Any]]:
    # Minimal raw log shapes compatible with backend.parser.windows_parser.parse_windows_event
    # Used only for local testing when Windows Security logs cannot be read.
    return [
        {
            "event_id": 4624,
            "source": "Security",
            "time": "2026-04-03T12:00:00",
            "data": [None, None, None, None, None, "alice"],
        },
        {
            "event_id": 4625,
            "source": "Security",
            "time": "2026-04-03T12:01:00",
            "data": [None, None, None, None, None, "alice"],
        },
        {
            "event_id": 4672,
            "source": "Security",
            "time": "2026-04-03T12:02:00",
            "data": [None, "bob"],
        },
        {
            "event_id": 4688,
            "source": "Security",
            "time": "2026-04-03T12:03:00",
            "data": [None, "bob", None, None, None, "powershell.exe -enc AAA"],
        },
    ]


def _chunk(items: List[Dict[str, Any]], chunk_size: int) -> List[List[Dict[str, Any]]]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")
    return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]


def build_payload(raw_log: Dict[str, Any], host: str) -> Dict[str, Any]:
    parsed = parse_windows_event(raw_log)
    ocsf = to_ocsf(parsed)

    user = parsed.get("user")
    if not user or str(user).strip().lower() == "none":
        user = UNKNOWN_USER

    payload: Dict[str, Any] = {
        "event_id": int(parsed.get("event_id")),
        "time": str(parsed.get("time")),
        "user": user,
        "action": parsed.get("action") or "other",
        "host": host,
        "ocsf": ocsf,
    }

    # Optional context used by backend scoring (kept as additional field).
    if parsed.get("process_name"):
        payload["process_name"] = parsed["process_name"]

    return payload


def validate_payload(payload: Dict[str, Any]) -> None:
    missing = REQUIRED_FIELDS.difference(payload.keys())
    if missing:
        raise ValueError(f"Payload missing required fields: {sorted(missing)}")

    if payload.get("user") is None or str(payload.get("user")).strip() == "":
        raise ValueError("Payload user must not be NULL/empty")

    if not isinstance(payload.get("ocsf"), dict):
        raise ValueError("Payload ocsf must be a dict")


def send_logs(logs: List[Dict[str, Any]]) -> None:
    headers = {"x-api-key": API_KEY}

    for batch in _chunk(logs, BATCH_SIZE):
        try:
            resp = requests.post(
                API_URL,
                json={"logs": batch},
                headers=headers,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except requests_exceptions.RequestException as exc:
            raise RuntimeError(
                "Failed to reach cloud ingest API. "
                "Start the cloud server first (python cloud/server.py) and verify "
                f"SIEM_API_URL is correct. Target was: {API_URL}"
            ) from exc
        if resp.status_code != 200:
            raise RuntimeError(f"Ingest failed: {resp.status_code} {resp.text}")


def _event_key(payload: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        str(payload.get("event_id")),
        str(payload.get("time")),
        str(payload.get("user")),
    )


def _dedupe_payloads(
    payloads: List[Dict[str, Any]],
    seen: Set[Tuple[str, str, str]],
    order: Deque[Tuple[str, str, str]],
    max_size: int,
) -> List[Dict[str, Any]]:
    if max_size <= 0:
        return payloads

    unique: List[Dict[str, Any]] = []
    for payload in payloads:
        key = _event_key(payload)
        if key in seen:
            continue
        seen.add(key)
        order.append(key)
        unique.append(payload)

        while len(order) > max_size:
            old = order.popleft()
            seen.discard(old)

    return unique


def main() -> None:
    parser = argparse.ArgumentParser(description="SIEM Agent: collect and send Windows logs")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Collect/parse/normalize and validate payloads, but do not send",
    )
    parser.add_argument(
        "--local-process",
        action="store_true",
        help="Process logs locally by calling cloud processing service directly (no Flask/HTTP)",
    )
    parser.add_argument(
        "--print-sample",
        action="store_true",
        help="Print one sample payload for inspection",
    )
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="Use synthetic Windows logs instead of reading the local Security event log",
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Run continuously: collect and send logs every poll interval",
    )
    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=POLL_SECONDS,
        help="Polling interval for --continuous (default from SIEM_POLL_SECONDS)",
    )
    parser.add_argument(
        "--no-dedupe",
        action="store_true",
        help="Disable in-memory dedupe (may resend same events each cycle)",
    )
    args = parser.parse_args()

    host = socket.gethostname()
    seen: Set[Tuple[str, str, str]] = set()
    order: Deque[Tuple[str, str, str]] = deque()

    def run_once() -> Optional[int]:
        if args.synthetic:
            raw_logs = _synthetic_raw_logs()
        else:
            try:
                raw_logs = get_system_logs(limit=COLLECT_LIMIT)
            except Exception as exc:
                message = str(exc)
                if "A required privilege is not held by the client" in message or "(1314," in message:
                    raise RuntimeError(
                        "Cannot read Windows Security event log (missing privilege). "
                        "Run the terminal as Administrator, or rerun with --synthetic for a local test."
                    ) from exc
                raise

        payloads = [build_payload(raw, host) for raw in raw_logs]
        for payload in payloads:
            validate_payload(payload)

        if not args.no_dedupe:
            payloads = _dedupe_payloads(payloads, seen, order, DEDUPE_CACHE_SIZE)

        if not payloads:
            return 0

        if args.print_sample:
            print("Sample payload:")
            print(payloads[0])

        if args.dry_run:
            print(
                f"Dry run OK: built {len(payloads)} payloads (batch size {BATCH_SIZE}). "
                "No data was sent."
            )
            return len(payloads)

        if args.local_process:
            from cloud.services.processing_service import ensure_logs_table, process_and_store_logs

            ensure_logs_table()
            stored = process_and_store_logs(payloads)
            return stored

        send_logs(payloads)
        return len(payloads)

    if not args.continuous:
        sent = run_once()
        if args.local_process:
            print(f"Local process OK: processed/stored {sent} logs.")
        elif args.dry_run:
            return
        else:
            print(f"Sent {sent} logs to {API_URL} in batches of {BATCH_SIZE}.")
        return

    poll_seconds = max(1, int(args.poll_seconds))
    print(f"Continuous mode: polling every {poll_seconds}s, sending to {API_URL}.")
    while True:
        try:
            sent = run_once()
            if args.local_process:
                print(f"Processed/stored {sent} logs.")
            elif args.dry_run:
                print(f"Dry-run built {sent} payloads.")
            else:
                print(f"Sent {sent} logs.")
            time.sleep(poll_seconds)
        except KeyboardInterrupt:
            print("Stopping.")
            return
        except Exception as exc:
            print(f"[WARN] Cycle failed: {exc}")
            time.sleep(FAIL_RETRY_SECONDS)


if __name__ == "__main__":
    main()
