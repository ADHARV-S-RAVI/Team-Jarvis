"""Streaming verification algorithms for GB-scale Data Verification Lab.

All file processing uses bounded-memory streaming so multi-gigabyte files
never load completely into RAM.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import random
import re
import tarfile
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

STREAM_BUFFER_BYTES = 1024 * 1024  # 1 MiB constant streaming buffer
MAX_ARCHIVE_ENTRIES = 5000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_DEDUP_HASHES = 50_000
RESERVOIR_SAMPLE_SIZE = 25


def streaming_sha256(file_path: Path, chunk_bytes: int = STREAM_BUFFER_BYTES) -> str:
    """Compute SHA-256 incrementally without loading the file into RAM."""
    h = hashlib.sha256()
    with file_path.open("rb") as fh:
        while True:
            buf = fh.read(chunk_bytes)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def compute_merkle_root(leaf_hashes: list[str]) -> str | None:
    """Compute binary SHA-256 Merkle root; duplicates last node on odd levels."""
    if not leaf_hashes:
        return None
    level = [bytes.fromhex(h) for h in leaf_hashes]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            next_level.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        level = next_level
    return level[0].hex()


def detect_content_type(file_path: Path, filename: str) -> tuple[str, str]:
    """Detect MIME and logical category using magic bytes and safe header inspection."""
    with file_path.open("rb") as fh:
        head = fh.read(4096)

    if head.startswith(b"%PDF-"):
        return "application/pdf", "pdf"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "application/zip", "archive"
    if head.startswith(b"\x1f\x8b\x08"):
        return "application/gzip", "archive"
    if len(head) > 262 and head[257:262] == b"ustar":
        return "application/x-tar", "archive"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", "image"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", "image"
    if b"-----BEGIN CERTIFICATE-----" in head:
        return "application/x-pem-file", "certificate"
    if b"-----BEGIN PUBLIC KEY-----" in head or b"-----BEGIN PRIVATE KEY-----" in head:
        return "application/pkcs8", "crypto_artifact"

    # Text / structured format heuristics
    try:
        sample = head.decode("utf-8")
    except UnicodeDecodeError:
        return "application/octet-stream", "binary"

    stripped = sample.lstrip()
    ext = Path(filename).suffix.lower()
    if stripped.startswith("{") or stripped.startswith("["):
        lines = [ln.strip() for ln in stripped.splitlines() if ln.strip()]
        if len(lines) > 1 and all(ln.startswith("{") and ln.endswith("}") for ln in lines[:5]):
            return "application/x-ndjson", "jsonl"
        return "application/json", "json"
    if ext == ".csv" or ("," in sample and "\n" in sample and not re.search(r"\b(ERROR|WARN|INFO)\b", sample)):
        return "text/csv", "csv"
    if ext == ".log" or re.search(r"\b(ERROR|WARN|WARNING|INFO|CRITICAL|DENY|ALLOW)\b", sample):
        return "text/x-log", "log"
    return "text/plain", "text"


def inspect_archive_safely(file_path: Path, mime: str) -> dict[str, object]:
    """Inspect ZIP/TAR metadata safely without extracting untrusted payloads."""
    findings: list[dict[str, str]] = []
    entries = 0
    total_uncompressed = 0
    traversal_hits: list[str] = []

    if mime == "application/zip":
        with zipfile.ZipFile(file_path, "r") as zf:
            for info in zf.infolist():
                entries += 1
                total_uncompressed += info.file_size
                if info.filename.startswith("/") or ".." in Path(info.filename).parts:
                    traversal_hits.append(info.filename)
                if entries > MAX_ARCHIVE_ENTRIES:
                    findings.append({"severity": "HIGH", "code": "ARCHIVE_ENTRY_LIMIT", "message": "Exceeded max archive entry inspection limit"})
                    break
                if total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                    findings.append({"severity": "HIGH", "code": "ARCHIVE_BOMB_RISK", "message": "Uncompressed size exceeds 2 GiB safety limit"})
                    break
    elif mime in ("application/x-tar", "application/gzip"):
        mode = "r:gz" if mime == "application/gzip" else "r:*"
        with tarfile.open(file_path, mode) as tf:
            for member in tf:
                entries += 1
                total_uncompressed += member.size
                if member.name.startswith("/") or ".." in Path(member.name).parts:
                    traversal_hits.append(member.name)
                if entries > MAX_ARCHIVE_ENTRIES:
                    findings.append({"severity": "HIGH", "code": "ARCHIVE_ENTRY_LIMIT", "message": "Exceeded max archive entry inspection limit"})
                    break

    if traversal_hits:
        findings.append({
            "severity": "CRITICAL",
            "code": "PATH_TRAVERSAL_ENTRY",
            "message": f"Archive contains unsafe path traversal entries: {traversal_hits[:3]}",
        })

    return {
        "entries_inspected": entries,
        "total_uncompressed_bytes": total_uncompressed,
        "traversal_hits": len(traversal_hits),
        "findings": findings,
    }


def analyze_crypto_and_cert(file_path: Path, category: str) -> tuple[str, str, list[dict[str, str]]]:
    """Inspect PEM certificates or crypto artifacts; classify quantum readiness honestly."""
    findings: list[dict[str, str]] = []
    if category == "certificate":
        raw = file_path.read_bytes()
        try:
            cert = x509.load_pem_x509_certificate(raw)
            pub = cert.public_key()
            now = datetime.now(timezone.utc)
            expired = cert.not_valid_after_utc < now
            not_yet = cert.not_valid_before_utc > now
            if isinstance(pub, rsa.RSAPublicKey):
                alg = f"RSA-{pub.key_size}"
                readiness = "Classical cryptography detected"
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                alg = f"ECDSA-{pub.curve.name}"
                readiness = "Classical cryptography detected"
            elif isinstance(pub, ed25519.Ed25519PublicKey):
                alg = "Ed25519"
                readiness = "Classical cryptography detected"
            else:
                alg = type(pub).__name__
                readiness = "Unknown"

            sig_status = "EXPIRED" if expired else "NOT_YET_VALID" if not_yet else "PARSED_VALID_DATES_UNTRUSTED_ROOT"
            if expired:
                findings.append({"severity": "HIGH", "code": "CERT_EXPIRED", "message": f"Certificate ({alg}) expired on {cert.not_valid_after_utc.isoformat()}"})
            findings.append({
                "severity": "INFO",
                "code": "TRUST_ANCHOR_NOTE",
                "message": f"Parsed {alg} subject={cert.subject.rfc4514_string()} (no external CA trust store verified).",
            })
            return sig_status, readiness, findings
        except Exception as exc:
            findings.append({"severity": "MEDIUM", "code": "CERT_PARSE_ERROR", "message": f"Failed to parse X.509 PEM: {type(exc).__name__}"})
            return "PARSE_FAILED", "Requires investigation", findings

    if category == "crypto_artifact":
        findings.append({
            "severity": "HIGH",
            "code": "KEY_MATERIAL_UPLOAD",
            "message": "PEM key header detected in uploaded artifact; verify no private keys are exposed.",
        })
        return "NONE", "Classical cryptography detected", findings

    return "NONE", "Not applicable", findings


def analyze_dataset_streaming(file_path: Path, category: str) -> dict[str, object]:
    """Stream CSV or JSONL line-by-line using Welford's algorithm & reservoir sampling."""
    rng = random.Random(42)
    row_count = 0
    missing_cells = 0
    malformed_rows = 0
    duplicate_rows = 0
    seen_hashes: set[str] = set()
    reservoir: list[dict[str, object]] = []
    columns: list[str] = []

    # Welford accumulators per numeric column
    num_count: dict[str, int] = {}
    num_mean: dict[str, float] = {}
    num_m2: dict[str, float] = {}
    num_min: dict[str, float] = {}
    num_max: dict[str, float] = {}

    def _update_row(row: dict[str, object]) -> None:
        nonlocal row_count, missing_cells, duplicate_rows
        row_count += 1
        canonical = json.dumps(row, sort_keys=True, default=str).encode("utf-8")
        rh = hashlib.sha256(canonical).hexdigest()[:16]
        if rh in seen_hashes:
            duplicate_rows += 1
        elif len(seen_hashes) < MAX_DEDUP_HASHES:
            seen_hashes.add(rh)

        if len(reservoir) < RESERVOIR_SAMPLE_SIZE:
            reservoir.append(row)
        else:
            j = rng.randint(0, row_count - 1)
            if j < RESERVOIR_SAMPLE_SIZE:
                reservoir[j] = row

        for col, val in row.items():
            if val is None or str(val).strip() == "":
                missing_cells += 1
                continue
            try:
                fval = float(val)
                if math.isfinite(fval):
                    c = num_count.get(col, 0) + 1
                    mean = num_mean.get(col, 0.0)
                    delta = fval - mean
                    mean += delta / c
                    delta2 = fval - mean
                    num_count[col] = c
                    num_mean[col] = mean
                    num_m2[col] = num_m2.get(col, 0.0) + delta * delta2
                    num_min[col] = min(num_min.get(col, fval), fval)
                    num_max[col] = max(num_max.get(col, fval), fval)
            except (ValueError, TypeError):
                pass

    if category == "csv":
        with file_path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            columns = list(reader.fieldnames or [])
            for row in reader:
                _update_row(dict(row))
    elif category == "jsonl":
        with file_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if not s:
                    continue
                try:
                    obj = json.loads(s)
                    if isinstance(obj, dict):
                        if not columns:
                            columns = list(obj.keys())
                        _update_row(obj)
                    else:
                        malformed_rows += 1
                except json.JSONDecodeError:
                    malformed_rows += 1
    elif category == "json":
        if file_path.stat().st_size <= 25 * 1024 * 1024:
            try:
                parsed = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
                if isinstance(parsed, list):
                    for item in parsed[:100_000]:
                        if isinstance(item, dict):
                            if not columns:
                                columns = list(item.keys())
                            _update_row(item)
                elif isinstance(parsed, dict):
                    columns = list(parsed.keys())
                    _update_row(parsed)
            except json.JSONDecodeError:
                malformed_rows += 1

    numeric_stats = {
        col: {
            "count": num_count[col],
            "mean": round(num_mean[col], 4),
            "stddev": round(math.sqrt(num_m2[col] / max(1, num_count[col] - 1)), 4) if num_count[col] > 1 else 0.0,
            "min": num_min[col],
            "max": num_max[col],
        }
        for col in num_count
    }

    total_cells = max(1, row_count * max(1, len(columns)))
    quality_score = round(max(0.0, 100.0 - (missing_cells / total_cells) * 40.0 - (malformed_rows / max(1, row_count)) * 50.0), 2)

    return {
        "row_count": row_count,
        "columns": columns,
        "missing_cells": missing_cells,
        "duplicate_rows": duplicate_rows,
        "malformed_rows": malformed_rows,
        "dedup_memory_capped": len(seen_hashes) >= MAX_DEDUP_HASHES,
        "numeric_stats": numeric_stats,
        "quality_score": quality_score,
        "preview_sample": reservoir[:10],
    }


def analyze_log_streaming(file_path: Path) -> dict[str, object]:
    """Stream log file line-by-line extracting severity counts and failure bursts."""
    total_lines = 0
    malformed = 0
    sev_counts = {"CRITICAL": 0, "ERROR": 0, "WARN": 0, "INFO": 0, "DENY": 0}
    sample_errors: list[str] = []
    ts_pattern = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")

    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.strip()
            if not s:
                continue
            total_lines += 1
            if not ts_pattern.search(s):
                malformed += 1
            upper = s.upper()
            for sev in sev_counts:
                if sev in upper:
                    sev_counts[sev] += 1
                    if sev in ("CRITICAL", "ERROR", "DENY") and len(sample_errors) < 10:
                        sample_errors.append(s[:220])
                    break

    coverage = round(((total_lines - malformed) / max(1, total_lines)) * 100.0, 2)
    return {
        "total_lines": total_lines,
        "malformed_lines": malformed,
        "timestamp_coverage_pct": coverage,
        "severity_counts": sev_counts,
        "sample_errors": sample_errors,
    }
