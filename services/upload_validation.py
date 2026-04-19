"""Validate uploaded file bytes: extension allowlist, content/MIME checks, optional ClamAV."""

import json
import os
import shutil
import subprocess
import tempfile
from typing import BinaryIO, FrozenSet, Optional, Tuple

import filetype


class MalwareDetectedError(ValueError):
    """Raised when ClamAV reports an infection (do not expose raw scanner output to users)."""

_ALLOWED_EXTENSIONS: FrozenSet[str] = frozenset(
    {".txt", ".md", ".csv", ".log", ".json", ".pdf"}
)

_TEXT_LIKE = frozenset({".txt", ".md", ".csv", ".log"})

# Reject regardless of filename if magic/MIME looks like malware carriers or executables.
_BLOCKED_MIMES: FrozenSet[str] = frozenset(
    {
        "application/x-dosexec",
        "application/x-msdownload",
        "application/x-msdos-program",
        "application/x-executable",
        "application/x-sharedlib",
        "application/x-mach-binary",
        "application/x-elf",
        "application/java-archive",
        "application/vnd.android.package-archive",
    }
)


def require_clamav() -> bool:
    return os.environ.get("UPLOAD_REQUIRE_CLAMAV", "0").strip().lower() in ("1", "true", "yes")


def read_upload_limited(stream: BinaryIO, max_bytes: int) -> bytes:
    """Read stream until max_bytes; raise ValueError if larger."""
    limit = max_bytes
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"File too large (max {limit // (1024 * 1024)} MB).")
    return data


def _extension(filename: str) -> str:
    base = os.path.basename(filename)
    lower = base.lower()
    if "." not in lower:
        return ""
    return "." + lower.rsplit(".", 1)[-1]


def _validate_text_utf8(data: bytes) -> None:
    if not data:
        return
    data.decode("utf-8")


def _validate_json_content(data: bytes) -> None:
    if not data:
        raise ValueError("Empty JSON file.")
    text = data.decode("utf-8")
    json.loads(text)


def _sniff_mime(data: bytes) -> Optional[str]:
    kind = filetype.guess(data)
    return kind.mime if kind else None


def _clamscan_available() -> bool:
    return shutil.which("clamscan") is not None


def scan_clamav(data: bytes) -> Tuple[str, Optional[str]]:
    """
    Run ClamAV clamscan on a temp file.

    Returns (outcome, detail) where outcome is:
    - "ok": clean, skipped when scanner absent and not required, or recoverable skip
    - "infected": ClamAV reported a match (detail is internal; do not show to users)
    - "error": misconfiguration or scan failure (detail is safe to show where appropriate)
    """
    if not data:
        return "ok", None

    if not _clamscan_available():
        if require_clamav():
            return "error", "Virus scanner is required but ClamAV (clamscan) is not installed."
        return "ok", None

    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            proc = subprocess.run(
                ["clamscan", "--no-summary", tmp_path],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        if proc.returncode == 0:
            return "ok", None
        if proc.returncode == 1:
            detail = (proc.stdout or proc.stderr or "").strip() or "Threat detected."
            return "infected", detail
        err = (proc.stderr or proc.stdout or "clamscan failed").strip()
        return "error", err
    except subprocess.TimeoutExpired:
        return "error", "Virus scan timed out."
    except OSError as e:
        if require_clamav():
            return "error", f"Virus scan failed: {e}"
        return "ok", None


def validate_upload(filename: str, data: bytes) -> str:
    """
    Validate extension, content/MIME, and malware scan.
    Returns the basename filename to store (unchanged if already validated by safe_filename).
    Raises ValueError with a short user-facing message on failure.
    """
    ext = _extension(filename)
    if ext not in _ALLOWED_EXTENSIONS:
        raise ValueError(
            "Only these file types are allowed: "
            + ", ".join(sorted(e.lstrip(".") for e in _ALLOWED_EXTENSIONS))
            + "."
        )

    sniffed = _sniff_mime(data)
    if sniffed and sniffed in _BLOCKED_MIMES:
        raise ValueError("This file type is not allowed (executable or unsafe content detected).")

    if ext in _TEXT_LIKE:
        if sniffed and sniffed not in _BLOCKED_MIMES:
            if sniffed not in ("text/plain", "application/octet-stream") and not sniffed.startswith(
                "text/"
            ):
                raise ValueError("File content does not match plain text.")
        _validate_text_utf8(data)

    elif ext == ".json":
        if sniffed and sniffed not in ("application/json", "text/plain"):
            raise ValueError("File content does not match a JSON document.")
        _validate_json_content(data)

    elif ext == ".pdf":
        if not data.startswith(b"%PDF"):
            raise ValueError("Invalid PDF file (missing PDF header).")
        if sniffed and sniffed != "application/pdf":
            raise ValueError("File content does not match a PDF document.")

    outcome, scan_err = scan_clamav(data)
    if outcome == "infected":
        raise MalwareDetectedError(scan_err or "malware scan failed")
    if outcome == "error":
        raise ValueError(scan_err or "Security scan failed.")

    return os.path.basename(filename)
