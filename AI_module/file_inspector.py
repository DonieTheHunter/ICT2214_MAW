# file_inspector.py (improved hints)
from __future__ import annotations

import hashlib
import math
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

SUSPICIOUS_EXTS = {
    ".exe",".dll",".scr",".bat",".cmd",".ps1",".vbs",".js",".jar",
    ".msi",".lnk",".hta",".iso",".img",".apk",
}
_STR_RE = re.compile(rb"[ -~]{4,}")

def _entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0]*256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c/n
            ent -= p * math.log2(p)
    return float(ent)

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _magic(head: bytes) -> str:
    if head.startswith(b"PK\x03\x04"): return "zip"
    if head.startswith(b"MZ"): return "pe_exe"
    if head.startswith(b"\x7fELF"): return "elf"
    if head.startswith(b"%PDF"): return "pdf"
    return "unknown"

def extract_strings(data: bytes, max_strings: int=40, max_total_chars: int=1600) -> List[str]:
    out: List[str] = []
    total = 0
    for m in _STR_RE.finditer(data):
        s = m.group(0)[:200]
        ss = s.decode("utf-8", errors="ignore").strip()
        if not ss:
            continue
        out.append(ss)
        total += len(ss)
        if len(out) >= max_strings or total >= max_total_chars:
            break
    return out

def _safe_join(upload_dir: Path, filename: str) -> Optional[Path]:
    base = Path(filename).name
    if not base:
        return None
    cand = (upload_dir / base).resolve()
    root = upload_dir.resolve()
    try:
        cand.relative_to(root)
    except Exception:
        return None
    return cand

def inspect_zip(path: Path, max_members: int=50, max_total_uncompressed: int=200_000_000, max_member_read: int=200_000) -> Dict[str, Any]:
    rep: Dict[str, Any] = {"is_zip": True}
    try:
        with zipfile.ZipFile(path, "r") as z:
            infos = z.infolist()
            rep["member_count"] = len(infos)
            rep["total_uncompressed_bytes"] = int(sum(i.file_size for i in infos))
            names = [i.filename for i in infos[:max_members]]
            rep["members_sample"] = names
            rep["suspicious_members_sample"] = [n for n in names if Path(n).suffix.lower() in SUSPICIOUS_EXTS][:20]
            if rep["total_uncompressed_bytes"] <= max_total_uncompressed:
                sample = []
                for info in infos:
                    if len(sample) >= 4:
                        break
                    if info.is_dir() or info.file_size > max_member_read:
                        continue
                    try:
                        data = z.read(info)
                        s = extract_strings(data)[:15]
                        if s:
                            sample.append({"member": info.filename, "strings": s})
                    except Exception:
                        continue
                rep["member_strings_sample"] = sample
            else:
                rep["note"] = "zip too large to inspect members safely"
    except Exception as e:
        rep["error"] = f"{type(e).__name__}: {e}"
    return rep

def inspect_file_path(path: Path, sha256_expected: Optional[str]=None, max_bytes_read: int=2_000_000) -> Dict[str, Any]:
    rep: Dict[str, Any] = {"available": False, "path": str(path)}
    if not path.exists():
        rep["error"] = "file_not_found"
        return rep
    if not path.is_file():
        rep["error"] = "not_a_file"
        return rep

    rep["available"] = True
    rep["size_bytes"] = int(path.stat().st_size)
    rep["sha256"] = _sha256_file(path)
    if sha256_expected:
        rep["sha256_matches_record"] = (rep["sha256"].lower() == str(sha256_expected).lower())

    head = path.open("rb").read(max_bytes_read)
    rep["magic"] = _magic(head)
    rep["entropy_head"] = _entropy_bytes(head)
    rep["strings_head_sample"] = extract_strings(head)
    if rep["magic"] == "zip":
        rep["zip"] = inspect_zip(path)
    return rep

def inspect_from_record(
    record: Dict[str, Any],
    upload_dir: Optional[str] = None,
    file_path_key: str = "file_path",
    max_bytes_read: int = 2_000_000,
) -> Dict[str, Any]:
    sha_expected = record.get("SHA256") or record.get("sha256")

    if record.get(file_path_key):
        p = Path(str(record[file_path_key]))
        return inspect_file_path(p, sha256_expected=sha_expected, max_bytes_read=max_bytes_read)

    if upload_dir and record.get("filename"):
        root = Path(upload_dir)
        p = _safe_join(root, str(record["filename"]))
        if not p:
            return {
                "available": False,
                "error": "unsafe_filename_path",
                "hint": "filename looked like path traversal; only basenames are allowed",
                "filename": str(record.get("filename")),
            }
        rep = inspect_file_path(p, sha256_expected=sha_expected, max_bytes_read=max_bytes_read)
        if not rep.get("available"):
            rep["hint"] = "File not found. Verify --upload-dir and that the saved filename matches the log."
        return rep

    return {
        "available": False,
        "error": "no_file_path_available",
        "hint": "Pass --upload-dir or log a 'file_path' field (absolute path) in your web server.",
        "filename": str(record.get("filename", "")),
    }
