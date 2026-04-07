import json
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Any


_POOL_CURSOR_LOCK = threading.Lock()
_POOL_CURSORS: dict[str, int] = {}


def _project_root() -> Path:
    return Path.cwd()


def _normalize_pool_dir(pool_dir: str | None = None) -> Path:
    raw = str(pool_dir or "mail").strip() or "mail"
    path = Path(raw)
    if path.is_absolute():
        return path
    return _project_root() / path


def _normalize_filename(filename: str | None = None) -> str:
    raw = Path(str(filename or "").strip() or "").name
    if not raw:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"forwardmail_{timestamp}.json"

    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._")
    if not safe:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = f"forwardmail_{timestamp}"
    if not safe.lower().endswith(".json"):
        safe += ".json"
    return safe


def _normalize_record(entry: Any) -> dict[str, str]:
    if isinstance(entry, str):
        email = entry.strip()
        if not email:
            raise ValueError("空邮箱记录")
        return {"email": email}
    if isinstance(entry, dict):
        email = str(entry.get("email") or entry.get("mail") or "").strip()
        if not email:
            raise ValueError("缺少 email")
        return {"email": email}
    raise ValueError(f"不支持的邮箱记录格式: {type(entry).__name__}")


def parse_forwardmail_pool_content(content: str) -> list[dict[str, str]]:
    text = str(content or "").strip()
    if not text:
        raise ValueError("邮箱池内容为空")

    if text[:1] in {"[", "{"}:
        payload = json.loads(text)
        if isinstance(payload, list):
            items = payload
        elif isinstance(payload, dict):
            items = payload.get("emails") or payload.get("items") or [payload]
        else:
            items = [payload]
        records = [_normalize_record(item) for item in items]
    else:
        lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        records = [{"email": line} for line in lines]

    if not records:
        raise ValueError("邮箱池内容为空")
    return records


def resolve_forwardmail_pool_path(
    *,
    pool_file: str | None = None,
    pool_dir: str | None = None,
) -> Path:
    base_dir = _normalize_pool_dir(pool_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    raw_file = str(pool_file or "").strip()
    if raw_file:
        file_path = Path(raw_file)
        if file_path.is_absolute():
            resolved = file_path
        else:
            resolved = base_dir / file_path.name
            if not resolved.exists():
                fallback = _project_root() / raw_file
                if fallback.exists():
                    resolved = fallback
        if not resolved.exists():
            raise RuntimeError(f"转发邮箱池文件不存在: {resolved}")
        return resolved

    candidates = [
        path
        for pattern in ("forwardmail_*.json", "forwardmail_*.txt")
        for path in base_dir.glob(pattern)
        if path.is_file()
    ]
    if not candidates:
        # Fallback to any .json or .txt if specific pattern not found
        candidates = [
            path
            for pattern in ("*.json", "*.txt")
            for path in base_dir.glob(pattern)
            if path.is_file() and "forwardmail" in path.name
        ]
        
    if not candidates:
         raise RuntimeError(f"mail 目录下未找到可用的转发邮箱池文件: {base_dir}")
         
    candidates.sort(key=lambda item: (item.stat().st_mtime, item.name), reverse=True)
    return candidates[0]


def load_forwardmail_pool_records(
    *,
    pool_file: str | None = None,
    pool_dir: str | None = None,
) -> tuple[Path, list[dict[str, str]]]:
    path = resolve_forwardmail_pool_path(pool_file=pool_file, pool_dir=pool_dir)
    content = path.read_text(encoding="utf-8", errors="ignore")
    records = parse_forwardmail_pool_content(content)
    return path, records


def load_forwardmail_pool_snapshot(
    *,
    pool_file: str | None = None,
    pool_dir: str | None = None,
    preview_limit: int = 100,
) -> dict[str, Any]:
    try:
        path, records = load_forwardmail_pool_records(pool_file=pool_file, pool_dir=pool_dir)
        limit = max(int(preview_limit or 0), 0)
        items = [
            {
                "index": idx,
                "email": record["email"],
                "mailbox": "INBOX",
            }
            for idx, record in enumerate(records[:limit], start=1)
        ]
        return {
            "filename": path.name,
            "path": str(path),
            "count": len(records),
            "items": items,
            "truncated": len(records) > limit if limit > 0 else len(records) > 0,
        }
    except Exception:
        return {
            "filename": str(pool_file or ""),
            "path": "",
            "count": 0,
            "items": [],
            "truncated": False,
        }


def take_next_forwardmail_record(
    *,
    pool_file: str | None = None,
    pool_dir: str | None = None,
) -> tuple[Path, dict[str, str]]:
    path, records = load_forwardmail_pool_records(pool_file=pool_file, pool_dir=pool_dir)
    key = str(path.resolve())
    with _POOL_CURSOR_LOCK:
        index = _POOL_CURSORS.get(key, 0)
        record = records[index % len(records)]
        _POOL_CURSORS[key] = index + 1
    return path, record


def save_forwardmail_pool_json(
    content: str,
    *,
    pool_dir: str | None = None,
    filename: str | None = None,
) -> dict[str, Any]:
    records = parse_forwardmail_pool_content(content)
    output_dir = _normalize_pool_dir(pool_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = _normalize_filename(filename)
    path = output_dir / safe_name
    path.write_text(
        json.dumps(records, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return {
        "filename": safe_name,
        "path": str(path),
        "count": len(records),
    }
