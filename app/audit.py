from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Optional, Any, Dict
from pathlib import Path
import portalocker

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def append_audit(audit_path: Path, entry: Dict[str, Any]) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False)
    # lock audit file for append
    with portalocker.Lock(str(audit_path), mode="a", timeout=5) as f:
        f.write(line + "\n")
