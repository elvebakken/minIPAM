from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Optional, Any, Dict, List
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

def read_audit_logs(audit_path: Path, user_filter: Optional[str] = None, action_filter: Optional[str] = None, 
                    date_from: Optional[str] = None, date_to: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
    """Read audit logs from file with optional filtering."""
    if not audit_path.exists():
        return []
    
    entries = []
    try:
        with portalocker.Lock(str(audit_path), mode="r", timeout=5) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    # Apply filters
                    if user_filter and entry.get("user") != user_filter:
                        continue
                    if action_filter and entry.get("action") != action_filter:
                        continue
                    if date_from:
                        try:
                            entry_ts = datetime.fromisoformat(entry.get("ts", "").replace("Z", "+00:00"))
                            from_ts = datetime.fromisoformat(date_from.replace("Z", "+00:00"))
                            if entry_ts < from_ts:
                                continue
                        except:
                            pass
                    if date_to:
                        try:
                            entry_ts = datetime.fromisoformat(entry.get("ts", "").replace("Z", "+00:00"))
                            to_ts = datetime.fromisoformat(date_to.replace("Z", "+00:00"))
                            if entry_ts > to_ts:
                                continue
                        except:
                            pass
                    entries.append(entry)
                except json.JSONDecodeError:
                    continue
    except Exception:
        pass
    
    # Return most recent first, limit results
    entries.reverse()
    return entries[:limit]
