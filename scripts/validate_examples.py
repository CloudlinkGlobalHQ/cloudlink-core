import json
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
EXECS = ROOT / "examples" / "v1" / "execution_results.jsonl"
ALLOWED_STATUS = {"SUCCESS", "FAILED"}

def parse_dt(s: str) -> None:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    datetime.fromisoformat(s)

def validate_execution_result(obj: dict) -> None:
    for k in ("action_id", "status", "completed_at"):
        if k not in obj:
            raise ValueError(f"missing required field: {k}")
    if not isinstance(obj["action_id"], str) or not obj["action_id"].strip():
        raise ValueError("action_id must be non-empty string")
    if obj["status"] not in ALLOWED_STATUS:
        raise ValueError(f"status must be one of {sorted(ALLOWED_STATUS)}")
    if not isinstance(obj["completed_at"], str):
        raise ValueError("completed_at must be a string")
    parse_dt(obj["completed_at"])

def main():
    if not EXECS.exists():
        raise SystemExit(f"Missing examples file: {EXECS}")
    ok = 0
    for line in EXECS.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        validate_execution_result(obj)
        ok += 1
    print(f"✅ validate_examples: {ok} execution_result example(s) valid")

if __name__ == "__main__":
    main()
