import json
from pathlib import Path
from typing import Any, Dict

from jsonschema import Draft7Validator


ROOT = Path(__file__).resolve().parents[1]


def load_schema(schema_name: str) -> Dict[str, Any]:
    schema_path = ROOT / "schemas" / "v1" / schema_name
    return json.loads(schema_path.read_text(encoding="utf-8"))


def validate_payload(payload: Dict[str, Any], schema_name: str) -> None:
    schema = load_schema(schema_name)
    validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda e: e.path)

    if errors:
        msgs = []
        for e in errors:
            path = ".".join([str(p) for p in e.path]) or "<root>"
            msgs.append(f"{path}: {e.message}")
        raise ValueError("Schema validation failed:\n" + "\n".join(msgs))
