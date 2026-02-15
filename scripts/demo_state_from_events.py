import sys
from pathlib import Path

# Make repo root importable so: from state.store import ...
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
from state.store import InMemoryStateStore


def main():
    store = InMemoryStateStore()

    # ~/cloudlink/cloudlink-core/scripts -> ~/cloudlink
    workspace = Path(__file__).resolve().parents[2]
    events_path = workspace / "cloudlink-infra" / "out" / "events.jsonl"

    if not events_path.exists():
        print(f"No events file found at: {events_path}")
        print("Run cloudlink-infra first to generate out/events.jsonl")
        return

    with open(events_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            event = json.loads(line)
            store.ingest_event(event)

    print("State contents:")
    print(store.list_resources())


if __name__ == "__main__":
    main()
