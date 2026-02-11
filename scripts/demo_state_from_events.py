import sys
from pathlib import Path

# Make repo root importable so: from state.store import ...
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
from state.store import InMemoryStateStore


def main():
    store = InMemoryStateStore()

    with open("../cloudlink-infra/out/events.jsonl", "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            event = json.loads(line)
            store.ingest_event(event)

    print("State contents:")
    print(store.list_resources())


if __name__ == "__main__":
    main()
