import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from state.store import InMemoryStateStore


def main():
    store = InMemoryStateStore()

    execution_result = {
        "action_id": "a1b2c3",
        "status": "SUCCESS",
        "completed_at": "2026-02-01T03:05:00Z",
        "observed_impact": {"estimated_monthly_savings_usd": 25.0},
        "notes": "simulated execution"
    }

    store.ingest_execution_result(execution_result)

    print("Execution Results in State:")
    print(store.list_execution_results())


if __name__ == "__main__":
    main()
