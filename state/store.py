from typing import Any, Dict, List


class InMemoryStateStore:
    def __init__(self):
        self._events: List[Dict[str, Any]] = []
        self._execution_results: Dict[str, Dict[str, Any]] = {}

    # ---- Events ----
    def ingest_event(self, event: Dict[str, Any]) -> None:
        self._events.append(event)

    def list_resources(self) -> List[Dict[str, Any]]:
        return list(self._events)

    # ---- Execution Results ----
    def ingest_execution_result(self, result: Dict[str, Any]) -> None:
        action_id = result["action_id"]

        self._execution_results[action_id] = {
            "status": result["status"],
            "completed_at": result["completed_at"],
            "observed_impact": result.get("observed_impact"),
            "notes": result.get("notes"),
        }

    def list_execution_results(self) -> Dict[str, Dict[str, Any]]:
        return self._execution_results
