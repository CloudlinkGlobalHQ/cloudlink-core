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
# state/store.py

class InMemoryStateStore:
    def __init__(self):
        # resource_id -> latest event/state
        self._resources = {}

    def ingest_event(self, event: dict):
        """
        Store the latest state for a resource.
        Expects event to contain 'resource_id'.
        """
        resource_id = event.get("resource_id")
        if not resource_id:
            raise ValueError("event must contain resource_id")

        self._resources[resource_id] = event

    def get_resource(self, resource_id: str):
        """
        Return latest known state for a resource.
        """
        return self._resources.get(resource_id)

    def list_resources(self):
        """
        Return all known resource states.
        """
        return list(self._resources.values())
