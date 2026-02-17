<<<<<<< HEAD
from __future__ import annotations
from typing import Any, Dict, List, Optional, Protocol


class StateStore(Protocol):
    # ---- Events / Resources ----
    def ingest_event(self, event: Dict[str, Any]) -> None: ...
    def get_resource(self, resource_id: str) -> Optional[Dict[str, Any]]: ...
    def list_resources(self) -> List[Dict[str, Any]]: ...

    # ---- Execution Results ----
    def ingest_execution_result(self, result: Dict[str, Any]) -> None: ...
    def list_execution_results(self) -> Dict[str, Dict[str, Any]]: ...

    # ---- Helper for agents ----
    def last_status(self, resource_id: str, action_type: str) -> Optional[str]: ...
=======
from typing import Any, Dict, List, Optional, Protocol
>>>>>>> 3453fcd (SQLite store updates + execution history)

class StateStore(Protocol):
    # ... existing methods ...

    # ---- Actions (lifecycle) ----
    def create_action_if_new(self, action: Dict[str, Any]) -> bool: ...
    def claim_actions(self, limit: int) -> List[Dict[str, Any]]: ...
    def update_action(
        self,
        action_id: str,
        *,
        status: str,
        updated_at: Optional[str] = None,
        attempt_count: Optional[int] = None,
        next_retry_at: Optional[str] = None,
        last_error: Optional[str] = None,
    ) -> None: ...
    
    

class InMemoryStateStore:
    """
    Simple in‑memory implementation for testing/dev.
    """

    def __init__(self):
        self._resources: Dict[str, Dict[str, Any]] = {}
        self._execution_results: Dict[str, Dict[str, Any]] = {}

    # ---- Events / Resources ----
    def ingest_event(self, event: Dict[str, Any]) -> None:
        rid = event.get("resource_id")
        if not rid:
            raise ValueError("event must contain resource_id")
        self._resources[rid] = dict(event)

    def get_resource(self, resource_id: str) -> Optional[Dict[str, Any]]:
        return self._resources.get(resource_id)

    def list_resources(self) -> List[Dict[str, Any]]:
        return list(self._resources.values())

    # ---- Execution Results ----
    def ingest_execution_result(self, result: Dict[str, Any]) -> None:
        aid = result.get("action_id")
        if not aid:
            raise ValueError("execution result must contain action_id")
        self._execution_results[aid] = dict(result)

    def list_execution_results(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._execution_results)

    # ---- Helper ----
    def last_status(self, resource_id: str, action_type: str) -> Optional[str]:
        latest_ts = ""
        latest_status: Optional[str] = None

        for r in self._execution_results.values():
            if r.get("resource_id") != resource_id:
                continue
            if r.get("action_type") != action_type:
                continue

            ts = r.get("completed_at") or r.get("created_at") or ""
            if ts >= latest_ts:
                latest_ts = ts
                latest_status = r.get("status")

        return latest_status
