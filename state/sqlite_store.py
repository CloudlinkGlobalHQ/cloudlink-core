from typing import Any, Dict, List, Optional


class SQLiteStateStore:
    """
    SQLite-backed implementation of the state store.

    This is a skeleton only.
    No real DB logic yet — just method signatures
    matching the InMemoryStateStore.
    """

    def __init__(self, db_path: str = "cloudlink.db"):
        self.db_path = db_path

    # ---- Events / Resource State ----
    def ingest_event(self, event: Dict[str, Any]) -> None:
        raise NotImplementedError("SQLite store not implemented yet")

    def get_resource(self, resource_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError("SQLite store not implemented yet")

    def list_resources(self) -> List[Dict[str, Any]]:
        raise NotImplementedError("SQLite store not implemented yet")

    # ---- Execution Results ----
    def ingest_execution_result(self, result: Dict[str, Any]) -> None:
        raise NotImplementedError("SQLite store not implemented yet")

    def list_execution_results(self) -> Dict[str, Dict[str, Any]]:
        raise NotImplementedError("SQLite store not implemented yet")
