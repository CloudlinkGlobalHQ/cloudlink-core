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
