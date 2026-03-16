"""
Tests for SQLiteStateStore and action_key_for.

Covers:
  - action_key_for determinism and uniqueness
  - create_action_if_new idempotence via UNIQUE constraint
  - claim_actions atomicity (no double-claiming)
  - update_action status transitions and retry fields
  - has_active_action correctly returns True/False across status transitions
  - run lifecycle: create_run / finish_run / list_runs
  - ingest_execution_result and retrieval
"""
import tempfile
import uuid
from datetime import datetime, timezone

import pytest

from state.sqlite_store import SQLiteStateStore, action_key_for


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _store() -> SQLiteStateStore:
    """Fresh in-memory-equivalent store per test (temp file)."""
    return SQLiteStateStore(db_path=tempfile.mktemp(suffix=".db"))


def _action(resource_id="r-1", action_type="close_open_ssh", key=None) -> dict:
    now = _now()
    return {
        "action_id": str(uuid.uuid4()),
        "action_key": key or str(uuid.uuid4()),
        "action_type": action_type,
        "resource_id": resource_id,
        "status": "PENDING",
        "created_at": now,
        "updated_at": now,
    }


# ---------------------------------------------------------------------------
# action_key_for
# ---------------------------------------------------------------------------

class TestActionKeyFor:
    def test_deterministic(self):
        k1 = action_key_for("r-1", "close_open_ssh", {"port": 22})
        k2 = action_key_for("r-1", "close_open_ssh", {"port": 22})
        assert k1 == k2

    def test_different_resource_gives_different_key(self):
        assert action_key_for("r-1", "close_open_ssh", {}) != action_key_for("r-2", "close_open_ssh", {})

    def test_different_action_type_gives_different_key(self):
        assert action_key_for("r-1", "close_open_ssh", {}) != action_key_for("r-1", "close_open_rdp", {})

    def test_none_and_empty_dict_are_equivalent(self):
        assert action_key_for("r-1", "review_high_cost", None) == action_key_for("r-1", "review_high_cost", {})

    def test_dict_key_order_is_irrelevant(self):
        k1 = action_key_for("r-1", "close_open_ssh", {"port": 22, "cidr": "0.0.0.0/0"})
        k2 = action_key_for("r-1", "close_open_ssh", {"cidr": "0.0.0.0/0", "port": 22})
        assert k1 == k2

    def test_returns_64_char_hex_string(self):
        k = action_key_for("r-1", "close_open_ssh", {})
        assert len(k) == 64
        assert all(c in "0123456789abcdef" for c in k)


# ---------------------------------------------------------------------------
# create_action_if_new
# ---------------------------------------------------------------------------

class TestCreateActionIfNew:
    def test_inserts_new_action(self):
        store = _store()
        assert store.create_action_if_new(_action()) is True

    def test_duplicate_key_returns_false(self):
        store = _store()
        shared_key = str(uuid.uuid4())
        a1 = _action(key=shared_key)
        a2 = _action(resource_id="r-2", key=shared_key)
        assert store.create_action_if_new(a1) is True
        assert store.create_action_if_new(a2) is False

    def test_different_keys_both_succeed(self):
        store = _store()
        assert store.create_action_if_new(_action()) is True
        assert store.create_action_if_new(_action()) is True

    def test_missing_required_field_raises(self):
        store = _store()
        bad = _action()
        del bad["action_key"]
        with pytest.raises(ValueError):
            store.create_action_if_new(bad)


# ---------------------------------------------------------------------------
# claim_actions
# ---------------------------------------------------------------------------

class TestClaimActions:
    def test_claiming_sets_in_progress(self):
        store = _store()
        store.create_action_if_new(_action())
        claimed = store.claim_actions(limit=10)
        assert len(claimed) == 1
        assert claimed[0]["status"] == "IN_PROGRESS"

    def test_no_double_claiming(self):
        store = _store()
        store.create_action_if_new(_action())
        first = store.claim_actions(limit=10)
        second = store.claim_actions(limit=10)
        assert len(first) == 1
        assert len(second) == 0

    def test_respects_limit(self):
        store = _store()
        for _ in range(5):
            store.create_action_if_new(_action())
        claimed = store.claim_actions(limit=2)
        assert len(claimed) == 2

    def test_retry_with_past_next_retry_at_is_claimed(self):
        store = _store()
        a = _action()
        store.create_action_if_new(a)
        claimed = store.claim_actions(limit=1)
        # set to RETRY with a past next_retry_at
        store.update_action(
            claimed[0]["action_id"],
            status="RETRY",
            next_retry_at="2000-01-01T00:00:00+00:00",
        )
        reclaimed = store.claim_actions(limit=1)
        assert len(reclaimed) == 1

    def test_retry_with_future_next_retry_at_is_not_claimed(self):
        store = _store()
        a = _action()
        store.create_action_if_new(a)
        claimed = store.claim_actions(limit=1)
        store.update_action(
            claimed[0]["action_id"],
            status="RETRY",
            next_retry_at="2099-01-01T00:00:00+00:00",
        )
        reclaimed = store.claim_actions(limit=1)
        assert len(reclaimed) == 0


# ---------------------------------------------------------------------------
# update_action
# ---------------------------------------------------------------------------

class TestUpdateAction:
    def test_success_transition(self):
        store = _store()
        store.create_action_if_new(_action())
        claimed = store.claim_actions(limit=1)
        action_id = claimed[0]["action_id"]
        store.update_action(action_id, status="SUCCESS")
        assert store.get_action(action_id)["status"] == "SUCCESS"

    def test_retry_stores_all_fields(self):
        store = _store()
        store.create_action_if_new(_action())
        claimed = store.claim_actions(limit=1)
        action_id = claimed[0]["action_id"]
        store.update_action(
            action_id,
            status="RETRY",
            attempt_count=2,
            next_retry_at="2099-01-01T00:00:00+00:00",
            last_error="connection refused",
        )
        a = store.get_action(action_id)
        assert a["status"] == "RETRY"
        assert a["attempt_count"] == 2
        assert a["next_retry_at"] == "2099-01-01T00:00:00+00:00"
        assert a["last_error"] == "connection refused"


# ---------------------------------------------------------------------------
# has_active_action
# ---------------------------------------------------------------------------

class TestHasActiveAction:
    def test_true_for_pending(self):
        store = _store()
        store.create_action_if_new(_action(resource_id="sg-1", action_type="close_open_ssh"))
        assert store.has_active_action("sg-1", "close_open_ssh") is True

    def test_true_for_in_progress(self):
        store = _store()
        store.create_action_if_new(_action(resource_id="sg-1", action_type="close_open_ssh"))
        store.claim_actions(limit=1)
        assert store.has_active_action("sg-1", "close_open_ssh") is True

    def test_true_for_retry(self):
        store = _store()
        store.create_action_if_new(_action(resource_id="sg-1", action_type="close_open_ssh"))
        claimed = store.claim_actions(limit=1)
        store.update_action(claimed[0]["action_id"], status="RETRY")
        assert store.has_active_action("sg-1", "close_open_ssh") is True

    def test_false_after_success(self):
        store = _store()
        store.create_action_if_new(_action(resource_id="sg-1", action_type="close_open_ssh"))
        claimed = store.claim_actions(limit=1)
        store.update_action(claimed[0]["action_id"], status="SUCCESS")
        assert store.has_active_action("sg-1", "close_open_ssh") is False

    def test_false_for_different_resource(self):
        store = _store()
        store.create_action_if_new(_action(resource_id="sg-1", action_type="close_open_ssh"))
        assert store.has_active_action("sg-2", "close_open_ssh") is False

    def test_false_for_different_action_type(self):
        store = _store()
        store.create_action_if_new(_action(resource_id="sg-1", action_type="close_open_ssh"))
        assert store.has_active_action("sg-1", "close_open_rdp") is False


# ---------------------------------------------------------------------------
# Run lifecycle
# ---------------------------------------------------------------------------

class TestRunLifecycle:
    def test_create_and_finish_run(self):
        store = _store()
        run_id = store.create_run()
        assert run_id is not None
        store.finish_run(
            run_id,
            proposed_count=5,
            claimed_count=4,
            success_count=3,
            failed_count=0,
            retry_count=1,
        )
        runs = store.list_runs(limit=1)
        assert runs[0]["status"] == "FINISHED"
        assert runs[0]["success_count"] == 3
        assert runs[0]["retry_count"] == 1
        assert runs[0]["claimed_count"] == 4

    def test_multiple_runs_ordered_newest_first(self):
        store = _store()
        r1 = store.create_run()
        r2 = store.create_run()
        store.finish_run(r1, proposed_count=1, claimed_count=1, success_count=1, failed_count=0, retry_count=0)
        store.finish_run(r2, proposed_count=2, claimed_count=2, success_count=2, failed_count=0, retry_count=0)
        runs = store.list_runs(limit=10)
        assert runs[0]["run_id"] == r2  # newest first


# ---------------------------------------------------------------------------
# Execution results
# ---------------------------------------------------------------------------

class TestExecutionResults:
    def test_ingest_and_retrieve(self):
        store = _store()
        store.create_action_if_new(_action())
        claimed = store.claim_actions(limit=1)
        action_id = claimed[0]["action_id"]

        store.ingest_execution_result({
            "action_id": action_id,
            "resource_id": "r-1",
            "action_type": "close_open_ssh",
            "status": "SUCCESS",
            "completed_at": _now(),
            "payload": {"did": "RevokeSecurityGroupIngress"},
        })
        results = store.list_execution_results_for_action(action_id)
        assert len(results) == 1
        assert results[0]["status"] == "SUCCESS"

    def test_multiple_results_per_action(self):
        store = _store()
        store.create_action_if_new(_action())
        claimed = store.claim_actions(limit=1)
        action_id = claimed[0]["action_id"]

        for _ in range(3):
            store.ingest_execution_result({
                "action_id": action_id,
                "resource_id": "r-1",
                "action_type": "close_open_ssh",
                "status": "RETRY",
                "completed_at": _now(),
                "payload": {"error": "timeout"},
            })
        assert len(store.list_execution_results_for_action(action_id)) == 3
