"""
Phase 2 multi-tenant tests for SQLiteStateStore.

Covers:
  - Tenant CRUD
  - API key issuance and lookup (hashed storage)
  - Tenant isolation: actions/resources/runs are scoped per tenant
  - Cloud credential add / list (masked) / decrypt / delete
  - Approval policies: default, set, override with auto_approve_min_confidence
  - _resolve_initial_status: AWAITING_APPROVAL vs PENDING
  - approve_action / reject_action only work for the owning tenant
"""
import tempfile
import uuid
from datetime import datetime, timezone

import pytest

from state.sqlite_store import SQLiteStateStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _store() -> SQLiteStateStore:
    return SQLiteStateStore(db_path=tempfile.mktemp(suffix=".db"))


def _action(resource_id="r-1", action_type="close_open_ssh") -> dict:
    now = _now()
    return {
        "action_id": str(uuid.uuid4()),
        "action_key": str(uuid.uuid4()),
        "action_type": action_type,
        "resource_id": resource_id,
        "status": "PENDING",
        "created_at": now,
        "updated_at": now,
    }


# ---------------------------------------------------------------------------
# Tenants
# ---------------------------------------------------------------------------

class TestTenants:
    def test_default_tenant_seeded(self):
        s = _store()
        tenants = s.list_tenants()
        ids = [t["tenant_id"] for t in tenants]
        assert "default" in ids

    def test_create_tenant_returns_uuid(self):
        s = _store()
        tid = s.create_tenant("Acme Corp")
        assert len(tid) == 36  # UUID format

    def test_get_tenant(self):
        s = _store()
        tid = s.create_tenant("Test Co")
        t = s.get_tenant(tid)
        assert t is not None
        assert t["name"] == "Test Co"
        assert t["status"] == "active"

    def test_get_tenant_unknown_returns_none(self):
        s = _store()
        assert s.get_tenant("nonexistent") is None

    def test_list_tenants_includes_created(self):
        s = _store()
        s.create_tenant("Alpha")
        s.create_tenant("Beta")
        names = [t["name"] for t in s.list_tenants()]
        assert "Alpha" in names
        assert "Beta" in names


# ---------------------------------------------------------------------------
# API Keys
# ---------------------------------------------------------------------------

class TestApiKeys:
    def test_lookup_after_add(self):
        s = _store()
        tid = s.create_tenant("KeyTest")
        raw = "super-secret-key-123"
        s.add_api_key(tid, raw, label="test")
        assert s.get_tenant_id_for_api_key(raw) == tid

    def test_unknown_key_returns_none(self):
        s = _store()
        assert s.get_tenant_id_for_api_key("not-a-key") is None

    def test_same_raw_key_for_two_tenants_raises(self):
        """The key_hash is the PK — same raw key for two tenants should fail."""
        s = _store()
        t1 = s.create_tenant("T1")
        t2 = s.create_tenant("T2")
        raw = "shared-key"
        s.add_api_key(t1, raw)
        import sqlite3
        with pytest.raises(sqlite3.IntegrityError):
            s.add_api_key(t2, raw)

    def test_raw_key_not_stored_plaintext(self):
        """The key_hash stored is not the same as the raw key."""
        s = _store()
        tid = s.create_tenant("Security")
        raw = "my-plaintext-key"
        key_hash = s.add_api_key(tid, raw)
        assert key_hash != raw
        assert len(key_hash) == 64  # SHA-256 hex


# ---------------------------------------------------------------------------
# Tenant Isolation
# ---------------------------------------------------------------------------

class TestTenantIsolation:
    def test_action_not_visible_to_other_tenant(self):
        s = _store()
        t1 = s.create_tenant("T1")
        t2 = s.create_tenant("T2")

        a = _action()
        s.create_action_if_new(a, tenant_id=t1)

        # t2 should not see t1's action
        assert s.list_actions(tenant_id=t2) == []
        assert s.list_actions(tenant_id=t1) != []

    def test_resource_not_visible_to_other_tenant(self):
        s = _store()
        t1 = s.create_tenant("T1")
        t2 = s.create_tenant("T2")

        s.ingest_event({"resource_id": "ec2-aaa", "type": "ec2"}, tenant_id=t1)

        assert s.list_resources(tenant_id=t1) != []
        assert s.list_resources(tenant_id=t2) == []

    def test_claim_only_claims_own_tenant_actions(self):
        s = _store()
        t1 = s.create_tenant("T1")
        t2 = s.create_tenant("T2")

        # Disable approval requirement for t1 and t2 so action status = PENDING
        s.set_approval_policy(t1, "stop_idle_ec2", require_approval=False)
        s.set_approval_policy(t2, "stop_idle_ec2", require_approval=False)

        a1 = _action(action_type="stop_idle_ec2")
        a2 = _action(action_type="stop_idle_ec2")
        s.create_action_if_new(a1, tenant_id=t1)
        s.create_action_if_new(a2, tenant_id=t2)

        claimed_t1 = s.claim_actions(limit=10, tenant_id=t1)
        assert len(claimed_t1) == 1
        assert claimed_t1[0]["action_id"] == a1["action_id"]

    def test_has_active_action_scoped_to_tenant(self):
        s = _store()
        t1 = s.create_tenant("T1")
        t2 = s.create_tenant("T2")

        a = _action(resource_id="r-shared", action_type="close_open_ssh")
        s.create_action_if_new(a, tenant_id=t1)

        assert s.has_active_action("r-shared", "close_open_ssh", tenant_id=t1)
        assert not s.has_active_action("r-shared", "close_open_ssh", tenant_id=t2)

    def test_runs_scoped_to_tenant(self):
        s = _store()
        t1 = s.create_tenant("T1")
        t2 = s.create_tenant("T2")

        run_id = s.create_run(tenant_id=t1)
        s.finish_run(run_id, proposed_count=0, claimed_count=0, success_count=0, failed_count=0, retry_count=0)

        assert len(s.list_runs(tenant_id=t1)) == 1
        assert len(s.list_runs(tenant_id=t2)) == 0


# ---------------------------------------------------------------------------
# Cloud Credentials
# ---------------------------------------------------------------------------

class TestCloudCredentials:
    def test_add_and_list_masked(self):
        s = _store()
        tid = s.create_tenant("CredTest")
        cred_id = s.add_credential(
            tenant_id=tid,
            cloud="aws",
            credential_type="iam_keys",
            payload='{"access_key": "AKIA...", "secret": "xxxx"}',
            label="prod-aws",
        )
        creds = s.list_credentials(tenant_id=tid)
        assert len(creds) == 1
        assert creds[0]["credential_id"] == cred_id
        assert creds[0]["cloud"] == "aws"
        assert creds[0]["label"] == "prod-aws"
        # list_credentials must NOT return the payload
        assert "encrypted_payload" not in creds[0]
        assert "payload" not in creds[0]

    def test_get_decrypted_credential(self):
        s = _store()
        tid = s.create_tenant("CredTest")
        payload = '{"access_key": "AKIA123", "secret": "shhh"}'
        cred_id = s.add_credential(
            tenant_id=tid, cloud="aws", credential_type="iam_keys", payload=payload
        )
        decrypted = s.get_decrypted_credential(tenant_id=tid, credential_id=cred_id)
        assert decrypted == payload

    def test_credential_not_accessible_by_other_tenant(self):
        s = _store()
        t1 = s.create_tenant("T1")
        t2 = s.create_tenant("T2")
        cred_id = s.add_credential(
            tenant_id=t1, cloud="gcp", credential_type="service_account_json", payload='{"key": "val"}'
        )
        assert s.get_decrypted_credential(tenant_id=t2, credential_id=cred_id) is None

    def test_delete_credential(self):
        s = _store()
        tid = s.create_tenant("CredTest")
        cred_id = s.add_credential(
            tenant_id=tid, cloud="azure", credential_type="client_secret", payload="my-secret"
        )
        assert s.delete_credential(tenant_id=tid, credential_id=cred_id) is True
        assert s.list_credentials(tenant_id=tid) == []

    def test_delete_other_tenant_credential_fails(self):
        s = _store()
        t1 = s.create_tenant("T1")
        t2 = s.create_tenant("T2")
        cred_id = s.add_credential(
            tenant_id=t1, cloud="aws", credential_type="iam_keys", payload="secret"
        )
        # t2 trying to delete t1's credential should return False
        assert s.delete_credential(tenant_id=t2, credential_id=cred_id) is False
        # Still present for t1
        assert len(s.list_credentials(tenant_id=t1)) == 1


# ---------------------------------------------------------------------------
# Approval Policies
# ---------------------------------------------------------------------------

class TestApprovalPolicies:
    def test_default_policy_requires_approval(self):
        s = _store()
        tid = s.create_tenant("PolicyTest")
        policy = s.get_approval_policy(tid, "stop_idle_ec2")
        assert policy["require_approval"] is True
        assert policy["auto_approve_min_confidence"] is None

    def test_set_no_approval_policy(self):
        s = _store()
        tid = s.create_tenant("PolicyTest")
        s.set_approval_policy(tid, "close_open_ssh", require_approval=False)
        policy = s.get_approval_policy(tid, "close_open_ssh")
        assert policy["require_approval"] is False

    def test_auto_approve_min_confidence(self):
        s = _store()
        tid = s.create_tenant("PolicyTest")
        s.set_approval_policy(tid, "stop_idle_ec2", require_approval=True, auto_approve_min_confidence=0.9)
        policy = s.get_approval_policy(tid, "stop_idle_ec2")
        assert policy["require_approval"] is True
        assert policy["auto_approve_min_confidence"] == pytest.approx(0.9)

    def test_upsert_policy(self):
        s = _store()
        tid = s.create_tenant("PolicyTest")
        s.set_approval_policy(tid, "stop_idle_ec2", require_approval=True)
        s.set_approval_policy(tid, "stop_idle_ec2", require_approval=False)
        assert s.get_approval_policy(tid, "stop_idle_ec2")["require_approval"] is False

    def test_list_approval_policies(self):
        s = _store()
        tid = s.create_tenant("PolicyTest")
        s.set_approval_policy(tid, "stop_idle_ec2", require_approval=False)
        s.set_approval_policy(tid, "close_open_ssh", require_approval=True)
        policies = s.list_approval_policies(tid)
        types = [p["action_type"] for p in policies]
        assert "stop_idle_ec2" in types
        assert "close_open_ssh" in types


# ---------------------------------------------------------------------------
# resolve_initial_status and approve/reject
# ---------------------------------------------------------------------------

class TestApprovalWorkflow:
    def test_action_awaiting_approval_by_default(self):
        """Default policy requires approval — action should start AWAITING_APPROVAL."""
        s = _store()
        tid = s.create_tenant("ApprovalTest")
        a = _action()
        s.create_action_if_new(a, tenant_id=tid)
        stored = s.get_action(a["action_id"], tenant_id=tid)
        assert stored["status"] == "AWAITING_APPROVAL"

    def test_action_pending_when_approval_not_required(self):
        s = _store()
        tid = s.create_tenant("ApprovalTest")
        s.set_approval_policy(tid, "close_open_ssh", require_approval=False)
        a = _action(action_type="close_open_ssh")
        s.create_action_if_new(a, tenant_id=tid)
        stored = s.get_action(a["action_id"], tenant_id=tid)
        assert stored["status"] == "PENDING"

    def test_action_auto_approved_by_high_confidence(self):
        s = _store()
        tid = s.create_tenant("ApprovalTest")
        s.set_approval_policy(tid, "stop_idle_ec2", require_approval=True, auto_approve_min_confidence=0.8)
        now = _now()
        a = {
            "action_id": str(uuid.uuid4()),
            "action_key": str(uuid.uuid4()),
            "action_type": "stop_idle_ec2",
            "resource_id": "r-high-conf",
            "status": "PENDING",
            "created_at": now,
            "updated_at": now,
            "confidence": 0.95,
        }
        s.create_action_if_new(a, tenant_id=tid)
        stored = s.get_action(a["action_id"], tenant_id=tid)
        assert stored["status"] == "PENDING"

    def test_approve_action(self):
        s = _store()
        tid = s.create_tenant("ApprovalTest")
        a = _action()
        s.create_action_if_new(a, tenant_id=tid)
        assert s.approve_action(a["action_id"], tid)
        stored = s.get_action(a["action_id"], tenant_id=tid)
        assert stored["status"] == "PENDING"

    def test_reject_action(self):
        s = _store()
        tid = s.create_tenant("ApprovalTest")
        a = _action()
        s.create_action_if_new(a, tenant_id=tid)
        assert s.reject_action(a["action_id"], tid)
        stored = s.get_action(a["action_id"], tenant_id=tid)
        assert stored["status"] == "FAILED"

    def test_approve_wrong_tenant_fails(self):
        s = _store()
        t1 = s.create_tenant("T1")
        t2 = s.create_tenant("T2")
        a = _action()
        s.create_action_if_new(a, tenant_id=t1)
        # t2 trying to approve t1's action
        assert not s.approve_action(a["action_id"], t2)
        # Action is still AWAITING_APPROVAL
        stored = s.get_action(a["action_id"], tenant_id=t1)
        assert stored["status"] == "AWAITING_APPROVAL"

    def test_awaiting_approval_not_claimable(self):
        """AWAITING_APPROVAL actions must not be claimed by the run loop."""
        s = _store()
        tid = s.create_tenant("ApprovalTest")
        a = _action()
        s.create_action_if_new(a, tenant_id=tid)
        # Status is AWAITING_APPROVAL — claim should return empty
        claimed = s.claim_actions(limit=10, tenant_id=tid)
        assert len(claimed) == 0

    def test_claimable_after_approval(self):
        s = _store()
        tid = s.create_tenant("ApprovalTest")
        a = _action()
        s.create_action_if_new(a, tenant_id=tid)
        s.approve_action(a["action_id"], tid)
        claimed = s.claim_actions(limit=10, tenant_id=tid)
        assert len(claimed) == 1
