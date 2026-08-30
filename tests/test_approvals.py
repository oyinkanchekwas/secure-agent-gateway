from __future__ import annotations

from dataclasses import replace
import unittest

from secure_agent_gateway.approvals import ApprovalAuthority, ApprovalError
from secure_agent_gateway.models import Control, PolicyDecision

from tests.support import APPROVAL_KEY, NOW


def decision(digest: str = "a" * 64, version: str = "policy-1") -> PolicyDecision:
    return PolicyDecision(
        control=Control.REQUIRE_APPROVAL,
        reason_codes=("approval.required",),
        evidence_fields=("tool",),
        request_digest=digest,
        policy_version=version,
    )


class ApprovalAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = ApprovalAuthority(APPROVAL_KEY, {"reviewer-1"})

    def test_valid_receipt_is_consumed_once(self) -> None:
        current = decision()
        receipt = self.authority.issue(
            current,
            approver_id="reviewer-1",
            now=NOW,
            approval_id="approval-1",
        )
        self.authority.verify_and_consume(receipt, current, now=NOW + 1)
        with self.assertRaisesRegex(ApprovalError, "approval.replayed"):
            self.authority.verify_and_consume(receipt, current, now=NOW + 2)

    def test_receipt_cannot_authorise_changed_request(self) -> None:
        receipt = self.authority.issue(decision(), approver_id="reviewer-1", now=NOW)
        with self.assertRaisesRegex(ApprovalError, "approval.request_mismatch"):
            self.authority.verify_and_consume(receipt, decision("b" * 64), now=NOW + 1)

    def test_receipt_is_bound_to_policy_version(self) -> None:
        receipt = self.authority.issue(decision(), approver_id="reviewer-1", now=NOW)
        with self.assertRaisesRegex(ApprovalError, "approval.policy_mismatch"):
            self.authority.verify_and_consume(receipt, decision(version="policy-2"), now=NOW + 1)

    def test_receipt_is_bound_to_session_context(self) -> None:
        current = replace(decision(), context_digest="b" * 64)
        receipt = self.authority.issue(current, approver_id="reviewer-1", now=NOW)
        changed = replace(current, context_digest="c" * 64)
        with self.assertRaisesRegex(ApprovalError, "approval.context_mismatch"):
            self.authority.verify_and_consume(receipt, changed, now=NOW + 1)

    def test_expired_receipt_is_rejected(self) -> None:
        receipt = self.authority.issue(
            decision(),
            approver_id="reviewer-1",
            ttl_seconds=5,
            now=NOW,
        )
        with self.assertRaisesRegex(ApprovalError, "approval.expired"):
            self.authority.verify_and_consume(receipt, decision(), now=NOW + 6)

    def test_changed_receipt_breaks_signature(self) -> None:
        receipt = self.authority.issue(decision(), approver_id="reviewer-1", now=NOW)
        changed = replace(receipt, expires_at=receipt.expires_at + 60)
        with self.assertRaisesRegex(ApprovalError, "approval.invalid_signature"):
            self.authority.verify_and_consume(changed, decision(), now=NOW + 1)

    def test_unknown_approver_cannot_issue_receipt(self) -> None:
        with self.assertRaisesRegex(ApprovalError, "approval.approver_denied"):
            self.authority.issue(decision(), approver_id="agent-1", now=NOW)

    def test_receipt_from_future_is_rejected(self) -> None:
        receipt = self.authority.issue(decision(), approver_id="reviewer-1", now=NOW + 10)
        with self.assertRaisesRegex(ApprovalError, "approval.not_yet_valid"):
            self.authority.verify_and_consume(receipt, decision(), now=NOW)

    def test_receipt_ttl_has_an_upper_bound(self) -> None:
        with self.assertRaisesRegex(ApprovalError, "approval.invalid_ttl"):
            self.authority.issue(
                decision(),
                approver_id="reviewer-1",
                ttl_seconds=3601,
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
