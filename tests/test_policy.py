from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from secure_agent_gateway.models import Control, ExecutionContext, Principal, RiskLevel
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.rate_limit import RateLimit
from secure_agent_gateway.registry import ToolRegistry, ToolSpec
from secure_agent_gateway.schema import FieldSpec

from tests.support import NOW, make_request


def no_op(arguments, context: ExecutionContext):
    return None


class PolicyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = ToolRegistry()
        self.principal = Principal("agent-1", frozenset({"researcher"}))

    def engine(self) -> PolicyEngine:
        return PolicyEngine(self.registry, policy_version="policy-test")

    def test_unknown_tool_is_denied(self) -> None:
        decision = self.engine().evaluate(self.principal, make_request(tool="missing"), now=NOW)
        self.assertEqual(decision.control, Control.DENY)
        self.assertEqual(decision.reason_codes, ("tool.unknown",))

    def test_path_and_host_rules_require_string_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "string fields"):
            ToolSpec(
                "read_file",
                {"path": FieldSpec("integer")},
                frozenset({"researcher"}),
                path_rules={"path": ("/tmp",)},
            )

    def test_role_mismatch_is_denied(self) -> None:
        self.registry.register(
            ToolSpec("admin_task", {}, frozenset({"administrator"})),
            no_op,
        )
        decision = self.engine().evaluate(
            self.principal,
            make_request(tool="admin_task", arguments={}),
            now=NOW,
        )
        self.assertEqual(decision.reason_codes, ("role.denied",))

    def test_schema_rejects_extra_and_wrong_type_fields(self) -> None:
        self.registry.register(
            ToolSpec("search", {"query": FieldSpec("string")}, frozenset({"researcher"})),
            no_op,
        )
        request = make_request(tool="search", arguments={"query": 4, "scope": "all"})
        decision = self.engine().evaluate(self.principal, request, now=NOW)
        self.assertEqual(decision.control, Control.DENY)
        self.assertIn("schema.wrong_type", decision.reason_codes)
        self.assertIn("schema.unexpected_field", decision.reason_codes)

    def test_agent_supplied_secret_field_is_denied(self) -> None:
        self.registry.register(
            ToolSpec("post", {"payload": FieldSpec("object")}, frozenset({"researcher"})),
            no_op,
        )
        request = make_request(tool="post", arguments={"payload": {"api_key": "fixture"}})
        decision = self.engine().evaluate(self.principal, request, now=NOW)
        self.assertEqual(decision.reason_codes, ("secret.agent_supplied",))
        self.assertEqual(decision.evidence_fields, ("arguments.payload.api_key",))

    def test_path_must_be_absolute_and_inside_root(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "workspace"
            root.mkdir()
            self.registry.register(
                ToolSpec(
                    "read_file",
                    {"path": FieldSpec("string")},
                    frozenset({"researcher"}),
                    path_rules={"path": (str(root),)},
                ),
                no_op,
            )
            engine = self.engine()
            relative = engine.evaluate(
                self.principal,
                make_request(tool="read_file", arguments={"path": "notes.txt"}),
                now=NOW,
            )
            escaped = engine.evaluate(
                self.principal,
                make_request(
                    request_id="req-2",
                    tool="read_file",
                    arguments={"path": str(root / ".." / "outside.txt")},
                ),
                now=NOW + 1,
            )
            allowed = engine.evaluate(
                self.principal,
                make_request(
                    request_id="req-3",
                    tool="read_file",
                    arguments={"path": str(root / "notes.txt")},
                ),
                now=NOW + 2,
            )
        self.assertEqual(relative.reason_codes, ("path.absolute_required",))
        self.assertEqual(escaped.reason_codes, ("path.outside_allowed_root",))
        self.assertEqual(allowed.control, Control.ALLOW)

    def test_outbound_destination_requires_https_and_exact_host(self) -> None:
        self.registry.register(
            ToolSpec(
                "post",
                {"destination": FieldSpec("string")},
                frozenset({"researcher"}),
                host_rules={"destination": ("research.example.test",)},
                rate_limit=RateLimit(5, 60),
            ),
            no_op,
        )
        engine = self.engine()
        insecure = engine.evaluate(
            self.principal,
            make_request(tool="post", arguments={"destination": "http://research.example.test"}),
            now=NOW,
        )
        wrong_host = engine.evaluate(
            self.principal,
            make_request(
                request_id="req-2",
                tool="post",
                arguments={"destination": "https://drop.example.test"},
            ),
            now=NOW + 1,
        )
        allowed = engine.evaluate(
            self.principal,
            make_request(
                request_id="req-3",
                tool="post",
                arguments={"destination": "https://research.example.test/results"},
            ),
            now=NOW + 2,
        )
        non_default_port = engine.evaluate(
            self.principal,
            make_request(
                request_id="req-4",
                tool="post",
                arguments={"destination": "https://research.example.test:444/results"},
            ),
            now=NOW + 3,
        )
        self.assertEqual(insecure.reason_codes, ("network.invalid_destination",))
        self.assertEqual(wrong_host.reason_codes, ("network.host_denied",))
        self.assertEqual(allowed.control, Control.ALLOW)
        self.assertEqual(non_default_port.reason_codes, ("network.invalid_destination",))

    def test_rate_limit_counts_policy_attempts(self) -> None:
        self.registry.register(
            ToolSpec(
                "search",
                {"query": FieldSpec("string")},
                frozenset({"researcher"}),
                rate_limit=RateLimit(1, 60),
            ),
            no_op,
        )
        engine = self.engine()
        first = engine.evaluate(
            self.principal,
            make_request(tool="search", arguments={"query": "one"}),
            now=NOW,
        )
        second = engine.evaluate(
            self.principal,
            make_request(
                request_id="req-2",
                tool="search",
                arguments={"query": "two"},
            ),
            now=NOW + 1,
        )
        self.assertEqual(first.control, Control.ALLOW)
        self.assertEqual(second.reason_codes, ("rate_limit.exceeded",))

    def test_denied_target_probe_consumes_rate_allowance(self) -> None:
        self.registry.register(
            ToolSpec(
                "post",
                {"destination": FieldSpec("string")},
                frozenset({"researcher"}),
                host_rules={"destination": ("research.example.test",)},
                rate_limit=RateLimit(1, 60),
            ),
            no_op,
        )
        engine = self.engine()
        denied = engine.evaluate(
            self.principal,
            make_request(tool="post", arguments={"destination": "https://denied.example.test"}),
            now=NOW,
        )
        limited = engine.evaluate(
            self.principal,
            make_request(
                request_id="req-2",
                tool="post",
                arguments={"destination": "https://research.example.test"},
            ),
            now=NOW + 1,
        )
        self.assertEqual(denied.reason_codes, ("network.host_denied",))
        self.assertEqual(limited.reason_codes, ("rate_limit.exceeded",))

    def test_destructive_tool_requires_approval(self) -> None:
        self.registry.register(
            ToolSpec(
                "remove",
                {},
                frozenset({"researcher"}),
                risk=RiskLevel.DESTRUCTIVE,
            ),
            no_op,
        )
        decision = self.engine().evaluate(
            self.principal,
            make_request(tool="remove", arguments={}),
            now=NOW,
        )
        self.assertEqual(decision.control, Control.REQUIRE_APPROVAL)


if __name__ == "__main__":
    unittest.main()
