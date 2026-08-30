from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from secure_agent_gateway.mcp import MCPGatewayAdapter, MCPProtocolError

from tests.support import AUTH_KEY, NOW, make_gateway


class MCPGatewayAdapterTests(unittest.TestCase):
    def make_adapter(self, directory: str) -> tuple[MCPGatewayAdapter, object]:
        fixture = make_gateway(Path(directory))
        identifiers = iter(("mcp-request-1", "mcp-nonce-1", "mcp-request-2", "mcp-nonce-2"))
        adapter = MCPGatewayAdapter(
            gateway=fixture.gateway,
            registry=fixture.policy.registry,
            key_id="agent-key",
            signing_secret=AUTH_KEY,
            principal_id="agent-1",
            session_handle="session-1",
            allowed_tools=frozenset({"search_docs", "post_results"}),
            clock=lambda: NOW,
            identifier_factory=lambda: next(identifiers),
        )
        return adapter, fixture

    def test_tool_listing_is_sorted_private_and_closed(self) -> None:
        with TemporaryDirectory() as directory:
            adapter, _ = self.make_adapter(directory)
            result = adapter.list_tools()
        self.assertEqual(result["resultType"], "complete")
        self.assertEqual(result["cacheScope"], "private")
        self.assertEqual(
            [tool["name"] for tool in result["tools"]],
            ["post_results", "search_docs"],
        )
        search = result["tools"][1]
        self.assertFalse(search["inputSchema"]["additionalProperties"])
        self.assertEqual(search["inputSchema"]["required"], ["query"])

    def test_permitted_call_returns_current_mcp_result_shape(self) -> None:
        with TemporaryDirectory() as directory:
            adapter, fixture = self.make_adapter(directory)
            result = adapter.call_tool("search_docs", {"query": "policy"})
            audit = fixture.audit.verify()
        self.assertEqual(result.protocol_result["resultType"], "complete")
        self.assertFalse(result.protocol_result["isError"])
        self.assertEqual(result.gateway_result.status, "succeeded")
        self.assertEqual(audit[-1]["event"]["session_id"], "session-1")

    def test_unlisted_tool_is_a_protocol_error(self) -> None:
        with TemporaryDirectory() as directory:
            adapter, _ = self.make_adapter(directory)
            with self.assertRaises(MCPProtocolError) as caught:
                adapter.call_tool("delete_workspace", {})
        self.assertEqual(caught.exception.code, -32602)

    def test_policy_denial_is_reported_as_a_tool_error(self) -> None:
        with TemporaryDirectory() as directory:
            adapter, _ = self.make_adapter(directory)
            result = adapter.call_tool(
                "post_results",
                {
                    "destination": "https://unlisted.example.test/results",
                    "payload": {"result": "fixture"},
                },
            )
        self.assertTrue(result.protocol_result["isError"])
        self.assertEqual(result.gateway_result.error_code, "network.host_denied")

    def test_pending_approval_identifier_stays_in_the_host_result(self) -> None:
        with TemporaryDirectory() as directory:
            adapter, _ = self.make_adapter(directory)
            result = adapter.call_tool(
                "post_results",
                {
                    "destination": "https://research.example.test/results",
                    "payload": {"result": "fixture"},
                },
            )
        rendered = result.to_mapping()
        self.assertEqual(result.gateway_result.status, "pending_approval")
        self.assertTrue(rendered["isError"])
        self.assertNotIn("mcp-request-1", str(rendered))

    def test_allowed_tool_set_must_be_registered(self) -> None:
        with TemporaryDirectory() as directory:
            fixture = make_gateway(Path(directory))
            with self.assertRaisesRegex(ValueError, "not registered"):
                MCPGatewayAdapter(
                    gateway=fixture.gateway,
                    registry=fixture.policy.registry,
                    key_id="agent-key",
                    signing_secret=AUTH_KEY,
                    principal_id="agent-1",
                    session_handle="session-1",
                    allowed_tools=frozenset({"missing"}),
                )


if __name__ == "__main__":
    unittest.main()
