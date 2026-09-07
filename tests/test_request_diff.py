from __future__ import annotations

import unittest

from secure_agent_gateway.request_diff import changed_fields, semantic_request

from tests.support import make_request


class RequestDiffTests(unittest.TestCase):
    def test_semantic_request_omits_transport_identifiers(self) -> None:
        request = make_request(arguments={"records": ["first", "second"]})

        self.assertEqual(
            semantic_request(request),
            {
                "principal_id": request.principal_id,
                "tool": request.tool,
                "arguments": {"records": ["first", "second"]},
            },
        )

    def test_changed_fields_reports_nested_sequence_positions(self) -> None:
        left = {"arguments": {"records": ["first", "second"]}}
        right = {"arguments": {"records": ["first", "replacement", "third"]}}

        self.assertEqual(
            changed_fields(left, right),
            {"arguments.records.1", "arguments.records.2"},
        )


if __name__ == "__main__":
    unittest.main()
