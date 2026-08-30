from __future__ import annotations

import argparse
import json
from platform import python_version
from statistics import median
from time import perf_counter_ns

from secure_agent_gateway.models import Control, ExecutionContext, Principal, ToolRequest
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.registry import ToolRegistry, ToolSpec
from secure_agent_gateway.session import SequencePolicy, SequenceRule, SessionEvent, SessionSnapshot


def percentile(values: list[int], proportion: float) -> int:
    ordered = sorted(values)
    return ordered[min(int(len(ordered) * proportion), len(ordered) - 1)]


def no_op(arguments, context: ExecutionContext):
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=10_000)
    args = parser.parse_args()
    if args.iterations < 100:
        parser.error("iterations must be at least 100")
    principal = Principal("agent-1", frozenset({"researcher"}))
    registry = ToolRegistry()
    registry.register(
        ToolSpec("send_message", {}, principal.roles),
        no_op,
    )
    policy = PolicyEngine(registry, policy_version="sequence-benchmark-v0.2")
    sequence_policy = SequencePolicy(
        [
            SequenceRule(
                rule_id="customer-data-egress",
                target_tools=frozenset({"send_message"}),
                required_effects=frozenset({"data.customer"}),
                control=Control.DENY,
                reason_code="sequence.customer_data_egress",
            )
        ]
    )
    request = ToolRequest(
        request_id="benchmark-send",
        principal_id=principal.principal_id,
        tool="send_message",
        arguments={},
        issued_at=1_800_000_000,
        nonce="benchmark-nonce",
        session_id="benchmark-session",
    )
    snapshot = SessionSnapshot(
        principal_id=request.principal_id,
        session_id=request.session_id,
        events=(
            SessionEvent(1, "benchmark-read", "read_customer", frozenset({"data.customer"})),
        ),
    )
    base = policy.inspect(principal, request)
    timings: list[int] = []
    for _ in range(args.iterations):
        started = perf_counter_ns()
        decision = sequence_policy.evaluate(request, snapshot, base)
        timings.append(perf_counter_ns() - started)
    if decision.control != Control.DENY:
        raise RuntimeError("benchmark policy did not intervene")
    payload = {
        "iterations": args.iterations,
        "median_nanoseconds": median(timings),
        "p95_nanoseconds": percentile(timings, 0.95),
        "python": python_version(),
        "sequence_policy_digest": sequence_policy.digest,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
