from __future__ import annotations

import argparse
import json
from pathlib import Path
import secrets
import time

from secure_agent_gateway.approvals import ApprovalAuthority
from secure_agent_gateway.audit import AuditLog
from secure_agent_gateway.auth import Authenticator, PrincipalCredential, sign_request
from secure_agent_gateway.gateway import SecureAgentGateway
from secure_agent_gateway.models import ExecutionContext, Principal, ToolRequest
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.registry import ToolRegistry, ToolSpec
from secure_agent_gateway.schema import FieldSpec


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secure-agent-gateway")
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo = subparsers.add_parser("demo", help="Run a permitted request through the gateway")
    demo.add_argument("--audit-log", type=Path, default=Path("gateway-audit.jsonl"))

    verify = subparsers.add_parser("verify-audit", help="Verify an audit hash chain")
    verify.add_argument("path", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "verify-audit":
        records = AuditLog(args.path).verify()
        print(json.dumps({"records": len(records), "status": "valid"}, sort_keys=True))
        return 0
    return run_demo(args.audit_log)


def run_demo(audit_path: Path) -> int:
    auth_key = secrets.token_bytes(32)
    approval_key = secrets.token_bytes(32)
    principal = Principal("demo-agent", frozenset({"researcher"}))
    credential = PrincipalCredential("demo-key", principal, auth_key)
    authenticator = Authenticator({credential.key_id: credential})
    registry = ToolRegistry()

    def search_docs(arguments: dict, context: ExecutionContext) -> dict:
        return {"matches": [arguments["query"]], "principal": context.principal.principal_id}

    registry.register(
        ToolSpec(
            name="search_docs",
            fields={"query": FieldSpec("string", max_length=200)},
            allowed_roles=frozenset({"researcher"}),
        ),
        search_docs,
    )
    policy = PolicyEngine(registry, policy_version="demo-policy-1")
    gateway = SecureAgentGateway(
        authenticator=authenticator,
        policy=policy,
        approvals=ApprovalAuthority(approval_key, {"demo-reviewer"}),
        audit_log=AuditLog(audit_path),
    )
    now = int(time.time())
    request = ToolRequest(
        request_id=f"demo-{secrets.token_hex(8)}",
        principal_id=principal.principal_id,
        tool="search_docs",
        arguments={"query": "approval policy"},
        issued_at=now,
        nonce=secrets.token_hex(16),
    )
    result = gateway.submit(sign_request(request, credential.key_id, auth_key), now=now)
    print(json.dumps(result.to_mapping(), indent=2, sort_keys=True))
    return 0 if result.status == "succeeded" else 1


if __name__ == "__main__":
    raise SystemExit(main())
