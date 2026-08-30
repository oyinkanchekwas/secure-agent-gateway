# Related work

Tool-call gateways already cover much of the enforcement base used here.

- [Docker MCP Gateway](https://github.com/docker/mcp-gateway) applies policy across MCP invocation
  paths, blocks secret exposure, and limits raw argument logging.
- [Microsoft MCP Gateway](https://github.com/microsoft/mcp-gateway) applies caller roles when tools
  are referenced and again when they are invoked.
- [Gatekeeper](https://github.com/Runestone-Labs/gatekeeper) provides allow, approval, and denial
  decisions with signed, expiring approval links and audit records.
- [MCP Gate](https://github.com/rsh1k/mcp-gate) combines agent identity, argument-aware policy,
  approval, and hash-chained audit records.
- [OpenPort Protocol](https://arxiv.org/abs/2602.20196) describes a server-side tool gateway and an
  execution-time state witness for delayed approvals.
- [Safeguarding LLM Agents from Misalignment through Provenance Analysis](https://arxiv.org/abs/2607.01236)
  measures unnecessary interventions on aligned agent traces. The contract report uses the same
  operational concern when it measures permitted requests that do not receive `allow`.

Secure Agent Gateway uses comparable controls as its enforcement base. Paired policy contracts add
a controlled permitted counterpart for each prohibited request. The changed fields are checked
mechanically, while acceptance measures prevention alongside retained task access. Evidence-field
requirements and a signed result digest keep the policy test record inspectable after the run.
