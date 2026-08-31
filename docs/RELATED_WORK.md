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
- [Fides Gateway](https://github.com/microsoft/fides-gateway) propagates information-flow labels
  through agent workflows and applies sink policy to labelled data.
- [AgentGate](https://github.com/zihan001/agentgate) includes sequence-aware controls for file,
  shell, database, and network tool use.
- [Gensee Crate](https://github.com/GenseeAI/gensee-crate) applies content, sequence, and rate rules
  at the MCP tool boundary.
- [Vellaveto](https://github.com/paolovella/vellaveto) combines policy checks, taint tracking,
  behavioural analysis, and approval controls for MCP traffic.
- [AARM](https://github.com/christian-posta/agent-governance-agw) demonstrates agent identity,
  permissions, intent validation, and runtime interception with an AI gateway.
- [Open Agent Passport](https://arxiv.org/abs/2603.20953) signs per-call authorisation decisions and
  verifies them at the tool boundary.
- [Intent-Governed Access Control](https://arxiv.org/abs/2606.22916) binds permissions to a declared
  intent and narrows authority within a session.
- [Bounded Agents](https://arxiv.org/abs/2608.15888) carries restricted scope and budgets through
  delegation chains, with composition checks over accumulated session state.
- [SentinelAgent](https://arxiv.org/abs/2604.02767) defines mechanically checked delegation-chain
  properties and a separate delegation authority service.
- [When Tool Outputs Become Commands](https://arxiv.org/abs/2608.27146) separates action-origin
  provenance from execution authority across multi-step tool use.
- [Solver-Aided Tool Policy Compliance for LLM Agents](https://arxiv.org/abs/2603.20449) expresses
  tool policy as declarative constraints and checks candidate calls with a solver.
- [Agent-C](https://arxiv.org/abs/2512.23738) defines temporal constraints for agent workflows and
  evaluates execution traces against them.
- [Verified Tool Calls](https://arxiv.org/abs/2608.02645) studies tool protocols under non-atomic
  failure, including ambiguous execution outcomes.
- [Temporal Agent Harness](https://github.com/temporal-community/temporal-agent-harness) provides
  durable agent execution and replay on Temporal.
- [Temper](https://github.com/nerdsane/temper) applies model checking to agent behaviour described
  by a formal specification.
- [Semantic differencing for models](https://www.cs.tau.ac.il/~maozs/papers/diff-framework-models15.pdf)
  includes change-impact analysis for access-control policies and witness-based semantic diffs.
- [IronSpec](https://www.usenix.org/conference/osdi24/presentation/goldweber) tests formal
  specifications with sanity checks, proof obligations, and mutation analysis.
- [Stateful Governance for Concurrent Agentic Systems](https://arxiv.org/abs/2608.02764) defines
  policy-state serialisability for agent actions over shared mutable state.
- [Safeguarding LLM Agents from Misalignment through Provenance Analysis](https://arxiv.org/abs/2607.01236)
  measures unnecessary interventions on aligned agent traces. The contract report uses the same
  operational concern when it measures permitted requests that do not receive `allow`.
- The [MCP 2026-07-28 tools specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/server/tools.mdx)
  defines deterministic tool discovery, private caching, complete results, and explicit state
  handles for cross-call workflows.

Secure Agent Gateway uses signed requests, bounded tools, approvals, and audit records as its
enforcement base. Its assurance layer pairs each prohibited request or trajectory with a controlled
permitted counterpart. Construction checks the changed fields, and acceptance measures prevention,
retained access, intervention timing, and causal evidence.

Sequence-policy mutation analysis tests the contract suite itself. Removing a rule, weakening its
control, narrowing its event window, or deleting one condition creates a new policy version for the
same paired trajectories. The mutation report records which faults the suite detects. This serves a
different purpose from runtime attack detection: it asks whether a policy regression would be
caught before release.

The v0.3 checker compares a runtime sequence policy with a separately authored flow model. It
searches a finite state space for the shortest failed trace, measures controlled safety and access
boundaries, and tests whether the independent model catches supported policy mutations.

The v0.4 change checker compares two sequence-policy versions and the flow model in one search. Its
state space is the union of branches reachable under either policy. This permits inspection of
downstream actions that exist only after a policy change, while the report keeps prior defects,
proposal defects, regressions, and repairs separate.
