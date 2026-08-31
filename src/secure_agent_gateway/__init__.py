"""Policy enforcement for coding-agent tool calls."""

from secure_agent_gateway.approvals import ApprovalAuthority, ApprovalReceipt
from secure_agent_gateway.audit import AuditLog
from secure_agent_gateway.auth import Authenticator, PrincipalCredential, sign_request
from secure_agent_gateway.contracts import (
    ContractAttestation,
    ContractAttestor,
    ContractCase,
    ContractReport,
    ContractThresholds,
    PairedPolicyContract,
    PolicyContractRunner,
)
from secure_agent_gateway.gateway import SecureAgentGateway
from secure_agent_gateway.mcp import MCPGatewayAdapter, MCPProtocolError, MCPToolCallResult
from secure_agent_gateway.model_checking import (
    BoundedCheckReport,
    BoundedCheckThresholds,
    BoundedMutationAnalyser,
    BoundedMutationOutcome,
    BoundedMutationReport,
    BoundedRelationalChecker,
    CheckedDecision,
    FlowRequirement,
    InvocationTemplate,
    ModelCounterexample,
    RelationalBoundary,
)
from secure_agent_gateway.models import Control, Principal, RiskLevel, ToolRequest
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.policy_change import (
    PolicyChangeAttestation,
    PolicyChangeAttestor,
    PolicyChangeChecker,
    PolicyChangeDecision,
    PolicyChangeReport,
    PolicyChangeWitness,
)
from secure_agent_gateway.probe_synthesis import (
    CausalContribution,
    ContrastProbe,
    ProbeSynthesisGap,
    ProbeSynthesisReport,
    RequirementProbeSynthesiser,
    probe_suite_digest,
)
from secure_agent_gateway.registry import ToolRegistry, ToolSpec
from secure_agent_gateway.schema import FieldSpec
from secure_agent_gateway.sqlite_store import SQLiteSessionStore
from secure_agent_gateway.session import (
    InMemorySessionStore,
    SequencePolicy,
    SequenceRule,
    SessionEvent,
    SessionSnapshot,
    SessionStore,
)
from secure_agent_gateway.trajectory import (
    MutationOutcome,
    MutationReport,
    PairedTrajectoryContract,
    SequenceMutationAnalyser,
    TrajectoryCase,
    TrajectoryCaseResult,
    TrajectoryContractRunner,
    TrajectoryReport,
    TrajectoryThresholds,
)

__all__ = [
    "ContractAttestation",
    "ContractAttestor",
    "ContractCase",
    "ContractReport",
    "ContractThresholds",
    "ApprovalAuthority",
    "ApprovalReceipt",
    "AuditLog",
    "Authenticator",
    "BoundedCheckReport",
    "BoundedCheckThresholds",
    "BoundedMutationAnalyser",
    "BoundedMutationOutcome",
    "BoundedMutationReport",
    "BoundedRelationalChecker",
    "CheckedDecision",
    "CausalContribution",
    "Control",
    "ContrastProbe",
    "FieldSpec",
    "FlowRequirement",
    "InMemorySessionStore",
    "InvocationTemplate",
    "MCPGatewayAdapter",
    "MCPProtocolError",
    "MCPToolCallResult",
    "MutationOutcome",
    "MutationReport",
    "ModelCounterexample",
    "PairedPolicyContract",
    "PairedTrajectoryContract",
    "PolicyEngine",
    "PolicyChangeAttestation",
    "PolicyChangeAttestor",
    "PolicyChangeChecker",
    "PolicyChangeDecision",
    "PolicyChangeReport",
    "PolicyChangeWitness",
    "PolicyContractRunner",
    "ProbeSynthesisGap",
    "ProbeSynthesisReport",
    "Principal",
    "PrincipalCredential",
    "RiskLevel",
    "RelationalBoundary",
    "RequirementProbeSynthesiser",
    "SecureAgentGateway",
    "SequenceMutationAnalyser",
    "SequencePolicy",
    "SequenceRule",
    "SessionEvent",
    "SessionSnapshot",
    "SessionStore",
    "SQLiteSessionStore",
    "ToolRegistry",
    "ToolRequest",
    "ToolSpec",
    "TrajectoryCase",
    "TrajectoryCaseResult",
    "TrajectoryContractRunner",
    "TrajectoryReport",
    "TrajectoryThresholds",
    "probe_suite_digest",
    "sign_request",
]

__version__ = "0.5.0"
