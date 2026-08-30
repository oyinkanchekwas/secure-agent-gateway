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
from secure_agent_gateway.models import Control, Principal, RiskLevel, ToolRequest
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.registry import ToolRegistry, ToolSpec
from secure_agent_gateway.schema import FieldSpec

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
    "Control",
    "FieldSpec",
    "PairedPolicyContract",
    "PolicyEngine",
    "PolicyContractRunner",
    "Principal",
    "PrincipalCredential",
    "RiskLevel",
    "SecureAgentGateway",
    "ToolRegistry",
    "ToolRequest",
    "ToolSpec",
    "sign_request",
]

__version__ = "0.1.0"
