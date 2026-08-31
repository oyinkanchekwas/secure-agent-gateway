# Attack cases

The test suite exercises inert requests and fixture adapters.

| Case | Expected control | Verification |
| --- | --- | --- |
| Changed request after signing | Deny | HMAC comparison fails |
| Reused key and nonce | Deny | Nonce store rejects the second request |
| Duplicate request identifier | Deny | Pending call remains unchanged |
| Role lacking tool permission | Deny | Adapter call count stays zero |
| Relative path or escaped root | Deny | Path evidence identifies the argument |
| HTTP or unlisted destination | Deny | Host policy stops the call |
| Credential field in arguments | Deny | Server-owned credential path remains separate |
| Expired or changed approval | Deny | Receipt verification fails |
| Competing valid approvals | One execution | Pending-state lock admits one receipt |
| Adapter exception | Execution failure | Exception text stays out of the audit log |
| Edited audit record | Verification failure | Record hash changes |
| Over-permissive policy contract | Acceptance failure | Unsafe-action prevention falls to zero |
| Altered contract report | Attestation failure | Report digest mismatch |
| Sensitive read followed by outbound send | Deny | Evidence identifies the successful read event |
| Same actions in separate sessions | Allow | Session boundary isolates effects |
| Failed sensitive read followed by send | Allow | Failed adapters emit zero effects |
| Concurrent read and send | Deny | Session lock commits the read effect before sink policy |
| Intervening call after approval request | Deny | Session-context digest changes |
| Removed or weakened sequence rule | Acceptance failure | Trajectory mutation is killed |
| Undisclosed MCP tool | Protocol error | Adapter rejects it before gateway submission |

Paired permitted cases confirm that each control still admits a request with the required role,
fields, destination, path, rate allowance, and approval state.
