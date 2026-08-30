# Attack cases

The test suite exercises inert requests and fixture adapters.

| Case | Expected control | Verification |
| --- | --- | --- |
| Changed request after signing | Deny | HMAC comparison fails |
| Reused key and nonce | Deny | Nonce store rejects the second request |
| Duplicate request identifier | Deny | Pending call remains unchanged |
| Role without tool permission | Deny | Adapter call count stays zero |
| Relative path or escaped root | Deny | Path evidence identifies the argument |
| HTTP or unlisted destination | Deny | Host policy stops the call |
| Credential field in arguments | Deny | Server-owned credential path remains separate |
| Expired or changed approval | Deny | Receipt verification fails |
| Competing valid approvals | One execution | Pending-state lock admits one receipt |
| Adapter exception | Execution failure | Exception text stays out of the audit log |
| Edited audit record | Verification failure | Record hash changes |
| Over-permissive policy contract | Acceptance failure | Unsafe-action prevention falls to zero |
| Altered contract report | Attestation failure | Report digest no longer matches |

Paired permitted cases confirm that each control still admits a request with the required role,
fields, destination, path, rate allowance, and approval state.
