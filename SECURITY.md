# Security policy

## Supported version

Security fixes are applied to the current `0.4.x` line while the repository remains in private
development.

## Reporting

Use GitHub private vulnerability reporting for suspected security faults. Include the affected
module, the request path, expected control, observed control, and a minimal inert reproduction.

Do not include live credentials, private logs, customer data, or working exploit targets. Revoke a
credential through its provider before reporting any accidental exposure.

## Operator responsibilities

Keep request-signing and approval-signing keys outside source control. Give adapters their own
restricted service identities. Review tool schemas and destination rules before registration.
Store audit files where agent processes cannot edit or remove them.
