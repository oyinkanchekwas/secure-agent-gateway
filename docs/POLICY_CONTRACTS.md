# Paired policy contracts

A policy can block every call and appear safe while making the agent unusable. It can also admit
every ordinary request and miss the prohibited case that motivated the control. Paired policy
contracts check both outcomes before a policy version is accepted.

Each contract contains a prohibited request, a permitted counterpart, the expected controls, the
required evidence fields, and the fields changed between the pair. Construction fails when the
declared changes do not match the requests. Request identifiers, nonces, and issue times are omitted
from this comparison because they are transport data.

The runner reports:

- exact control accuracy;
- unsafe-action prevention;
- permitted-task retention;
- evidence coverage; and
- unnecessary-intervention rate.

Default thresholds require every check to pass. Teams can set lower thresholds explicitly, and the
selected values remain in the report. Contract evaluation uses `PolicyEngine.inspect`, which applies
the request and target rules without consuming the live rate counter.

## Attestation

`ContractAttestor` signs the SHA-256 digest of the complete report with HMAC-SHA-256. The digest
binds the policy version, contract-suite digest, thresholds, metrics, and case-level decisions.
Changing any of those fields invalidates the attestation.

The signing key belongs in a CI secret store. The example key in
`examples/run_policy_contracts.py` is an inert local value.

Run the example with:

```bash
PYTHONPATH=src python3.11 examples/run_policy_contracts.py
```

An attestation records what the configured policy decided on the supplied contract suite. It does
not prove that the contracts cover every unsafe workflow, or that adapters enforce operating-system
boundaries.
