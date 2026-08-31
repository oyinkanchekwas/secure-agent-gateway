# Contributing

Open an issue before changing the request contract, control meanings, approval format, or audit
record structure. A proposed change should include its failure case and a focused regression test.

Run:

```bash
make PYTHON=python3.11 check
```

Use inert fixtures. Exclude credentials, private service addresses, copied production logs, and
payloads from real users.
