# C# Security Audit

This read-only .NET 8 utility checks the repository for common deployment
hardening failures:

- default or placeholder credentials;
- plaintext credential assignments;
- disabled TLS verification;
- management services bound to `0.0.0.0`.

It redacts credential-like evidence and returns exit code `1` when the selected
severity threshold is met, which makes it suitable for CI or a deployment gate.

## Run

From the repository root:

```powershell
dotnet run --project security-hardening -- --path .
```

JSON output for automation:

```powershell
dotnet run --project security-hardening -- --path . --format json --fail-on high
```

Use `--fail-on critical` when you want informational and high-severity findings
reported without failing a local exploratory scan.