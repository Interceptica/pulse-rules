# pulse-rules

Community security detection rules for [Pulse](https://pulse.io) SAST engine.

**License:** Apache 2.0 — use freely, contribute openly.

## Structure

```
pulse-default/
├── python/security/       # SQL injection, XSS, SSRF, etc.
├── java/security/         # Spring, JDBC, deserialization, etc.
├── javascript/security/   # Express, Node, prototype pollution, etc.
├── typescript/security/   # Same as JS + TS-specific patterns
└── go/security/           # SQL injection, command injection, etc.
```

## Rule Format

Rules use the Pulse YAML format (ast-grep compatible):

```yaml
id: pulse.python.security.sql-injection-f-string
language: python
severity: error
message: |
  SQL injection via f-string interpolation.
  Use parameterized queries instead.
rule:
  pattern: $CURSOR.execute($QUERY)
  has:
    kind: formatted_string
metadata:
  cwe: ["CWE-89"]
  owasp: ["A03:2021"]
  pulse.confidence: HIGH
test:
  positive:
    - |
      cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
  negative:
    - |
      cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

## Contributing

We welcome community contributions! See [CONTRIBUTING.md](CONTRIBUTING.md).

- Every PR runs 8 automated quality gates
- Review SLA: 7 days

## Quality Gates

All rules must pass:
1. Schema validation
2. Test positive fires
3. Test negative clean
4. Benchmark FP rate check
5. Metadata completeness
6. Message quality
7. Regression check
8. Snapshot test
