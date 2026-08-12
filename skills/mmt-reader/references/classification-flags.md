# Classification flags

Three hidden flags control how mmtReader identifies protocols. All default to `1` (enabled), and **the standard run** leaves them at their defaults.

| Flag | Controls | Set to `0` when |
|------|----------|-----------------|
| `-x 0\|1` | IP address classification | You need speed and accept coarser results |
| `-y 0\|1` | Hostname (SNI) classification | SNI is encrypted or irrelevant to the question |
| `-z 0\|1` | Port number classification | You want MMP-only mode |

## MMP-only mode

```bash
mmtReader analyze -t <file> --json -a -s -x 0 -y 0 -z 0
```

Disables all three classifiers, leaving only MMT's protocol-machine parsing. Faster on large captures, but application-level names (Google, Salesforce, MSN) collapse into their transport protocols.

## Reporting rule

Whenever you run with any flag set to `0`, say so in the answer and name what it cost — e.g. "run with `-y 0`, so HTTPS traffic is reported as SSL rather than by hostname." An answer produced with classification disabled but presented as a full protocol breakdown is wrong even though the numbers are right.
