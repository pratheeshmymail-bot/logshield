# LogShield

Offline-first redaction of common secrets and personal data from text logs.

**LogShield runs locally. It does not call an AI service, upload files, or require an API key.**

## Features

- Redacts common API-key formats (OpenAI-style, GitHub, AWS access key IDs, Slack tokens).
- Redacts bearer-token values and password/secret assignments.
- Redacts email addresses.
- Reads from a file or standard input.
- Writes to standard output or a separate output file.
- Optional in-place editing with a `.bak` backup.
- Reports redaction counts without printing matched secret values.

## Requirements

- Python 3.9 or newer

## Install from a local checkout

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

python -m pip install -e .
```

## Usage

Redact a file to the terminal:

```bash
logshield application.log --summary
```

Write a cleaned copy:

```bash
logshield application.log --output application.cleaned.log --summary
```

Read from a pipeline:

```bash
cat application.log | logshield --summary
```

Replace a file after creating `application.log.bak`:

```bash
logshield application.log --in-place --summary
```

## JSON-aware redaction

Use `--json` with valid JSON input. LogShield redacts values under sensitive
keys such as `password`, `api_key`, `access_token`, `authorization`, and
`private_key`, as well as recognized secret patterns and email addresses
inside string values. It preserves JSON structure and data types, but
normalizes formatting and whitespace.

```bash
logshield application.json --json --output application.cleaned.json --summary
```

Invalid JSON is rejected rather than silently treated as plain text.

## Additional detections (v0.3.0)

The text scanner now also checks for JWT-shaped strings, Google API keys,
common database connection URL passwords, and PEM private-key blocks.
These checks are heuristic and may miss unknown formats or produce false
positives. Review output before sharing it.

## Custom rules

Create a JSON array with a name and Python regular expression for each rule:

```json
[
  {"name": "employee_id", "pattern": "EMP-[0-9]{5}", "replacement": "[EMPLOYEE_ID]"}
]
```

Run with `--rules custom-rules.json`:

```bash
logshield application.log --rules custom-rules.json --summary
logshield application.json --json --rules custom-rules.json --output cleaned.json
```

Custom regexes are trusted local configuration. Avoid complex patterns from
untrusted sources because poorly designed regular expressions can be slow.

## Run tests

```bash
python -m pip install pytest
python -m pytest
```

## Important limitations

LogShield is a best-effort text filter, not a guarantee that all sensitive information is removed. It can miss unknown or unusual secret formats and can occasionally redact harmless text. Review cleaned output before sharing it. Never use it as the only control for protecting credentials.

The first release handles text files only. It does not parse binary logs, archives, databases, or structured formats such as JSON in a schema-aware way.

## Roadmap

- [x] JSON-aware redaction that preserves valid JSON
- [x] Configurable custom patterns
- [x] Additional cloud-provider and database credential patterns
- [ ] GitHub Actions CI across supported Python versions
- [ ] Optional HTML summary report
- [ ] Windows/macOS/Linux packaged releases

## Contributing

Bug reports and pull requests are welcome. Please never submit real credentials, private logs, or personal data in issues or tests. Use synthetic examples.

## Security

If you find a security issue, do not publish real secrets or exploit details in a public issue. Open a private security report through the repository's GitHub security page once enabled.
