# Contributing to Anonix Gateway

Thank you for contributing to **Anonix Gateway**!

## Development Setup

### Backend
```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1

pip install -e ".[dev]"
```

### Admin Console
```bash
cd console
npm install
npm run build
```

## Quality Checks
Before opening a pull request, run all checks:

```bash
ruff check src tests
mypy src
pytest -v
```

## Design Principles
- **Fail closed:** Missing or invalid authentication (`401`), unauthorized groups/policies (`403`), and masking/format errors (`502` on proxy) must never leak raw payloads.
- **Zero-PII persistence:** Never log or store raw or masked payload field values in databases or audit tables.
- **No hardcoded policies or credentials:** Every masking rule comes from explicit `MaskingPolicy` definitions; every secret is generated or injected per deployment.
