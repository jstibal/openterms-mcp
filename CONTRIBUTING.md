# Contributing to Openterms

Thanks for your interest in contributing. Openterms is open source (Apache 2.0) and we welcome contributions of all kinds.

## Getting Started

```bash
git clone https://github.com/jstibal/openterms.git
cd openterms
pip install flask pyjwt cryptography pyyaml
python run.py
```

Server starts at `http://localhost:5000`. Or use Docker:

```bash
docker compose up --build
```

## Running Tests

```bash
# All 120 tests
make test

# Or directly
python -m unittest tests.test_core tests.test_mvp3 -v
```

All tests must pass before submitting a PR.

## Code Style

- Python 3.10+
- No external linter enforced yet — keep it consistent with existing code
- Functions should have docstrings
- New endpoints need tests

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Add tests for any new functionality
3. Run `make test` and confirm all 120+ tests pass
4. Write a clear PR description explaining what changed and why
5. Keep PRs focused — one feature or fix per PR

## Areas Where Contributions Are Welcome

**Framework integrations** — LangChain callback handlers, CrewAI plugins, Anthropic SDK middleware, or any agent framework that could auto-receipt tool calls. These should be separate packages (e.g., `openterms-langchain`) that depend on the core.

**Language SDKs** — Provider verification SDKs in Python, Node, Go. The core need is: fetch JWKS keys, verify Ed25519 signatures, check receipt fields. See the `verify_receipt_by_hash` endpoint for the API contract.

**Open Receipt Specification feedback** — The ORS spec is at [github.com/jstibal/ors-spec](https://github.com/jstibal/ors-spec). Issues and PRs on the spec are highly valuable.

**Documentation** — Tutorials, integration guides, architecture docs.

**Bug reports** — File an issue with steps to reproduce.

## What Not to Submit

- Changes to the cryptographic signing pipeline without discussion first (file an issue)
- Breaking changes to the receipt schema (this needs an ORS spec discussion)
- Dependencies on paid services or non-open-source libraries

## Questions?

Open a GitHub Discussion or file an issue. We're happy to help you find the right place to contribute.
