# ASM SaaS - Project Rules

## Project
- ASM SaaS: Attack Surface Management tool. Discovers a domain's subdomains,
  live hosts, open ports, TLS and header issues, risk-scores them, and later
  monitors changes.
- Build in phases. Only build what the current prompt asks. Never start the
  next phase on your own.

## Stack
- v1: Python 3.11+, httpx, dnspython, argparse, pytest, ruff
- Later phases, only when a prompt says so: FastAPI, PostgreSQL, Next.js
- Never add a dependency without asking me first and explaining why

## Code quality
- Clear, simple, commented code a student can explain. No clever one-liners.
- Type hints and docstrings on every function; small functions, one job each
- Use logging, not print (except CLI output)
- Tests for all logic; tests never touch the network (use mocks and fixtures)
- Before saying "done": run pytest and ruff check . and show the results

## Security (non-negotiable)
- Validate all user input
- Every network call has a timeout and error handling
- No secrets or API keys in code or git; use env vars, keep .env in .gitignore
- Only scan targets the user owns or has written permission to test
- Respect rate limits; never evade bot protection, WAFs or rate limiting
- Active scanning (ports, HTTP probing) only in steps that explicitly allow it

## Workflow
- Always produce an implementation plan first and wait for my approval
- If something is unclear, ask instead of guessing
- After each step, update docs/LEARNING_NOTES.md: plain-English explanation
  of new files plus 5 interview questions with answers
- End every task with: file tree, commands run, test results, open questions
