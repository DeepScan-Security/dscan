# dscan — Claude Code Instructions

## Workflow rules
- Never ask "want me to do X, or move to the next prompt?" — just do X
- Never pause for permission mid-task. Complete the full prompt, then stop.
- If you find a coverage gap, fix it. Don't flag it and wait.
- If tests fail, fix them. Don't report the failure and ask what to do.
- Commit only when explicitly told to commit.

## TDD rules
- Tests first or alongside — never after
- Every new function needs tests before moving on
- Coverage must stay ≥ 80% at all times — fix gaps immediately

## Code style
- Python 3.11+
- Async throughout (use asyncio, aiofiles)
- Use inspect.iscoroutinefunction not asyncio.iscoroutinefunction
- Type hints on all public functions
- No print() — use rich console for all output

## What not to do
- Do not ask clarifying questions mid-prompt — use best judgment
- Do not summarise what you just did at the end — just stop
- Do not offer alternatives unless explicitly asked
- Do not start background tasks (dashboard servers etc) during test runs or coverage checks
- Do not leave background processes running after a prompt completes
