# dscan

An open source agent security suite.

```bash
pip install dscan
```

```python
from dscan import watch

@watch
async def my_agent(task: str):
    ...  # your agent code unchanged
```

```bash
dscan dashboard  # localhost:4321
```

## What it does

`dscan` wraps your agent so you can see and secure what it does:

- **Tracer** — records inputs, outputs, and tool calls.
- **Redactor** — strips sensitive data from traces.
- **Scanner** — analyzes traces for security issues.
- **Dashboard** — a local web UI to inspect everything.

Wrap any agent function with `@watch` and your code runs unchanged.

## Development

```bash
pip install -e ".[dev]"
pytest
```

Built test-first (TDD) throughout — tests are written alongside every
feature, never after.

## License

MIT
