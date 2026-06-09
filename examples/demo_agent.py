"""A minimal example agent instrumented with dscan.

Run with::

    python examples/demo_agent.py
"""

from __future__ import annotations

import asyncio

from dscan import watch


@watch
async def my_agent(task: str) -> str:
    """A toy agent that "completes" a task."""
    await asyncio.sleep(0)
    return f"completed: {task}"


async def main() -> None:
    result = await my_agent("summarize the news")
    print(result)


if __name__ == "__main__":
    asyncio.run(main())
