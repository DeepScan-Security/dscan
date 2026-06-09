"""dscan — an open source agent security suite.

Wrap your agent with :func:`watch` to trace, redact, and scan its
behavior, then inspect everything in a local dashboard::

    from dscan import watch

    @watch
    async def my_agent(task: str):
        ...  # your agent code unchanged

    # then, from the shell:
    # dscan dashboard  # localhost:4321
"""

from dscan.watcher import watch

__version__ = "0.3.0"

__all__ = ["watch", "__version__"]
