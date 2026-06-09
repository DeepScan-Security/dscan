"""Dashboard web server.

This module is a scaffold placeholder. The aiohttp + Jinja2 server is
built out test-first in later iterations.
"""

from __future__ import annotations

from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent / "templates"


def serve(host: str = "127.0.0.1", port: int = 4321) -> None:
    """Serve the dashboard.

    Placeholder implementation: real routing and trace rendering are
    added test-first in later iterations.
    """
    raise NotImplementedError("dashboard server is not implemented yet")
