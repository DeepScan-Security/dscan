"""dscan command-line interface."""

from __future__ import annotations

import click

from dscan import __version__


@click.group()
@click.version_option(__version__, prog_name="dscan")
def main() -> None:
    """dscan — an open source agent security suite."""


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Host to bind.")
@click.option("--port", default=4321, show_default=True, help="Port to bind.")
def dashboard(host: str, port: int) -> None:
    """Launch the local dashboard."""
    from dscan.dashboard.server import serve

    serve(host=host, port=port)


if __name__ == "__main__":
    main()
