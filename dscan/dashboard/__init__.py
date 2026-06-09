"""dscan dashboard — local web UI for inspecting agent traces.

This package holds the dashboard's aiohttp server (:mod:`dscan.dashboard.server`)
and its single HTML template. The server reads NDJSON traces from
``~/.dscan/traces`` (or ``DSCAN_TRACES_DIR``) and exposes them at
``localhost:4321`` over a small JSON API plus a self-contained page that
renders sessions, redacted tool calls, and trail findings. It depends
only on ``aiohttp`` and ``aiofiles``; there are no external front-end
dependencies.
"""
