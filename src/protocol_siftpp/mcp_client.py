"""Async bridge to our read-only forensic MCP server.

Spawns the server over stdio, lists its tools (converted to Anthropic tool
schemas), and exposes `call()` to invoke a tool and get the parsed JSON result.
"""

from __future__ import annotations

import json
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class McpForensics:
    """Async context manager holding an open MCP session to the SIFT++ server."""

    def __init__(self, params: StdioServerParameters):
        self.params = params
        self.session: ClientSession | None = None
        self.anthropic_tools: list[dict[str, Any]] = []
        self._stdio_cm = None
        self._session_cm = None

    async def __aenter__(self) -> "McpForensics":
        self._stdio_cm = stdio_client(self.params)
        read, write = await self._stdio_cm.__aenter__()
        self._session_cm = ClientSession(read, write)
        self.session = await self._session_cm.__aenter__()
        await self.session.initialize()
        listed = await self.session.list_tools()
        self.anthropic_tools = [
            {
                "name": t.name,
                "description": t.description or "",
                "input_schema": t.inputSchema or {"type": "object", "properties": {}},
            }
            for t in listed.tools
        ]
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._session_cm is not None:
            await self._session_cm.__aexit__(*exc)
        if self._stdio_cm is not None:
            await self._stdio_cm.__aexit__(*exc)

    async def call(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        assert self.session is not None, "session not started"
        result = await self.session.call_tool(name, arguments or {})
        text = "".join(getattr(c, "text", "") for c in result.content)
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return {"result_text": text, "exit_code": 1 if result.isError else 0}
