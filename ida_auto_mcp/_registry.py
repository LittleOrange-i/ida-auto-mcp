"""Global MCP server instance and tool decorators."""

from .mcp_server import McpServer

mcp = McpServer("ida-auto-mcp", version="1.0.1")


def tool(func):
    """Register a read-only MCP tool (always enabled)."""
    return mcp.tool(func)


def write_tool(func):
    """Register a tool that modifies the IDA database or writes files.

    Disabled unless the server is started with --allow-write.
    """
    return mcp.tool(func, group="write")


def script_tool(func):
    """Register a tool that executes arbitrary code.

    Disabled unless the server is started with --allow-script.
    """
    return mcp.tool(func, group="script")
