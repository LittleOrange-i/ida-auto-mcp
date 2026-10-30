"""Snapshot of the metadata the server advertises to MCP clients: server
instructions and every tool's name, title, description, parameters and
annotations, with all permission groups enabled.

After an intentional change, regenerate tests/tool_metadata.json with:

    IDA_AUTO_MCP_UPDATE_SNAPSHOT=1 python -m unittest tests.test_tool_metadata
"""

import json
import os
import unittest
from pathlib import Path

from ida_auto_mcp import tools  # noqa: F401 - registers the tools
from ida_auto_mcp._registry import mcp

SNAPSHOT = Path(__file__).with_name("tool_metadata.json")
PROTOCOL_VERSION = "2025-11-25"


def served_metadata() -> dict:
    saved = (set(mcp.enabled_groups), mcp.protocol_version)
    mcp.enabled_groups.update({"write", "script"})
    try:
        initialize = mcp.dispatch(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "snapshot", "version": "1"},
                },
            }
        )["result"]
        tools_list = mcp.dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})[
            "result"
        ]
    finally:
        mcp.enabled_groups.clear()
        mcp.enabled_groups.update(saved[0])
        mcp.protocol_version = saved[1]
    initialize["serverInfo"]["version"] = "<version>"
    return {"initialize": initialize, "tools/list": tools_list}


class ToolMetadataSnapshotTest(unittest.TestCase):
    def test_metadata_matches_snapshot(self):
        current = served_metadata()
        if os.environ.get("IDA_AUTO_MCP_UPDATE_SNAPSHOT") == "1":
            SNAPSHOT.write_text(
                json.dumps(current, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        expected = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        self.assertEqual(
            current,
            expected,
            "The advertised tool metadata changed. If that is intended, "
            "regenerate tests/tool_metadata.json (see this module's docstring).",
        )

    def test_every_tool_has_annotations(self):
        tools_list = served_metadata()["tools/list"]["tools"]
        self.assertEqual(len(tools_list), 55)
        for tool in tools_list:
            self.assertIn("readOnlyHint", tool["annotations"], tool["name"])
            self.assertTrue(tool["title"], tool["name"])


if __name__ == "__main__":
    unittest.main()
