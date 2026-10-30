"""Checks that the package and plugin metadata agree. No IDA installation is
needed.

    python -m unittest discover -s tests -v
"""

import json
import re
import unittest
from pathlib import Path

from ida_auto_mcp._registry import mcp

ROOT = Path(__file__).resolve().parent.parent


def read_json(*parts: str) -> dict:
    return json.loads(ROOT.joinpath(*parts).read_text(encoding="utf-8"))


class MetadataTests(unittest.TestCase):
    def test_versions_agree(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        version = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
        self.assertEqual(mcp.version, version, "ida_auto_mcp/_registry.py")
        self.assertEqual(
            read_json(".claude-plugin", "plugin.json")["version"],
            version,
            ".claude-plugin/plugin.json",
        )

    def test_marketplace_lists_the_plugin_at_the_root(self):
        plugin = read_json(".claude-plugin", "plugin.json")
        marketplace = read_json(".claude-plugin", "marketplace.json")
        self.assertEqual(
            [(p["name"], p["source"]) for p in marketplace["plugins"]],
            [(plugin["name"], "./")],
        )


if __name__ == "__main__":
    unittest.main()
