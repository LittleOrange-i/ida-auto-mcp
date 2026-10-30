"""Tests for run_script's REPL behavior. No IDA installation is needed:
the scripts use plain Python.

    python -m unittest discover -s tests -v
"""

import unittest

from ida_auto_mcp import tools  # noqa: F401 - registers the tools
from ida_auto_mcp._registry import mcp
from ida_auto_mcp.session import get_manager


def run(script: str) -> dict:
    response = mcp.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "run_script", "arguments": {"script": script}},
        }
    )
    return response["result"]


class RunScriptTests(unittest.TestCase):
    def setUp(self):
        self._saved = (set(mcp.enabled_groups), mcp.tool_timeout)
        mcp.enabled_groups.add("script")
        get_manager().generation += 1  # start from empty variables

    def tearDown(self):
        mcp.enabled_groups.clear()
        mcp.enabled_groups.update(self._saved[0])
        mcp.tool_timeout = self._saved[1]

    def test_variables_persist_and_final_expression_is_returned(self):
        self.assertIsNone(run("answer = 41")["structuredContent"]["result"])
        result = run("print('computing')\nanswer + 1")["structuredContent"]
        self.assertEqual(result["result"], 42)
        self.assertEqual(result["output"], "computing\n")

    def test_variables_are_dropped_when_the_database_changes(self):
        run("answer = 41")
        get_manager().generation += 1
        result = run("answer")
        self.assertTrue(result["isError"])
        self.assertIn("NameError", result["structuredContent"]["error"])

    def test_non_json_result_is_returned_as_repr(self):
        result = run("object")["structuredContent"]
        self.assertEqual(result["result"], "<class 'object'>")

    def test_traceback_shows_only_the_script(self):
        result = run("def f():\n    return 1 / 0\n\nf()")
        self.assertTrue(result["isError"])
        error = result["structuredContent"]["error"]
        self.assertIn('File "<script>", line 2, in f', error)
        self.assertIn("return 1 / 0", error)
        self.assertIn("ZeroDivisionError", error)
        self.assertNotIn("tools.py", error)

    def test_syntax_error_is_reported(self):
        result = run("def broken(:\n    pass")
        self.assertTrue(result["isError"])
        self.assertIn("SyntaxError", result["structuredContent"]["error"])

    def test_exit_does_not_stop_the_server(self):
        result = run("raise SystemExit(3)")
        self.assertTrue(result["isError"])
        self.assertIn("SystemExit(3)", result["structuredContent"]["error"])
        self.assertFalse(run("1 + 1")["isError"])

    def test_bare_except_cannot_swallow_the_time_limit(self):
        mcp.tool_timeout = 0.2
        result = run(
            "try:\n"
            "    while True:\n"
            "        pass\n"
            "except BaseException:\n"
            "    pass\n"
            "'swallowed'"
        )
        self.assertTrue(result["isError"])
        self.assertIn("timed out", result["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
