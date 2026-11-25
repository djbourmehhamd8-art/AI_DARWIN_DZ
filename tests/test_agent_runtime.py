import threading
import unittest

from bot.agent_runtime import (
    AgentPlan, AgentRuntime, AgentStep, AgentPolicyError, ToolSpec,
)


class AgentRuntimeTests(unittest.TestCase):
    def test_runs_allowlisted_tools_in_order(self):
        seen = []
        runtime = AgentRuntime([
            ToolSpec("lookup", lambda args: seen.append(args["q"]) or {"hits": 2}),
            ToolSpec("summarize", lambda args: "done"),
        ])
        result = runtime.run(AgentPlan((
            AgentStep("lookup", {"q": "example"}),
            AgentStep("summarize", {}),
        )))
        self.assertEqual(result.status, "completed")
        self.assertEqual(seen, ["example"])
        self.assertEqual([x.status for x in result.steps], ["completed", "completed"])

    def test_unknown_tool_is_rejected(self):
        result = AgentRuntime().run(AgentPlan((AgentStep("shell", {"cmd": "id"}),)))
        self.assertEqual(result.status, "rejected")
        self.assertIn("allowlisted", result.steps[0].error)

    def test_sensitive_tool_requires_explicit_approval(self):
        called = []
        runtime = AgentRuntime([ToolSpec("delete_record", lambda a: called.append(True), requires_approval=True)])
        result = runtime.run(AgentPlan((AgentStep("delete_record", {}),)))
        self.assertEqual(result.status, "approval_required")
        self.assertEqual(called, [])

    def test_approval_callback_can_authorize_sensitive_tool(self):
        runtime = AgentRuntime(
            [ToolSpec("sensitive", lambda a: "approved", requires_approval=True)],
            approval=lambda step, spec: True,
        )
        result = runtime.run(AgentPlan((AgentStep("sensitive", {}),)))
        self.assertEqual(result.status, "completed")

    def test_step_limit_is_enforced(self):
        runtime = AgentRuntime([ToolSpec("noop", lambda a: None)], max_steps=1)
        with self.assertRaises(AgentPolicyError):
            runtime.run(AgentPlan((AgentStep("noop"), AgentStep("noop"))))

    def test_argument_size_is_enforced(self):
        runtime = AgentRuntime([ToolSpec("small", lambda a: None, max_argument_bytes=8)])
        result = runtime.run(AgentPlan((AgentStep("small", {"x": "a" * 30}),)))
        self.assertEqual(result.status, "rejected")
        self.assertIn("size", result.steps[0].error)

    def test_cancellation_stops_before_first_tool(self):
        called = []
        event = threading.Event()
        event.set()
        runtime = AgentRuntime([ToolSpec("noop", lambda a: called.append(True))])
        result = runtime.run(AgentPlan((AgentStep("noop"),)), cancel=event)
        self.assertEqual(result.status, "cancelled")
        self.assertEqual(called, [])

    def test_handler_error_is_not_exposed(self):
        runtime = AgentRuntime([ToolSpec("bad", lambda a: (_ for _ in ()).throw(RuntimeError("secret=abc")))])
        result = runtime.run(AgentPlan((AgentStep("bad"),)))
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.steps[0].error, "RuntimeError")
        self.assertNotIn("abc", result.steps[0].error)

    def test_invalid_plan_step_is_rejected_cleanly(self):
        with self.assertRaises(AgentPolicyError):
            AgentRuntime().run(AgentPlan((object(),)))

    def test_duplicate_tools_are_refused(self):
        runtime = AgentRuntime([ToolSpec("one", lambda a: None)])
        with self.assertRaises(AgentPolicyError):
            runtime.register(ToolSpec("one", lambda a: None))


if __name__ == "__main__":
    unittest.main()
