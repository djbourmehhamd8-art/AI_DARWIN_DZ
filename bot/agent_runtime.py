"""Bounded, permission-aware execution foundation for DARWIN's agent system.

This module deliberately does not execute shell commands, evaluate model-generated
code, or grant tools implicit authority. Callers provide an explicit tool registry
and an explicit approval callback for operations that need human consent.
"""
from __future__ import annotations

import json
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Tuple


_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


class AgentPolicyError(ValueError):
    """A plan or tool request violates the runtime policy."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    handler: Callable[[Mapping[str, Any]], Any]
    description: str = ""
    requires_approval: bool = False
    max_argument_bytes: int = 16_384

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.name):
            raise AgentPolicyError("invalid tool name")
        if not callable(self.handler):
            raise AgentPolicyError("tool handler must be callable")
        if not 1 <= int(self.max_argument_bytes) <= 65_536:
            raise AgentPolicyError("tool argument limit is out of range")


@dataclass(frozen=True)
class AgentStep:
    tool: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    purpose: str = ""


@dataclass(frozen=True)
class AgentPlan:
    steps: Tuple[AgentStep, ...]
    task_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])


@dataclass(frozen=True)
class StepResult:
    index: int
    tool: str
    status: str
    output: Any = None
    error: str = ""
    elapsed_ms: int = 0


@dataclass(frozen=True)
class AgentResult:
    task_id: str
    status: str
    steps: Tuple[StepResult, ...]
    elapsed_ms: int


class AgentRuntime:
    """Sequential agent tool runner with explicit allowlisting and bounded plans."""

    def __init__(
        self,
        tools: Iterable[ToolSpec] = (),
        *,
        max_steps: int = 8,
        max_task_seconds: float = 45.0,
        max_plan_bytes: int = 65_536,
        approval: Optional[Callable[[AgentStep, ToolSpec], bool]] = None,
    ) -> None:
        if not 1 <= int(max_steps) <= 32:
            raise ValueError("max_steps must be between 1 and 32")
        if not 1 <= float(max_task_seconds) <= 300:
            raise ValueError("max_task_seconds must be between 1 and 300")
        if not 1_024 <= int(max_plan_bytes) <= 262_144:
            raise ValueError("max_plan_bytes is out of range")
        self.max_steps = int(max_steps)
        self.max_task_seconds = float(max_task_seconds)
        self.max_plan_bytes = int(max_plan_bytes)
        self.approval = approval
        self._tools: Dict[str, ToolSpec] = {}
        self._lock = threading.RLock()
        for tool in tools:
            self.register(tool)

    def register(self, tool: ToolSpec) -> None:
        if not isinstance(tool, ToolSpec):
            raise TypeError("tool must be a ToolSpec")
        with self._lock:
            if tool.name in self._tools:
                raise AgentPolicyError("duplicate tool registration")
            self._tools[tool.name] = tool

    def tool_names(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._tools))

    def run(self, plan: AgentPlan, cancel: Optional[threading.Event] = None) -> AgentResult:
        started = time.monotonic()
        results = []
        if not isinstance(plan, AgentPlan):
            raise AgentPolicyError("invalid plan")
        if not isinstance(plan.task_id, str) or not plan.task_id or len(plan.task_id) > 64:
            raise AgentPolicyError("invalid task id")
        if not isinstance(plan.steps, tuple) or not plan.steps:
            raise AgentPolicyError("plan must contain at least one step")
        if len(plan.steps) > self.max_steps:
            raise AgentPolicyError("plan exceeds the step limit")
        if any(not isinstance(step, AgentStep) or not isinstance(step.tool, str) or not _NAME.fullmatch(step.tool)
               for step in plan.steps):
            raise AgentPolicyError("plan contains an invalid step")
        try:
            encoded = json.dumps(
                [{"tool": s.tool, "arguments": s.arguments, "purpose": s.purpose} for s in plan.steps],
                ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise AgentPolicyError("plan arguments must be JSON-compatible") from exc
        if len(encoded) > self.max_plan_bytes:
            raise AgentPolicyError("plan exceeds the size limit")

        for index, step in enumerate(plan.steps, 1):
            elapsed = time.monotonic() - started
            if cancel is not None and cancel.is_set():
                return self._result(plan.task_id, "cancelled", results, started)
            if elapsed >= self.max_task_seconds:
                results.append(StepResult(index, getattr(step, "tool", ""), "timeout", error="task time budget exceeded"))
                return self._result(plan.task_id, "timeout", results, started)
            if not isinstance(step, AgentStep):
                results.append(StepResult(index, "", "rejected", error="invalid step"))
                return self._result(plan.task_id, "rejected", results, started)
            with self._lock:
                spec = self._tools.get(step.tool)
            if spec is None:
                results.append(StepResult(index, step.tool, "rejected", error="tool is not allowlisted"))
                return self._result(plan.task_id, "rejected", results, started)
            try:
                args = dict(step.arguments)
                arg_bytes = json.dumps(args, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            except (TypeError, ValueError):
                results.append(StepResult(index, step.tool, "rejected", error="invalid tool arguments"))
                return self._result(plan.task_id, "rejected", results, started)
            if len(arg_bytes) > spec.max_argument_bytes:
                results.append(StepResult(index, step.tool, "rejected", error="tool arguments exceed the size limit"))
                return self._result(plan.task_id, "rejected", results, started)
            if spec.requires_approval:
                approved = False
                if self.approval is not None:
                    try:
                        approved = bool(self.approval(step, spec))
                    except Exception:
                        approved = False
                if not approved:
                    results.append(StepResult(index, step.tool, "approval_required", error="explicit approval was not granted"))
                    return self._result(plan.task_id, "approval_required", results, started)
            step_started = time.monotonic()
            try:
                output = spec.handler(args)
                # Ensure tool results are serializable and bounded before returning them
                # to a caller that may display or persist the result.
                rendered = json.dumps(output, ensure_ascii=False, default=str)
                if len(rendered.encode("utf-8")) > 65_536:
                    raise AgentPolicyError("tool output exceeds the result size limit")
                output = json.loads(rendered)
                results.append(StepResult(index, step.tool, "completed", output=output,
                                          elapsed_ms=int((time.monotonic() - step_started) * 1000)))
            except Exception as exc:
                # Do not expose arbitrary exception messages; they may contain credentials.
                results.append(StepResult(index, step.tool, "failed", error=type(exc).__name__,
                                          elapsed_ms=int((time.monotonic() - step_started) * 1000)))
                return self._result(plan.task_id, "failed", results, started)
        return self._result(plan.task_id, "completed", results, started)

    @staticmethod
    def _result(task_id: str, status: str, results: list, started: float) -> AgentResult:
        return AgentResult(task_id, status, tuple(results), int((time.monotonic() - started) * 1000))
