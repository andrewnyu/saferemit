"""A verification trace: every check the gateway ran, in order, with its outcome.

The UI renders this step by step, so judges (and OFWs) can see exactly why a
payment went through or was stopped.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class Rejected(Exception):
    """Stops the pipeline. `code` is a stable machine-readable error code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class StepUpRequired(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass
class Trace:
    steps: list[dict] = field(default_factory=list)

    def passed(self, step: str, label: str, detail: str = "") -> None:
        self.steps.append({"step": step, "label": label, "result": "pass", "detail": detail})

    def failed(self, step: str, label: str, detail: str, code: str, stop: bool = True) -> None:
        self.steps.append({"step": step, "label": label, "result": "fail", "detail": detail, "code": code})
        if stop:
            raise Rejected(code, detail)

    def pending(self, step: str, label: str, detail: str) -> None:
        self.steps.append({"step": step, "label": label, "result": "pending", "detail": detail})

    def skipped(self, step: str, label: str, detail: str = "not run") -> None:
        self.steps.append({"step": step, "label": label, "result": "skipped", "detail": detail})

    def first_failure(self) -> dict | None:
        return next((s for s in self.steps if s["result"] == "fail"), None)

    def to_list(self) -> list[dict]:
        return list(self.steps)
