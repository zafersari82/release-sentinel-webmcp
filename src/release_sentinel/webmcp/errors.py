from __future__ import annotations


class WebMCPServiceError(RuntimeError):
    """A bounded WebMCP failure with an optional concrete recovery action."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 409,
        next_action: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.next_action = next_action

    def to_payload(self) -> dict[str, str]:
        payload = {"code": self.code, "message": str(self)}
        if self.next_action:
            payload["next_action"] = self.next_action
        return payload
