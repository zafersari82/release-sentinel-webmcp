"""OpenTelemetry instrumentation for Release Sentinel control-plane paths."""

from .tracing import current_trace_id, safe_span, set_safe_attributes, tracer

__all__ = ["current_trace_id", "safe_span", "set_safe_attributes", "tracer"]
