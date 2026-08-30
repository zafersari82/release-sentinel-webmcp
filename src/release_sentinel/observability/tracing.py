from __future__ import annotations

from release_sentinel import __version__

import os
from contextlib import contextmanager
from typing import Any, Iterator, Mapping

from opentelemetry import trace
from opentelemetry.propagators.textmap import Getter, Setter
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

_ALLOWED_ATTRIBUTES = frozenset(
    {
        "component",
        "agent_id",
        "agent_role",
        "decision_authority",
        "evidence_authority",
        "verdict",
        "agent_influence",
        "llm_present",
    }
)
_MAX_STRING_VALUE = 96
_PROVIDER_INITIALIZED = False
_PROVIDER = None


class _HeaderSetter(Setter[dict[str, str]]):
    def set(self, carrier: dict[str, str], key: str, value: str) -> None:
        carrier[key] = value


class _HeaderGetter(Getter[Mapping[str, str]]):
    def get(self, carrier: Mapping[str, str], key: str) -> list[str] | None:
        value = carrier.get(key) or carrier.get(key.lower()) or carrier.get(key.title())
        return [value] if value is not None else None

    def keys(self, carrier: Mapping[str, str]) -> list[str]:
        return list(carrier.keys())


_SETTER = _HeaderSetter()
_GETTER = _HeaderGetter()


def _configure_provider() -> None:
    """Install an SDK provider once and optionally export to a standard OTLP collector.

    Export failures are intentionally outside release authority. The SDK remains active
    even when no exporter is configured so local integration tests can prove W3C trace
    propagation without requiring an observability backend.
    """
    global _PROVIDER_INITIALIZED, _PROVIDER
    if _PROVIDER_INITIALIZED:
        return
    _PROVIDER_INITIALIZED = True
    try:
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider

        existing = trace.get_tracer_provider()
        if existing.__class__.__name__ == "ProxyTracerProvider":
            provider = TracerProvider(resource=Resource.create({"service.name": "release-sentinel"}))
            trace.set_tracer_provider(provider)
            _PROVIDER = provider
        else:
            _PROVIDER = existing

        endpoint_configured = bool(
            os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
            or os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        )
        if endpoint_configured and hasattr(_PROVIDER, "add_span_processor"):
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
                from opentelemetry.sdk.trace.export import BatchSpanProcessor

                _PROVIDER.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
            except Exception:
                # Observability is explicitly non-authoritative. Misconfiguration must
                # never alter or suppress a release verdict.
                pass
    except Exception:
        _PROVIDER = None


def add_span_processor(processor: Any) -> bool:
    """Test/embedding hook. Returns False when the active provider is not an SDK provider."""
    _configure_provider()
    if _PROVIDER is None or not hasattr(_PROVIDER, "add_span_processor"):
        return False
    try:
        _PROVIDER.add_span_processor(processor)
        return True
    except Exception:
        return False


def tracer():
    _configure_provider()
    return trace.get_tracer("release-sentinel.control-plane", __version__)


def _bounded_value(value: Any) -> str | bool | int | float | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value[:_MAX_STRING_VALUE]
    if value is None:
        return None
    return str(value)[:_MAX_STRING_VALUE]


def set_safe_attributes(span: Any, attributes: Mapping[str, Any] | None) -> None:
    if not attributes:
        return
    for key, value in attributes.items():
        if key not in _ALLOWED_ATTRIBUTES:
            continue
        bounded = _bounded_value(value)
        if bounded is None:
            continue
        try:
            span.set_attribute(key, bounded)
        except Exception:
            continue


class _NullSpan:
    def set_attribute(self, *_: Any, **__: Any) -> None:
        return None

    def get_span_context(self):
        return trace.INVALID_SPAN_CONTEXT


@contextmanager
def safe_span(name: str, attributes: Mapping[str, Any] | None = None) -> Iterator[Any]:
    """Start a span without allowing telemetry setup/export to affect business logic."""
    try:
        manager = tracer().start_as_current_span(name)
        span = manager.__enter__()
        set_safe_attributes(span, attributes)
    except Exception:
        yield _NullSpan()
        return

    try:
        yield span
    except BaseException as exc:
        try:
            manager.__exit__(type(exc), exc, exc.__traceback__)
        except Exception:
            pass
        raise
    else:
        try:
            manager.__exit__(None, None, None)
        except Exception:
            pass


def inject_trace_context(headers: dict[str, str]) -> None:
    try:
        TraceContextTextMapPropagator().inject(headers, setter=_SETTER)
    except Exception:
        return


def extract_trace_context(headers: Mapping[str, str]):
    try:
        return TraceContextTextMapPropagator().extract(headers, getter=_GETTER)
    except Exception:
        return None


def current_trace_id() -> str | None:
    try:
        context = trace.get_current_span().get_span_context()
        if not context.is_valid:
            return None
        return f"{context.trace_id:032x}"
    except Exception:
        return None
