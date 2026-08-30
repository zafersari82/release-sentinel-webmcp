from __future__ import annotations

import asyncio
import sys
import types as pytypes

import pytest

from release_sentinel.infrastructure import adk_smoke


def test_smoke_token_is_not_release_authority():
    assert adk_smoke._SMOKE_TOKEN == "RELEASE_SENTINEL_ADK_SMOKE_OK"


def test_adk_smoke_fails_closed_without_required_response_token(monkeypatch):
    class FakeSession:
        id = "s1"

    class FakeSessionService:
        async def create_session(self, **kwargs):
            return FakeSession()

    class FakeContent:
        def __init__(self, **kwargs): pass

    class FakePart:
        @staticmethod
        def from_text(*, text): return object()

    class FakeTypes:
        Content = FakeContent
        Part = FakePart

    class FakeEvent:
        author = "cloud_smoke_agent"
        content = pytypes.SimpleNamespace(parts=[pytypes.SimpleNamespace(text="WRONG")])

    class FakeRunner:
        def __init__(self, **kwargs): self.session_service = FakeSessionService()
        async def run_async(self, **kwargs):
            yield FakeEvent()

    class FakeAgent:
        def __init__(self, **kwargs): pass

    google_pkg = pytypes.ModuleType("google")
    adk_pkg = pytypes.ModuleType("google.adk")
    runners_pkg = pytypes.ModuleType("google.adk.runners")
    genai_pkg = pytypes.ModuleType("google.genai")
    adk_pkg.Agent = FakeAgent
    runners_pkg.InMemoryRunner = FakeRunner
    genai_pkg.types = FakeTypes
    monkeypatch.setitem(sys.modules, "google", google_pkg)
    monkeypatch.setitem(sys.modules, "google.adk", adk_pkg)
    monkeypatch.setitem(sys.modules, "google.adk.runners", runners_pkg)
    monkeypatch.setitem(sys.modules, "google.genai", genai_pkg)

    with pytest.raises(RuntimeError, match="required proof token"):
        asyncio.run(adk_smoke.run_adk_gemini_smoke())


def test_adk_smoke_reports_real_call_only_after_exact_token(monkeypatch):
    class FakeSession:
        id = "s1"

    class FakeSessionService:
        async def create_session(self, **kwargs): return FakeSession()

    class FakeContent:
        def __init__(self, **kwargs): pass

    class FakePart:
        @staticmethod
        def from_text(*, text): return object()

    class FakeTypes:
        Content = FakeContent
        Part = FakePart

    class FakeEvent:
        author = "cloud_smoke_agent"
        content = pytypes.SimpleNamespace(parts=[pytypes.SimpleNamespace(text="RELEASE_SENTINEL_ADK_SMOKE_OK")])

    class FakeRunner:
        def __init__(self, **kwargs): self.session_service = FakeSessionService()
        async def run_async(self, **kwargs): yield FakeEvent()

    class FakeAgent:
        def __init__(self, **kwargs): pass

    google_pkg = pytypes.ModuleType("google")
    adk_pkg = pytypes.ModuleType("google.adk")
    runners_pkg = pytypes.ModuleType("google.adk.runners")
    genai_pkg = pytypes.ModuleType("google.genai")
    adk_pkg.Agent = FakeAgent
    runners_pkg.InMemoryRunner = FakeRunner
    genai_pkg.types = FakeTypes
    monkeypatch.setitem(sys.modules, "google", google_pkg)
    monkeypatch.setitem(sys.modules, "google.adk", adk_pkg)
    monkeypatch.setitem(sys.modules, "google.adk.runners", runners_pkg)
    monkeypatch.setitem(sys.modules, "google.genai", genai_pkg)

    proof = asyncio.run(adk_smoke.run_adk_gemini_smoke())
    assert proof["adk_real_call"] is True
    assert proof["gemini_real_call"] is True
    assert proof["response_token_matched"] is True
    assert proof["release_authority"] == "NONE"
