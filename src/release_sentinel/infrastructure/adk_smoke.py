from __future__ import annotations

import asyncio
import os
from typing import Any

_SMOKE_TOKEN = "RELEASE_SENTINEL_ADK_SMOKE_OK"


async def run_adk_gemini_smoke() -> dict[str, Any]:
    """Make one real ADK -> Gemini call using the deployed service identity.

    This is deliberately advisory-only. It proves that the installed ADK runtime,
    configured Gemini backend, and Google Cloud credentials can complete a real
    model turn. It does not influence release or cutover authority.
    """
    from google.adk import Agent
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    model = os.getenv("RELEASE_SENTINEL_MODEL", "gemini-3.6-flash")
    app_name = "release_sentinel_cloud_smoke"
    user_id = "cloud-proof"
    agent = Agent(
        name="cloud_smoke_agent",
        model=model,
        mode="chat",
        instruction=(
            "You are a connectivity smoke-test agent with no release authority. "
            f"Reply with exactly {_SMOKE_TOKEN} and nothing else."
        ),
    )
    runner = InMemoryRunner(app_name=app_name, agent=agent)
    session = await runner.session_service.create_session(app_name=app_name, user_id=user_id)
    content = types.Content(
        role="user",
        parts=[types.Part.from_text(text="Perform the Release Sentinel ADK cloud connectivity smoke test.")],
    )

    event_count = 0
    authors: set[str] = set()
    response_texts: list[str] = []
    async for event in runner.run_async(
        user_id=user_id,
        session_id=session.id,
        new_message=content,
    ):
        event_count += 1
        author = getattr(event, "author", None)
        if author:
            authors.add(str(author))
        payload = getattr(event, "content", None)
        parts = getattr(payload, "parts", None) if payload is not None else None
        for part in parts or []:
            text = getattr(part, "text", None)
            if text:
                response_texts.append(str(text).strip())

    matched = any(text == _SMOKE_TOKEN for text in response_texts)
    if not matched:
        raise RuntimeError("real ADK/Gemini smoke did not return the required proof token")
    return {
        "adk_real_call": True,
        "gemini_real_call": True,
        "model": model,
        "event_count": event_count,
        "authors": sorted(authors),
        "response_token_matched": True,
        "release_authority": "NONE",
    }


def run_adk_gemini_smoke_sync() -> dict[str, Any]:
    return asyncio.run(run_adk_gemini_smoke())
