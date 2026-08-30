from __future__ import annotations

import json
import os
import shutil

from playwright.sync_api import sync_playwright

from release_sentinel.webmcp.contracts import AttackName


BASE_URL = os.getenv("RELEASE_SENTINEL_WEBMCP_BASE", "http://127.0.0.1:18081").rstrip("/")


def _chrome_executable() -> str:
    explicit = os.getenv("PLAYWRIGHT_CHROME_EXECUTABLE", "").strip()
    if explicit:
        return explicit
    for candidate in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise RuntimeError("no system Chrome/Chromium executable found")


def _payload(result):
    return json.loads(result) if isinstance(result, str) else result


def main() -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=False,
            executable_path=_chrome_executable(),
            args=[
                "--no-sandbox",
                "--enable-experimental-web-platform-features",
                "--enable-features=WebMCP,WebMCPTesting,DevToolsWebMCPSupport",
            ],
        )
        print("browser version:", browser.version)
        page = browser.new_page()
        page.on("console", lambda message: print(f"browser console [{message.type}]: {message.text}"))
        page.on("pageerror", lambda error: print(f"browser pageerror: {error}"))

        page.goto(f"{BASE_URL}/arena", wait_until="networkidle")
        page.wait_for_function("document.querySelector('#webmcpStatus')?.textContent === 'REGISTERED'")

        feature_state = page.evaluate(
            """async () => ({
              modelContextType: typeof document.modelContext,
              executeToolType: typeof document.modelContext?.executeTool,
              tools: document.modelContext ? (await document.modelContext.getTools()).map(tool => ({
                name: tool.name,
                sameWindow: tool.window === window,
              })) : [],
            })"""
        )
        print("native WebMCP feature state:", json.dumps(feature_state, indent=2))
        assert feature_state["modelContextType"] == "object", feature_state
        assert feature_state["executeToolType"] == "function", feature_state
        assert len(feature_state["tools"]) == 12, feature_state
        assert all(tool["sameWindow"] for tool in feature_state["tools"]), feature_state
        assert any(tool["name"] == "run_attack_suite" for tool in feature_state["tools"]), feature_state

        release_execution = page.evaluate(
            """async () => {
              const tools = await document.modelContext.getTools();
              const tool = tools.find(candidate => candidate.name === 'inspect_release' && candidate.window === window);
              if (!tool) {
                return {ok: false, name: 'InspectorSelectionError', message: 'inspect_release was not associated with the current window'};
              }
              try {
                const result = await document.modelContext.executeTool(tool, '{}');
                return {ok: true, result};
              } catch (error) {
                return {ok: false, name: error?.name || '', message: error?.message || String(error), stack: error?.stack || ''};
              }
            }"""
        )
        print("inspector-equivalent inspect_release execution:", json.dumps(release_execution, indent=2))
        assert release_execution["ok"] is True, release_execution

        release_payload = _payload(release_execution["result"])
        assert release_payload["current_verdict"] == "NO_GO", release_payload
        assert release_payload["authority"] == "DETERMINISTIC_GATEKEEPER", release_payload

        attack_execution = page.evaluate(
            """async () => {
              const tools = await document.modelContext.getTools();
              const tool = tools.find(candidate => candidate.name === 'run_attack' && candidate.window === window);
              if (!tool) {
                return {ok: false, name: 'InspectorSelectionError', message: 'run_attack was not associated with the current window'};
              }
              try {
                const result = await document.modelContext.executeTool(
                  tool,
                  JSON.stringify({attack_name: 'force_agents_go'}),
                );
                return {ok: true, result};
              } catch (error) {
                return {ok: false, name: error?.name || '', message: error?.message || String(error), stack: error?.stack || ''};
              }
            }"""
        )
        print("inspector-equivalent run_attack execution:", json.dumps(attack_execution, indent=2))
        assert attack_execution["ok"] is True, attack_execution

        attack_payload = _payload(attack_execution["result"])
        assert attack_payload["attack"] == "force_agents_go", attack_payload
        assert attack_payload["attack_blocked"] is True, attack_payload
        assert attack_payload["agent_influence"] == 0, attack_payload
        assert attack_payload["webmcp_authority"] == "NO_RELEASE_AUTHORITY", attack_payload

        suite_execution = page.evaluate(
            """async () => {
              const tools = await document.modelContext.getTools();
              const tool = tools.find(candidate => candidate.name === 'run_attack_suite' && candidate.window === window);
              if (!tool) {
                return {ok: false, name: 'InspectorSelectionError', message: 'run_attack_suite was not associated with the current window'};
              }
              try {
                const result = await document.modelContext.executeTool(tool, '{}');
                return {ok: true, result};
              } catch (error) {
                return {ok: false, name: error?.name || '', message: error?.message || String(error), stack: error?.stack || ''};
              }
            }"""
        )
        print("inspector-equivalent run_attack_suite execution:", json.dumps(suite_execution, indent=2))
        assert suite_execution["ok"] is True, suite_execution

        suite_payload = _payload(suite_execution["result"])
        expected_attacks = {item.value for item in AttackName}
        returned_attacks = {item["attack"] for item in suite_payload["results"]}

        assert suite_payload["suite"] == "bounded_release_attack_suite", suite_payload
        assert suite_payload["attacks_requested"] == len(expected_attacks) == 8, suite_payload
        assert suite_payload["attacks_executed"] == 8, suite_payload
        assert suite_payload["contained_count"] == 8, suite_payload
        assert suite_payload["all_contained"] is True, suite_payload
        assert suite_payload["unexpected_authority_gains"] == 0, suite_payload
        assert suite_payload["max_agent_influence"] == 0, suite_payload
        assert suite_payload["authority"] == "DETERMINISTIC_GO_GATEKEEPER", suite_payload
        assert suite_payload["webmcp_authority"] == "NO_RELEASE_AUTHORITY", suite_payload
        assert len(suite_payload["results"]) == 8, suite_payload
        assert returned_attacks == expected_attacks, suite_payload
        assert all(item["attack_blocked"] is True for item in suite_payload["results"]), suite_payload
        assert all(item["webmcp_authority"] == "NO_RELEASE_AUTHORITY" for item in suite_payload["results"]), suite_payload

        browser.close()


if __name__ == "__main__":
    main()
