"""Tests for gateway/llm_policy.py — what an agent may ask a provider to do (#297)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from mcp_trentina_crunchtools.gateway.llm_policy import (
    LlmApi,
    LlmRefusedError,
    Reason,
    admit,
    forward_headers,
)

A, OA, R, G = LlmApi.ANTHROPIC, LlmApi.OPENAI, LlmApi.OPENROUTER, LlmApi.GEMINI

_CLAUDE = {"model": "claude-sonnet-4-5", "max_tokens": 8, "messages": []}
_GPT = {"model": "gpt-4.1", "messages": [{"role": "user", "content": "hi"}]}
_ROUTER = {**_GPT, "model": "anthropic/claude-sonnet-4"}
_GEMINI_PATH = "v1beta/models/gemini-2.5-flash:generateContent"


def _admit(api: LlmApi, path: str, body: dict[str, Any] | None, **kw: Any) -> Any:
    raw = json.dumps(body).encode() if body is not None else b""
    return admit(api, kw.pop("method", "POST"), path, kw.pop("query", ""), raw, **kw)


def _reason(api: LlmApi, path: str, body: dict[str, Any] | None, **kw: Any) -> Reason:
    with pytest.raises(LlmRefusedError) as err:
        _admit(api, path, body, **kw)
    return err.value.reason


class TestPlainCallsPass:
    """A completion with caller-run function tools is what the proxy is for."""

    def test_anthropic_messages_with_custom_tool(self) -> None:
        body = {
            **_CLAUDE,
            "system": [{"type": "text", "text": "be brief"}],
            "tools": [{"name": "read", "input_schema": {}}, {"type": "custom", "name": "w"}],
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "see https://example.com"},
                        {"type": "image", "source": {"type": "base64", "data": "AA=="}},
                        {"type": "tool_result", "tool_use_id": "t", "content": "ok"},
                    ],
                }
            ],
        }
        admitted = _admit(A, "v1/messages", body, query="beta=true")
        assert admitted.endpoint == "messages"
        assert admitted.model == "claude-sonnet-4-5"
        assert admitted.query == "beta=true"
        assert json.loads(admitted.body) == body

    def test_openai_chat_with_function_and_inline_image(self) -> None:
        body = {
            **_GPT,
            "tools": [{"type": "function", "function": {"name": "f"}}],
            "tool_choice": {"type": "function", "function": {"name": "f"}},
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "x"},
                        {"type": "image_url", "image_url": {"url": "data:image/png;base64,AA"}},
                    ],
                }
            ],
        }
        assert _admit(OA, "v1/chat/completions", body).endpoint == "chat/completions"

    def test_openrouter_with_its_own_fields(self) -> None:
        body = {**_ROUTER, "provider": {"order": ["anthropic"]}, "models": ["openai/gpt-4.1"]}
        assert _admit(R, "v1/chat/completions", body).model == "anthropic/claude-sonnet-4"

    def test_openai_responses_with_function_tool(self) -> None:
        body = {
            "model": "gpt-5",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "x"}]}],
            "tools": [{"type": "function", "name": "f", "parameters": {}}],
        }
        assert _admit(OA, "v1/responses", body).endpoint == "responses"

    def test_gemini_generate_with_function_declarations(self) -> None:
        body = {
            "contents": [{"role": "user", "parts": [{"text": "x"}]}],
            "tools": [{"functionDeclarations": [{"name": "f"}]}],
            "generationConfig": {"temperature": 0},
        }
        admitted = _admit(G, _GEMINI_PATH, body, query="alt=sse")
        assert admitted.model == "gemini-2.5-flash"

    def test_model_listing_get(self) -> None:
        admitted = _admit(A, "v1/models", None, method="GET")
        assert admitted.body is None


class TestServerToolsRefused:
    """Every provider-run tool is a path to the internet the gateway never sees."""

    @pytest.mark.parametrize(
        "tool",
        [
            "web_fetch_20250910",
            "web_search_20250305",
            "code_execution_20250825",
            "computer_20250124",
            "bash_20250124",
        ],
    )
    def test_anthropic_tool_types(self, tool: str) -> None:
        body = {**_CLAUDE, "tools": [{"type": tool, "name": "x"}]}
        assert _reason(A, "v1/messages", body) is Reason.SERVER_TOOL

    def test_anthropic_mcp_servers(self) -> None:
        body = {**_CLAUDE, "mcp_servers": [{"type": "url", "url": "https://evil/mcp"}]}
        assert _reason(A, "v1/messages", body) is Reason.MCP_SERVERS

    def test_anthropic_container(self) -> None:
        assert _reason(A, "v1/messages", {**_CLAUDE, "container": "c"}) is Reason.SERVER_TOOL

    def test_openai_web_search_options(self) -> None:
        body = {**_GPT, "web_search_options": {}}
        assert _reason(OA, "v1/chat/completions", body) is Reason.SERVER_TOOL

    @pytest.mark.parametrize("tool", ["web_search_preview", "mcp", "file_search", "computer"])
    def test_openai_responses_tools(self, tool: str) -> None:
        body = {"model": "gpt-5", "input": "x", "tools": [{"type": tool}]}
        assert _reason(OA, "v1/responses", body) is Reason.SERVER_TOOL

    def test_openai_tool_choice_naming_a_server_tool(self) -> None:
        body = {"model": "gpt-5", "input": "x", "tool_choice": {"type": "web_search_preview"}}
        assert _reason(OA, "v1/responses", body) is Reason.SERVER_TOOL

    def test_openrouter_web_plugin(self) -> None:
        body = {**_ROUTER, "plugins": [{"id": "web"}]}
        assert _reason(R, "v1/chat/completions", body) is Reason.PLUGINS

    @pytest.mark.parametrize(
        "tool",
        [
            {"googleSearch": {}},
            {"google_search_retrieval": {}},
            {"urlContext": {}},
            {"codeExecution": {}},
        ],
    )
    def test_gemini_grounding_and_url_context(self, tool: dict[str, Any]) -> None:
        body = {"contents": [], "tools": [tool]}
        assert _reason(G, _GEMINI_PATH, body) is Reason.SERVER_TOOL


class TestOnlineModelsRefused:
    @pytest.mark.parametrize(
        ("api", "path", "body"),
        [
            (R, "v1/chat/completions", {**_ROUTER, "model": "openai/gpt-4.1:online"}),
            (R, "v1/chat/completions", {**_ROUTER, "models": ["x/y:online"]}),
            (R, "v1/chat/completions", {**_ROUTER, "model": "perplexity/sonar-pro"}),
            (OA, "v1/chat/completions", {**_GPT, "model": "gpt-4o-search-preview"}),
        ],
    )
    def test_self_searching_model(self, api: LlmApi, path: str, body: dict[str, Any]) -> None:
        assert _reason(api, path, body) is Reason.ONLINE_MODEL

    def test_allowed_models_narrows(self) -> None:
        reason = _reason(OA, "v1/chat/completions", _GPT, allowed_models=["gpt-5*"])
        assert reason is Reason.MODEL_NOT_ALLOWED
        gpt5 = {**_GPT, "model": "gpt-5-mini"}
        _admit(OA, "v1/chat/completions", gpt5, allowed_models=["gpt-5*"])

    def test_gemini_path_model_checked(self) -> None:
        path = "v1beta/models/gemini-2.5-flash:generateContent"
        reason = _reason(G, path, {"contents": []}, allowed_models=["gemini-2.5-pro"])
        assert reason is Reason.MODEL_NOT_ALLOWED


class TestUrlSourcesRefused:
    """A content source the provider dereferences is a fetch by another name."""

    def test_anthropic_image_url_source(self) -> None:
        block = {"type": "image", "source": {"type": "url", "url": "https://evil/?d=secret"}}
        body = {**_CLAUDE, "messages": [{"role": "user", "content": [block]}]}
        assert _reason(A, "v1/messages", body) is Reason.URL_SOURCE

    def test_anthropic_document_url_inside_tool_result(self) -> None:
        doc = {"type": "document", "source": {"type": "url", "url": "https://evil"}}
        result = {"type": "tool_result", "tool_use_id": "t", "content": [doc]}
        body = {**_CLAUDE, "messages": [{"role": "user", "content": [result]}]}
        assert _reason(A, "v1/messages", body) is Reason.URL_SOURCE

    def test_anthropic_server_tool_result_block(self) -> None:
        block = {"type": "web_fetch_tool_result", "tool_use_id": "t", "content": {}}
        body = {**_CLAUDE, "messages": [{"role": "assistant", "content": [block]}]}
        assert _reason(A, "v1/messages", body) is Reason.CONTENT_TYPE

    @pytest.mark.parametrize(
        "image", [{"url": "https://evil/x.png"}, "https://evil/x.png", {"url": "HTTP://e"}]
    )
    def test_openai_image_url(self, image: Any) -> None:
        part = {"type": "image_url", "image_url": image}
        body = {**_GPT, "messages": [{"role": "user", "content": [part]}]}
        assert _reason(OA, "v1/chat/completions", body) is Reason.URL_SOURCE

    def test_openrouter_file_data_url(self) -> None:
        part = {"type": "file", "file": {"filename": "a.pdf", "file_data": "https://evil/a.pdf"}}
        body = {**_ROUTER, "messages": [{"role": "user", "content": [part]}]}
        assert _reason(R, "v1/chat/completions", body) is Reason.URL_SOURCE

    def test_responses_input_file_url(self) -> None:
        part = {"type": "input_file", "file_url": "https://evil/a.pdf"}
        body = {"model": "gpt-5", "input": [{"role": "user", "content": [part]}]}
        assert _reason(OA, "v1/responses", body) is Reason.URL_SOURCE

    def test_gemini_file_data_outside_files_api(self) -> None:
        part = {"fileData": {"fileUri": "https://www.youtube.com/watch?v=x"}}
        body = {"contents": [{"role": "user", "parts": [part]}]}
        assert _reason(G, _GEMINI_PATH, body) is Reason.URL_SOURCE

    def test_gemini_file_data_in_files_api_passes(self) -> None:
        uri = "https://generativelanguage.googleapis.com/v1beta/files/abc"
        part = {"file_data": {"file_uri": uri, "mime_type": "application/pdf"}}
        admitted = _admit(G, _GEMINI_PATH, {"contents": [{"role": "user", "parts": [part]}]})
        assert admitted.endpoint == "generateContent"

    def test_gemini_both_spellings_of_one_key_refused(self) -> None:
        """Only one of ``fileData``/``file_data`` would be judged; Google reads either."""
        good = {"file_uri": "https://generativelanguage.googleapis.com/v1beta/files/a"}
        part = {"file_data": good, "fileData": {"fileUri": "https://evil/x"}}
        body = {"contents": [{"role": "user", "parts": [part]}]}
        assert _reason(G, _GEMINI_PATH, body) is Reason.MALFORMED

    def test_gemini_both_spellings_of_tools_refused(self) -> None:
        body = {"contents": [], "tools": [], "Tools": [{"googleSearch": {}}]}
        assert _reason(G, _GEMINI_PATH, body) is Reason.MALFORMED


class TestStoredStateRefused:
    @pytest.mark.parametrize("key", ["prompt", "conversation", "background"])
    def test_responses(self, key: str) -> None:
        body = {"model": "gpt-5", "input": "x", key: {"id": "p"}}
        assert _reason(OA, "v1/responses", body) is Reason.STORED_STATE

    def test_gemini_cached_content(self) -> None:
        body = {"contents": [], "cachedContent": "cachedContents/x"}
        assert _reason(G, _GEMINI_PATH, body) is Reason.STORED_STATE


class TestShape:
    def test_unknown_param_refused(self) -> None:
        assert _reason(A, "v1/messages", {**_CLAUDE, "new_thing": 1}) is Reason.UNKNOWN_PARAM

    @pytest.mark.parametrize(
        ("api", "path"),
        [
            (A, "v1/files"),
            (A, "v1/messages/batches"),
            (A, "v1/skills"),
            (OA, "v1/files"),
            (OA, "v1/assistants"),
            (G, "v1beta/cachedContents"),
            (G, "v1beta/files"),
            (G, "upload/v1beta/files"),
        ],
    )
    def test_endpoint_refused(self, api: LlmApi, path: str) -> None:
        assert _reason(api, path, {}) is Reason.ENDPOINT

    def test_wrong_method(self) -> None:
        assert _reason(A, "v1/messages", None, method="DELETE") is Reason.METHOD

    def test_gemini_key_in_query_refused(self) -> None:
        assert _reason(G, _GEMINI_PATH, {"contents": []}, query="key=abc") is Reason.QUERY

    def test_duplicate_query_param_refused(self) -> None:
        assert _reason(A, "v1/messages", _CLAUDE, query="beta=true&beta=x") is Reason.QUERY

    def test_non_object_body(self) -> None:
        with pytest.raises(LlmRefusedError) as err:
            admit(A, "POST", "v1/messages", "", b"[1]")
        assert err.value.reason is Reason.MALFORMED

    def test_nan_refused(self) -> None:
        with pytest.raises(LlmRefusedError) as err:
            admit(A, "POST", "v1/messages", "", b'{"temperature": NaN}')
        assert err.value.reason is Reason.MALFORMED

    def test_tools_not_a_list(self) -> None:
        body = {**_CLAUDE, "tools": {"type": "web_search_20250305"}}
        assert _reason(A, "v1/messages", body) is Reason.MALFORMED

    def test_get_with_body_refused(self) -> None:
        assert _reason(A, "v1/models", {"x": 1}, method="GET") is Reason.MALFORMED


class TestForwardHeaders:
    def test_allowlist(self) -> None:
        headers = forward_headers(
            OA,
            [
                ("Accept", "text/event-stream"),
                ("Authorization", "Bearer gateway"),
                ("OpenAI-Organization", "org-x"),
                ("OpenAI-Project", "proj-x"),
                ("anthropic-beta", "context-1m-2025-08-07"),
                ("HTTP-Referer", "https://x"),
            ],
        )
        assert headers == {"accept": "text/event-stream"}

    def test_anthropic_beta_filtered(self) -> None:
        headers = forward_headers(
            A,
            [("anthropic-beta", "web-fetch-2025-09-10,claude-code-20250219,files-api-2025-04-14")],
        )
        assert headers == {"anthropic-beta": "claude-code-20250219"}

    def test_anthropic_beta_all_unsafe_dropped(self) -> None:
        assert forward_headers(A, [("anthropic-beta", "mcp-client-2025-04-04")]) == {}
