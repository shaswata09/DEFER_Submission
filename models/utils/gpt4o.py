"""
GPT-4o — TAMAS Benchmark Baseline (API-based)

Proprietary model accessed via OpenAI API.
Role: Reproduce TAMAS benchmark baselines on flat AutoGen configuration.
Estimated cost: ~$25–50 for full TAMAS evaluation.
No local GPU needed.
"""

import os
from typing import Optional

from openai import OpenAI


class GPT4o:
    """Utility class for querying GPT-4o via OpenAI API."""

    def __init__(
        self,
        model: str = "gpt-4o",
        api_key: Optional[str] = None,
    ):
        self.model = model
        self.client = OpenAI(api_key=api_key or os.environ.get("OPENAI_API_KEY"))

    # ------------------------------------------------------------------ #
    #  Chat completions
    # ------------------------------------------------------------------ #

    def chat(
        self,
        messages: list[dict],
        temperature: float = 0.0,
        max_tokens: int = 4096,
        top_p: float = 1.0,
        frequency_penalty: float = 0.0,
        presence_penalty: float = 0.0,
        stop: Optional[list[str]] = None,
        stream: bool = False,
    ):
        """Send a chat completion request."""
        return self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            top_p=top_p,
            frequency_penalty=frequency_penalty,
            presence_penalty=presence_penalty,
            stop=stop,
            stream=stream,
        )

    def chat_deterministic(self, messages: list[dict], **kwargs):
        """Chat with temperature=0.0 for reproducible experiment runs."""
        return self.chat(messages, temperature=0.0, **kwargs)

    def chat_creative(self, messages: list[dict], **kwargs):
        """Chat with temperature=0.7 for experiment variation runs."""
        return self.chat(messages, temperature=0.7, **kwargs)

    # ------------------------------------------------------------------ #
    #  Tool / function calling
    # ------------------------------------------------------------------ #

    def tool_call(
        self,
        messages: list[dict],
        tools: list[dict],
        tool_choice: str = "auto",
        temperature: float = 0.0,
        max_tokens: int = 4096,
        parallel_tool_calls: bool = True,
        stream: bool = False,
    ):
        """Send a chat completion with tool/function calling enabled."""
        return self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=tools,
            tool_choice=tool_choice,
            temperature=temperature,
            max_tokens=max_tokens,
            parallel_tool_calls=parallel_tool_calls,
            stream=stream,
        )

    def tool_call_required(self, messages: list[dict], tools: list[dict], **kwargs):
        """Force the model to make a tool call."""
        return self.tool_call(messages, tools, tool_choice="required", **kwargs)

    def tool_call_specific(
        self, messages: list[dict], tools: list[dict], function_name: str, **kwargs
    ):
        """Force the model to call a specific function."""
        return self.tool_call(
            messages,
            tools,
            tool_choice={"type": "function", "function": {"name": function_name}},
            **kwargs,
        )

    # ------------------------------------------------------------------ #
    #  Structured output
    # ------------------------------------------------------------------ #

    def chat_json(self, messages: list[dict], **kwargs):
        """Request JSON-formatted output."""
        return self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            response_format={"type": "json_object"},
            **kwargs,
        )

    def chat_json_schema(self, messages: list[dict], schema: dict, schema_name: str = "response", **kwargs):
        """Request output conforming to a specific JSON schema."""
        return self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            response_format={
                "type": "json_schema",
                "json_schema": {"name": schema_name, "schema": schema},
            },
            **kwargs,
        )

    # ------------------------------------------------------------------ #
    #  Batch inference
    # ------------------------------------------------------------------ #

    def batch_chat(
        self,
        message_batches: list[list[dict]],
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> list:
        """Run chat completions for a batch of message lists sequentially."""
        results = []
        for messages in message_batches:
            resp = self.chat(messages, temperature=temperature, max_tokens=max_tokens)
            results.append(resp)
        return results

    # ------------------------------------------------------------------ #
    #  Metadata
    # ------------------------------------------------------------------ #

    def health_check(self) -> bool:
        """Verify API connectivity with a minimal request."""
        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=5,
            )
            return resp.choices[0].finish_reason is not None
        except Exception:
            return False

    def get_config(self) -> dict:
        """Return the model configuration for logging/reproducibility."""
        return {
            "model_id": self.model,
            "provider": "openai",
            "role": "tamas_baseline",
            "api_based": True,
            "estimated_cost": "$25-50",
        }
