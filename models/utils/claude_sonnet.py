"""
Claude Sonnet — Validator V4 (API-based)

Proprietary model accessed via Anthropic API.
Role: Fourth validator in consensus module. Default validator alongside V1 (Qwen3-32B) and V2 (Mistral).
Estimated cost: ~$12–20 for full experiment run.
No local GPU needed.
"""

import os
from typing import Optional

from anthropic import Anthropic


class ClaudeSonnet:
    """Utility class for querying Claude Sonnet via Anthropic API."""

    def __init__(
        self,
        model: str = "claude-sonnet-4-6",
        api_key: Optional[str] = None,
    ):
        self.model = model
        self.client = Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))

    # ------------------------------------------------------------------ #
    #  Chat completions
    # ------------------------------------------------------------------ #

    def chat(
        self,
        messages: list[dict],
        system: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        top_p: float = 1.0,
        stop_sequences: Optional[list[str]] = None,
        stream: bool = False,
    ):
        """Send a message to Claude Sonnet.

        Args:
            messages: List of message dicts with 'role' and 'content' keys.
                      System messages are extracted and passed separately.
            system: Explicit system prompt (overrides any system message in messages list).
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
        """
        # Extract system message if not provided explicitly
        if system is None:
            non_system = []
            for msg in messages:
                if msg["role"] == "system":
                    system = msg["content"]
                else:
                    non_system.append(msg)
            messages = non_system if non_system else messages

        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        # Claude doesn't allow temperature + top_p together
        if top_p != 1.0:
            del kwargs["temperature"]
            kwargs["top_p"] = top_p
        if system:
            kwargs["system"] = system
        if stop_sequences:
            kwargs["stop_sequences"] = stop_sequences
        if stream:
            return self.client.messages.stream(**kwargs)

        return self.client.messages.create(**kwargs)

    def chat_deterministic(self, messages: list[dict], **kwargs):
        """Chat with temperature=0.0 for reproducible experiment runs."""
        return self.chat(messages, temperature=0.0, **kwargs)

    def chat_creative(self, messages: list[dict], **kwargs):
        """Chat with temperature=0.7 for experiment variation runs."""
        return self.chat(messages, temperature=0.7, **kwargs)

    # ------------------------------------------------------------------ #
    #  Validation (primary use case)
    # ------------------------------------------------------------------ #

    def validate(
        self,
        proposal: str,
        context: str,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ):
        """Validate an agent proposal (primary use case as Validator V4).

        Returns a structured validation judgment given a proposal and incident context.
        """
        system = (
            "You are a security validation agent. Evaluate the proposed action "
            "for correctness, safety, and appropriateness given the incident context. "
            'Respond with JSON only: {"approved": bool, "confidence": float, "reasoning": str, "risks": [str]}'
        )
        messages = [
            {
                "role": "user",
                "content": f"## Incident Context\n{context}\n\n## Proposed Action\n{proposal}",
            },
        ]
        return self.client.messages.create(
            model=self.model,
            system=system,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def batch_validate(
        self,
        proposals: list[dict],
        temperature: float = 0.0,
    ) -> list:
        """Validate a batch of proposals. Each dict should have 'proposal' and 'context' keys."""
        results = []
        for item in proposals:
            resp = self.validate(
                proposal=item["proposal"],
                context=item["context"],
                temperature=temperature,
            )
            results.append(resp)
        return results

    # ------------------------------------------------------------------ #
    #  Tool / function calling
    # ------------------------------------------------------------------ #

    def tool_call(
        self,
        messages: list[dict],
        tools: list[dict],
        tool_choice: Optional[dict] = None,
        system: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ):
        """Send a message with tool use enabled.

        Args:
            tools: List of Anthropic-format tool definitions with 'name', 'description',
                   and 'input_schema' keys.
            tool_choice: Tool choice config, e.g. {"type": "auto"}, {"type": "any"},
                         or {"type": "tool", "name": "function_name"}.
        """
        # Extract system message
        if system is None:
            non_system = []
            for msg in messages:
                if msg["role"] == "system":
                    system = msg["content"]
                else:
                    non_system.append(msg)
            messages = non_system if non_system else messages

        kwargs = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if system:
            kwargs["system"] = system
        if tool_choice:
            kwargs["tool_choice"] = tool_choice

        return self.client.messages.create(**kwargs)

    def tool_call_required(self, messages: list[dict], tools: list[dict], **kwargs):
        """Force the model to use a tool."""
        return self.tool_call(messages, tools, tool_choice={"type": "any"}, **kwargs)

    def tool_call_specific(
        self, messages: list[dict], tools: list[dict], tool_name: str, **kwargs
    ):
        """Force the model to call a specific tool."""
        return self.tool_call(
            messages, tools, tool_choice={"type": "tool", "name": tool_name}, **kwargs
        )

    # ------------------------------------------------------------------ #
    #  Structured output
    # ------------------------------------------------------------------ #

    def chat_json(self, messages: list[dict], **kwargs):
        """Request JSON-formatted output by instructing the model."""
        system = kwargs.pop("system", None)
        if system:
            system += "\n\nRespond with valid JSON only."
        else:
            system = "Respond with valid JSON only."
        return self.chat(messages, system=system, **kwargs)

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
            resp = self.client.messages.create(
                model=self.model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=5,
            )
            return resp.stop_reason is not None
        except Exception:
            return False

    def get_config(self) -> dict:
        """Return the model configuration for logging/reproducibility."""
        return {
            "model_id": self.model,
            "provider": "anthropic",
            "role": "validator_4",
            "api_based": True,
            "estimated_cost": "$12-20",
        }
