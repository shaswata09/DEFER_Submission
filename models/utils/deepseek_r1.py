"""
DeepSeek-R1-Distill-Qwen-32B — Validator V2

Distilled reasoning model from DeepSeek-R1 into Qwen2.5-32B.
Strong reasoning/judgment capabilities for validation tasks.
GPU assignment: GPU 3, ~64GB BF16, single GPU. V5 Mistral swaps onto GPU 3 when needed.
Role: Second validator in consensus module (DeepSeek family = distinct failure mode from Qwen).
"""

import subprocess
import os
import signal
import time
from pathlib import Path
from typing import Optional

import httpx
from openai import OpenAI


MODELS_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = str(MODELS_DIR / "deepseek-ai" / "DeepSeek-R1-Distill-Qwen-32B")
DEFAULT_PORT = 8005
DEFAULT_GPUS = "3"


class DeepSeekR1:
    """Utility class for serving and querying DeepSeek-R1-Distill-Qwen-32B."""

    def __init__(
        self,
        port: int = DEFAULT_PORT,
        model_path: str = MODEL_PATH,
        gpus: str = DEFAULT_GPUS,
    ):
        self.port = port
        self.model_path = model_path
        self.gpus = gpus
        self.base_url = f"http://localhost:{port}/v1"
        self.client = OpenAI(base_url=self.base_url, api_key="unused")
        self._process: Optional[subprocess.Popen] = None

    # ------------------------------------------------------------------ #
    #  Server lifecycle
    # ------------------------------------------------------------------ #

    def serve(
        self,
        tensor_parallel_size: int = 1,
        gpu_memory_utilization: float = 0.9,
        max_model_len: Optional[int] = None,
        dtype: str = "bfloat16",
        quantization: Optional[str] = None,
        enable_tool_choice: bool = False,
        tool_call_parser: str = "hermes",
        extra_args: Optional[list[str]] = None,
    ) -> subprocess.Popen:
        """Start vLLM server with full configuration control.

        DeepSeek-R1-Distill uses chain-of-thought reasoning by default.
        Default enable_tool_choice=False — validators do structured validation, not tool calling.
        """
        cmd = [
            "vllm", "serve", self.model_path,
            "--tensor-parallel-size", str(tensor_parallel_size),
            "--gpu-memory-utilization", str(gpu_memory_utilization),
            "--dtype", dtype,
            "--port", str(self.port),
        ]
        if max_model_len:
            cmd += ["--max-model-len", str(max_model_len)]
        if quantization:
            cmd += ["--quantization", quantization]
        if enable_tool_choice:
            cmd += ["--enable-auto-tool-choice", "--tool-call-parser", tool_call_parser]
        if extra_args:
            cmd += extra_args

        env = os.environ.copy()
        env["CUDA_VISIBLE_DEVICES"] = self.gpus

        self._process = subprocess.Popen(cmd, env=env)
        return self._process

    def serve_dedicated(self, **kwargs) -> subprocess.Popen:
        """Serve on a dedicated GPU with full memory utilization."""
        return self.serve(gpu_memory_utilization=0.9, **kwargs)

    def serve_fp8(self, **kwargs) -> subprocess.Popen:
        """Serve with FP8 quantization for reduced VRAM."""
        return self.serve(quantization="fp8", **kwargs)

    def stop(self):
        """Stop the vLLM server."""
        if self._process:
            self._process.send_signal(signal.SIGTERM)
            self._process.wait(timeout=30)
            self._process = None

    def wait_until_ready(self, timeout: int = 600, poll_interval: float = 5.0) -> bool:
        """Block until the server responds to health checks."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.health_check():
                return True
            time.sleep(poll_interval)
        return False

    def health_check(self) -> bool:
        """Check if the vLLM server is running and healthy."""
        try:
            r = httpx.get(f"http://localhost:{self.port}/health", timeout=5)
            return r.status_code == 200
        except httpx.ConnectError:
            return False

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
        """Send a chat completion request.

        DeepSeek-R1-Distill produces chain-of-thought reasoning in <think>...</think> tags
        before giving the final answer.
        """
        return self.client.chat.completions.create(
            model=self.model_path,
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
    #  Validation (primary use case)
    # ------------------------------------------------------------------ #

    def validate(
        self,
        proposal: str,
        context: str,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ):
        """Validate an agent proposal (primary use case as Validator V2).

        Leverages DeepSeek-R1's reasoning capabilities for deeper analysis.
        The model will reason in <think> tags before producing the JSON verdict.
        """
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a security validation agent. Evaluate the proposed action "
                    "for correctness, safety, and appropriateness given the incident context. "
                    "Think step by step, then respond with JSON: "
                    '{\"approved\": bool, \"confidence\": float, \"reasoning\": str, \"risks\": [str]}'
                ),
            },
            {
                "role": "user",
                "content": f"## Incident Context\n{context}\n\n## Proposed Action\n{proposal}",
            },
        ]
        return self.client.chat.completions.create(
            model=self.model_path,
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
        tool_choice: str = "auto",
        temperature: float = 0.0,
        max_tokens: int = 4096,
        parallel_tool_calls: bool = True,
        stream: bool = False,
    ):
        """Send a chat completion with tool/function calling enabled."""
        return self.client.chat.completions.create(
            model=self.model_path,
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

    # ------------------------------------------------------------------ #
    #  Structured output
    # ------------------------------------------------------------------ #

    def chat_json(self, messages: list[dict], **kwargs):
        """Request JSON-formatted output."""
        return self.client.chat.completions.create(
            model=self.model_path,
            messages=messages,
            response_format={"type": "json_object"},
            **kwargs,
        )

    def chat_json_schema(self, messages: list[dict], schema: dict, schema_name: str = "response", **kwargs):
        """Request output conforming to a specific JSON schema."""
        return self.client.chat.completions.create(
            model=self.model_path,
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
    #  Token counting & metadata
    # ------------------------------------------------------------------ #

    def list_models(self) -> list:
        """List models available on the vLLM server."""
        return self.client.models.list().data

    def get_config(self) -> dict:
        """Return the model configuration for logging/reproducibility."""
        return {
            "model_id": "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B",
            "model_path": self.model_path,
            "role": "validator_2",
            "architecture": "dense",
            "total_params": "32B",
            "base_model": "Qwen2.5-32B",
            "distilled_from": "DeepSeek-R1",
            "reasoning_style": "chain_of_thought",
            "gpu_assignment": self.gpus,
            "port": self.port,
            "base_url": self.base_url,
        }
