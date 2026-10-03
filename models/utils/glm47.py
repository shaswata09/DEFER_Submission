"""
GLM-4.7 (Zhipu AI) — Diversity Agents

Dense model, ~668GB BF16 weights.
GPU assignment: GPU 0,1,4,5 TP=4 with FP8 quantization (~84GB/GPU). Swaps with Primary.
Role: Second model family for cross-model diversity checks (30 trials).
Requires vLLM nightly for GLM-4.7 support.
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
MODEL_PATH = str(MODELS_DIR / "zai-org" / "GLM-4.7-FP8")
DEFAULT_PORT = 8001
DEFAULT_GPUS = "0,1,4,5"


class GLM47:
    """Utility class for serving and querying GLM-4.7."""

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
        tensor_parallel_size: int = 4,
        gpu_memory_utilization: float = 0.9,
        max_model_len: Optional[int] = 32768,
        dtype: str = "auto",
        quantization: Optional[str] = None,
        enable_tool_choice: bool = True,
        tool_call_parser: str = "glm47",
        reasoning_parser: str = "glm45",
        enable_thinking: bool = False,
        thinking_budget: int = 4096,
        extra_args: Optional[list[str]] = None,
    ) -> subprocess.Popen:
        """Start vLLM server with full configuration control.

        GLM-4.7 uses its own tool-call parser ('glm47') and reasoning parser ('glm45').
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
            cmd += [
                "--enable-auto-tool-choice",
                "--tool-call-parser", tool_call_parser,
                "--reasoning-parser", reasoning_parser,
            ]
        if enable_thinking:
            cmd += ["--enable-thinking", "--thinking-budget", str(thinking_budget)]
        if extra_args:
            cmd += extra_args

        env = os.environ.copy()
        env["CUDA_VISIBLE_DEVICES"] = self.gpus

        self._process = subprocess.Popen(cmd, env=env)
        return self._process

    def serve_fp8(self, **kwargs) -> subprocess.Popen:
        """Serve with FP8 quantization to reduce VRAM from ~260GB to ~130GB."""
        return self.serve(quantization="fp8", **kwargs)

    def serve_with_thinking(self, thinking_budget: int = 4096, **kwargs) -> subprocess.Popen:
        """Serve with GLM-4.7 interleaved thinking enabled."""
        return self.serve(enable_thinking=True, thinking_budget=thinking_budget, **kwargs)

    def serve_no_reasoning(self, **kwargs) -> subprocess.Popen:
        """Serve without reasoning parser (plain generation only)."""
        return self.serve(enable_tool_choice=False, **kwargs)

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
        top_k: int = -1,
        frequency_penalty: float = 0.0,
        presence_penalty: float = 0.0,
        stop: Optional[list[str]] = None,
        stream: bool = False,
    ):
        """Send a chat completion request."""
        return self.client.chat.completions.create(
            model=self.model_path,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            top_p=top_p,
            extra_body={"top_k": top_k},
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
        """Send a chat completion with tool/function calling enabled.

        GLM-4.7 uses the 'glm47' tool-call parser on the vLLM side.
        The OpenAI-compatible API surface is identical.
        """
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
            "model_id": "zai-org/GLM-4.7",
            "model_path": self.model_path,
            "role": "diversity_agents",
            "architecture": "dense",
            "gpu_assignment": self.gpus,
            "port": self.port,
            "base_url": self.base_url,
            "tool_call_parser": "glm47",
            "reasoning_parser": "glm45",
            "requires_vllm_nightly": True,
        }
