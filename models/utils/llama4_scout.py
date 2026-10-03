"""
Llama-4-Scout-17B-16E-Instruct — Validator 3

MoE model (109B total, 17B active per token, 16 experts).
GPU assignment: GPU 5, ~55GB FP8, single GPU.
Role: Third validator in multi-validator consensus (Meta Llama family = fourth model family for diversity).
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
MODEL_PATH = str(MODELS_DIR / "meta-llama" / "Llama-4-Scout-17B-16E-Instruct")
DEFAULT_PORT = 8004
DEFAULT_GPUS = "4,5"


class Llama4Scout:
    """Utility class for serving and querying Llama-4-Scout-17B-16E-Instruct."""

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
        tensor_parallel_size: int = 2,
        gpu_memory_utilization: float = 0.9,
        max_model_len: Optional[int] = None,
        dtype: str = "bfloat16",
        quantization: Optional[str] = None,
        enable_tool_choice: bool = False,
        tool_call_parser: str = "llama4_pythonic",
        extra_args: Optional[list[str]] = None,
    ) -> subprocess.Popen:
        """Start vLLM server with full configuration control.

        Llama 4 Scout uses the 'llama4_pythonic' tool-call parser.
        Default TP=2 on NVLink pair — model is 203GB at BF16, requires 2× H200.
        Default enable_tool_choice=False — validators primarily do structured validation, not tool calling.
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

    def serve_fp8(self, **kwargs) -> subprocess.Popen:
        """Serve with FP8 quantization (~55GB VRAM)."""
        return self.serve(quantization="fp8", **kwargs)

    def serve_multi_gpu(self, gpus: str = "4,5", **kwargs) -> subprocess.Popen:
        """Serve across multiple GPUs with tensor parallelism."""
        self.gpus = gpus
        return self.serve(tensor_parallel_size=2, gpu_memory_utilization=0.45, **kwargs)

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
        """Send a chat completion request."""
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

    def validate(
        self,
        proposal: str,
        context: str,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ):
        """Validate an agent proposal (primary use case as Validator 3).

        Returns a structured validation judgment given a proposal and incident context.
        """
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a security validation agent. Evaluate the proposed action "
                    "for correctness, safety, and appropriateness given the incident context. "
                    "Respond with JSON: {\"approved\": bool, \"confidence\": float, \"reasoning\": str, \"risks\": [str]}"
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
            response_format={"type": "json_object"},
        )

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
    #  Token counting & metadata
    # ------------------------------------------------------------------ #

    def list_models(self) -> list:
        """List models available on the vLLM server."""
        return self.client.models.list().data

    def get_config(self) -> dict:
        """Return the model configuration for logging/reproducibility."""
        return {
            "model_id": "meta-llama/Llama-4-Scout-17B-16E-Instruct",
            "model_path": self.model_path,
            "role": "validator_3",
            "architecture": "MoE",
            "total_params": "109B",
            "active_params": "17B",
            "num_experts": 16,
            "gpu_assignment": self.gpus,
            "port": self.port,
            "base_url": self.base_url,
            "tool_call_parser": "llama4_pythonic",
        }
