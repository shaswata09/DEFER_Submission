"""
Qwen3-Embedding-8B — Embedding Model for ChromaDB / RAG Memory Layer

#1 on MTEB multilingual leaderboard (score 70.58 as of June 2025).
Supports 100+ languages, Matryoshka dimensions (32–4096), last-token pooling.
Runs on CPU or any GPU (~16GB VRAM in BF16, less with quantization).
Role: Used by Memory Management Agent for semantic search and
      write-boundary filtering (cosine similarity checks via P4).
"""

import os
from pathlib import Path
from typing import Optional, Union

import numpy as np
import torch
import torch.nn.functional as F
from transformers import AutoModel, AutoTokenizer
from sentence_transformers import SentenceTransformer


MODELS_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = str(MODELS_DIR / "Qwen" / "Qwen3-Embedding-8B")


class Qwen3Embedding:
    """Utility class for loading and running Qwen3-Embedding-8B embeddings."""

    def __init__(
        self,
        model_path: str = MODEL_PATH,
        device: Optional[str] = None,
        embedding_dim: int = 4096,
    ):
        self.model_path = model_path
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.embedding_dim = embedding_dim
        self._st_model: Optional[SentenceTransformer] = None
        self._hf_model = None
        self._hf_tokenizer = None

    # ------------------------------------------------------------------ #
    #  Model lifecycle — SentenceTransformer (recommended)
    # ------------------------------------------------------------------ #

    def load(
        self,
        device: Optional[str] = None,
        trust_remote_code: bool = True,
        use_flash_attention: bool = False,
    ) -> SentenceTransformer:
        """Load the embedding model via SentenceTransformer (recommended)."""
        device = device or self.device
        model_kwargs = {}
        tokenizer_kwargs = {"padding_side": "left"}
        if use_flash_attention:
            model_kwargs["attn_implementation"] = "flash_attention_2"
            model_kwargs["device_map"] = "auto"

        self._st_model = SentenceTransformer(
            self.model_path,
            device=device,
            trust_remote_code=trust_remote_code,
            model_kwargs=model_kwargs,
            tokenizer_kwargs=tokenizer_kwargs,
        )
        return self._st_model

    def load_flash_attn(self, **kwargs) -> SentenceTransformer:
        """Load with Flash Attention 2 for faster inference on GPU."""
        return self.load(use_flash_attention=True, **kwargs)

    def load_cpu(self, **kwargs) -> SentenceTransformer:
        """Force loading on CPU regardless of GPU availability."""
        self.device = "cpu"
        return self.load(device="cpu", **kwargs)

    def load_gpu(self, gpu_id: int = 0, **kwargs) -> SentenceTransformer:
        """Load on a specific GPU."""
        device = f"cuda:{gpu_id}"
        self.device = device
        return self.load(device=device, **kwargs)

    # ------------------------------------------------------------------ #
    #  Model lifecycle — Transformers (manual, for advanced use)
    # ------------------------------------------------------------------ #

    def load_transformers(
        self,
        device: Optional[str] = None,
        torch_dtype=torch.bfloat16,
        attn_implementation: str = "eager",
    ):
        """Load via raw transformers (for manual pooling / advanced control).

        Uses eager attention by default — cuDNN SDPA has compatibility issues
        with Qwen3-Embedding on H200 GPUs.
        """
        device = device or self.device
        self._hf_tokenizer = AutoTokenizer.from_pretrained(
            self.model_path, padding_side="left"
        )
        self._hf_model = AutoModel.from_pretrained(
            self.model_path,
            torch_dtype=torch_dtype,
            attn_implementation=attn_implementation,
        ).to(device)
        self._hf_model.eval()
        return self._hf_model, self._hf_tokenizer

    # ------------------------------------------------------------------ #
    #  Unload
    # ------------------------------------------------------------------ #

    def unload(self):
        """Free the model from memory."""
        self._st_model = None
        self._hf_model = None
        self._hf_tokenizer = None
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

    @property
    def model(self) -> SentenceTransformer:
        """Get the loaded SentenceTransformer model, loading it if necessary."""
        if self._st_model is None:
            self.load()
        return self._st_model

    # ------------------------------------------------------------------ #
    #  Encoding — SentenceTransformer API
    # ------------------------------------------------------------------ #

    def encode(
        self,
        texts: Union[str, list[str]],
        batch_size: int = 32,
        normalize: bool = True,
        show_progress: bool = False,
    ) -> np.ndarray:
        """Encode text(s) into embedding vectors (no instruction prefix).

        Use this for documents/passages. For queries, use encode_queries().

        Returns:
            numpy array of shape (n_texts, embedding_dim).
        """
        if isinstance(texts, str):
            texts = [texts]
        embs = self.model.encode(
            texts,
            batch_size=batch_size,
            normalize_embeddings=normalize,
            show_progress_bar=show_progress,
        )
        if self.embedding_dim < 4096:
            embs = embs[:, :self.embedding_dim]
            if normalize:
                embs = embs / np.linalg.norm(embs, axis=1, keepdims=True)
        return embs

    def encode_queries(
        self,
        queries: Union[str, list[str]],
        task_description: str = "Given a web search query, retrieve relevant passages that answer the query",
        batch_size: int = 32,
        normalize: bool = True,
    ) -> np.ndarray:
        """Encode search queries with Qwen3 instruction prefix.

        Qwen3-Embedding uses 'Instruct: {task}\\nQuery:{query}' format for queries.
        The sentence-transformers integration handles this via prompt_name="query".

        Args:
            queries: Query text(s) to encode.
            task_description: Task instruction in English. Custom instructions
                              improve retrieval by 1-5% over generic ones.
        """
        if isinstance(queries, str):
            queries = [queries]
        embs = self.model.encode(
            queries,
            prompt_name="query",
            batch_size=batch_size,
            normalize_embeddings=normalize,
            show_progress_bar=False,
        )
        if self.embedding_dim < 4096:
            embs = embs[:, :self.embedding_dim]
            if normalize:
                embs = embs / np.linalg.norm(embs, axis=1, keepdims=True)
        return embs

    def encode_documents(
        self,
        documents: Union[str, list[str]],
        batch_size: int = 32,
        normalize: bool = True,
    ) -> np.ndarray:
        """Encode documents/passages (no instruction prefix, per Qwen3 spec)."""
        return self.encode(documents, batch_size=batch_size, normalize=normalize)

    # ------------------------------------------------------------------ #
    #  Encoding — Transformers API (manual last-token pooling)
    # ------------------------------------------------------------------ #

    def encode_transformers(
        self,
        texts: Union[str, list[str]],
        instruction: Optional[str] = None,
        max_length: int = 8192,
        normalize: bool = True,
    ) -> np.ndarray:
        """Encode using raw transformers with manual last-token pooling.

        Args:
            texts: Text(s) to encode.
            instruction: If provided, prepend 'Instruct: {instruction}\\nQuery:{text}'
                         format (use for queries only, not documents).
        """
        if self._hf_model is None or self._hf_tokenizer is None:
            raise RuntimeError("Call load_transformers() first")

        if isinstance(texts, str):
            texts = [texts]
        if instruction:
            texts = [f"Instruct: {instruction}\nQuery:{t}" for t in texts]

        batch_dict = self._hf_tokenizer(
            texts, padding=True, truncation=True,
            max_length=max_length, return_tensors="pt",
        ).to(self._hf_model.device)

        with torch.no_grad():
            outputs = self._hf_model(**batch_dict)

        # Last-token pooling
        attention_mask = batch_dict["attention_mask"]
        last_token_indices = attention_mask.sum(dim=1) - 1
        embeddings = outputs.last_hidden_state[
            torch.arange(len(texts), device=outputs.last_hidden_state.device),
            last_token_indices,
        ]

        if self.embedding_dim < 4096:
            embeddings = embeddings[:, :self.embedding_dim]
        if normalize:
            embeddings = F.normalize(embeddings, p=2, dim=1)

        return embeddings.cpu().float().numpy()

    # ------------------------------------------------------------------ #
    #  Matryoshka dimension control
    # ------------------------------------------------------------------ #

    def set_embedding_dim(self, dim: int):
        """Set the embedding dimension (Matryoshka, range 32–4096).

        Lower dimensions trade accuracy for speed/storage. Useful for
        rapid prototyping or memory-constrained ChromaDB deployments.
        """
        if not 32 <= dim <= 4096:
            raise ValueError(f"Dimension must be 32–4096, got {dim}")
        self.embedding_dim = dim

    # ------------------------------------------------------------------ #
    #  Similarity
    # ------------------------------------------------------------------ #

    def similarity(self, texts_a: Union[str, list[str]], texts_b: Union[str, list[str]]) -> np.ndarray:
        """Compute cosine similarity between two sets of texts.

        Returns:
            Similarity matrix of shape (len(texts_a), len(texts_b)).
        """
        emb_a = self.encode(texts_a, normalize=True)
        emb_b = self.encode(texts_b, normalize=True)
        return emb_a @ emb_b.T

    def query_document_similarity(
        self, queries: Union[str, list[str]], documents: Union[str, list[str]]
    ) -> np.ndarray:
        """Compute similarity between queries and documents using appropriate prefixes."""
        emb_q = self.encode_queries(queries)
        emb_d = self.encode_documents(documents)
        return emb_q @ emb_d.T

    def pairwise_similarity(self, texts: list[str]) -> np.ndarray:
        """Compute pairwise cosine similarity matrix for a set of texts."""
        emb = self.encode(texts, normalize=True)
        return emb @ emb.T

    # ------------------------------------------------------------------ #
    #  Retrieval
    # ------------------------------------------------------------------ #

    def rank_documents(
        self,
        query: str,
        documents: list[str],
        top_k: Optional[int] = None,
    ) -> list[dict]:
        """Rank documents by relevance to a query.

        Returns:
            List of dicts with 'index', 'score', and 'text' keys, sorted by score descending.
        """
        scores = self.query_document_similarity(query, documents).flatten()
        ranked_indices = np.argsort(scores)[::-1]
        if top_k:
            ranked_indices = ranked_indices[:top_k]
        return [
            {"index": int(i), "score": float(scores[i]), "text": documents[i]}
            for i in ranked_indices
        ]

    # ------------------------------------------------------------------ #
    #  Metadata
    # ------------------------------------------------------------------ #

    def get_embedding_dimension(self) -> int:
        """Return the current embedding dimensionality."""
        return self.embedding_dim

    def get_config(self) -> dict:
        """Return the model configuration for logging/reproducibility."""
        return {
            "model_id": "Qwen/Qwen3-Embedding-8B",
            "model_path": self.model_path,
            "role": "embedding_model",
            "device": self.device,
            "embedding_dim": self.embedding_dim,
            "max_embedding_dim": 4096,
            "matryoshka_supported": True,
            "use_case": "chromadb_rag_memory_layer",
            "pooling": "last_token",
            "instruction_format": "Instruct: {task}\\nQuery:{query}",
            "languages": "100+",
        }
