"""
Qwen3-Embedding-0.6B — Lightweight Embedding Model for CPU Operation

Fast CPU inference (~1.2GB). Same API as Qwen3-Embedding-8B but smaller.
Used when GPUs are occupied by LLM servers. Sufficient quality for
write-boundary filtering and ChromaDB seed operations.

Embedding dim: 1024 (vs 4096 for 8B). Matryoshka supported (32–1024).
"""

import os
from pathlib import Path
from typing import Optional, Union

import numpy as np
import torch
from sentence_transformers import SentenceTransformer


MODELS_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = str(MODELS_DIR / "Qwen" / "Qwen3-Embedding-0.6B")


class Qwen3EmbeddingSmall:
    """Utility class for Qwen3-Embedding-0.6B. Optimized for CPU."""

    def __init__(
        self,
        model_path: str = MODEL_PATH,
        device: str = "cpu",
        embedding_dim: int = 1024,
    ):
        self.model_path = model_path
        self.device = device
        self.embedding_dim = embedding_dim
        self._model: Optional[SentenceTransformer] = None

    # ------------------------------------------------------------------ #
    #  Model lifecycle
    # ------------------------------------------------------------------ #

    def load(self, device: Optional[str] = None) -> SentenceTransformer:
        """Load the embedding model."""
        device = device or self.device
        self._model = SentenceTransformer(
            self.model_path,
            device=device,
            trust_remote_code=True,
        )
        return self._model

    def load_cpu(self) -> SentenceTransformer:
        """Load on CPU (default and recommended)."""
        self.device = "cpu"
        return self.load(device="cpu")

    def load_gpu(self, gpu_id: int = 0) -> SentenceTransformer:
        """Load on a specific GPU if available."""
        device = f"cuda:{gpu_id}"
        self.device = device
        return self.load(device=device)

    def unload(self):
        """Free the model from memory."""
        self._model = None
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

    @property
    def model(self) -> SentenceTransformer:
        if self._model is None:
            self.load()
        return self._model

    # ------------------------------------------------------------------ #
    #  Encoding
    # ------------------------------------------------------------------ #

    def encode(
        self,
        texts: Union[str, list[str]],
        batch_size: int = 64,
        normalize: bool = True,
        show_progress: bool = False,
    ) -> np.ndarray:
        """Encode text(s) into embeddings. Use for documents."""
        if isinstance(texts, str):
            texts = [texts]
        embs = self.model.encode(
            texts,
            batch_size=batch_size,
            normalize_embeddings=normalize,
            show_progress_bar=show_progress,
        )
        if self.embedding_dim < embs.shape[1]:
            embs = embs[:, :self.embedding_dim]
            if normalize:
                embs = embs / np.linalg.norm(embs, axis=1, keepdims=True)
        return embs

    def encode_queries(
        self,
        queries: Union[str, list[str]],
        batch_size: int = 64,
        normalize: bool = True,
    ) -> np.ndarray:
        """Encode queries with instruction prefix for retrieval."""
        if isinstance(queries, str):
            queries = [queries]
        return self.model.encode(
            queries,
            prompt_name="query",
            batch_size=batch_size,
            normalize_embeddings=normalize,
        )

    def encode_documents(
        self,
        documents: Union[str, list[str]],
        batch_size: int = 64,
        normalize: bool = True,
    ) -> np.ndarray:
        """Encode documents (no prefix)."""
        return self.encode(documents, batch_size=batch_size, normalize=normalize)

    # ------------------------------------------------------------------ #
    #  Matryoshka
    # ------------------------------------------------------------------ #

    def set_embedding_dim(self, dim: int):
        """Set embedding dimension (Matryoshka, 32–1024)."""
        if not 32 <= dim <= 1024:
            raise ValueError(f"Dimension must be 32–1024, got {dim}")
        self.embedding_dim = dim

    # ------------------------------------------------------------------ #
    #  Similarity
    # ------------------------------------------------------------------ #

    def similarity(self, texts_a: Union[str, list[str]], texts_b: Union[str, list[str]]) -> np.ndarray:
        """Cosine similarity between two sets of texts."""
        emb_a = self.encode(texts_a, normalize=True)
        emb_b = self.encode(texts_b, normalize=True)
        return emb_a @ emb_b.T

    def query_document_similarity(
        self, queries: Union[str, list[str]], documents: Union[str, list[str]]
    ) -> np.ndarray:
        """Similarity with asymmetric query/document encoding."""
        emb_q = self.encode_queries(queries)
        emb_d = self.encode_documents(documents)
        return emb_q @ emb_d.T

    def pairwise_similarity(self, texts: list[str]) -> np.ndarray:
        """Pairwise cosine similarity matrix."""
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
        """Rank documents by relevance to a query."""
        scores = self.query_document_similarity(query, documents).flatten()
        ranked = np.argsort(scores)[::-1]
        if top_k:
            ranked = ranked[:top_k]
        return [
            {"index": int(i), "score": float(scores[i]), "text": documents[i]}
            for i in ranked
        ]

    # ------------------------------------------------------------------ #
    #  Metadata
    # ------------------------------------------------------------------ #

    def get_embedding_dimension(self) -> int:
        return self.embedding_dim

    def get_config(self) -> dict:
        return {
            "model_id": "Qwen/Qwen3-Embedding-0.6B",
            "model_path": self.model_path,
            "role": "embedding_model_lightweight",
            "device": self.device,
            "embedding_dim": self.embedding_dim,
            "max_embedding_dim": 1024,
            "matryoshka_supported": True,
            "use_case": "cpu_chromadb_write_filter",
            "pooling": "last_token",
        }
