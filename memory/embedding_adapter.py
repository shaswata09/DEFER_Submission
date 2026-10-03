"""
ChromaDB Embedding Adapter

Wraps any embedding model into ChromaDB's EmbeddingFunction protocol.
Compatible with ChromaDB >= 1.0 (requires name, get_config, build_from_config, embed_query).

Usage:
    from models.utils import Qwen3Embedding
    from memory.embedding_adapter import ChromaEmbeddingAdapter

    emb = Qwen3Embedding()
    emb.load()

    adapter = ChromaEmbeddingAdapter(
        encode_fn=emb.encode,
        query_fn=emb.encode_queries,  # optional, for asymmetric encoding
        name="qwen3_embedding_8b",
    )

    collection = chroma_client.get_or_create_collection(
        name="threat_repo",
        embedding_function=adapter,
    )
"""

from typing import Callable, Optional


class ChromaEmbeddingAdapter:
    """Adapts any encode function into ChromaDB's embedding function protocol."""

    def __init__(
        self,
        encode_fn: Callable,
        query_fn: Optional[Callable] = None,
        adapter_name: str = "custom_embedding",
    ):
        """
        Args:
            encode_fn: Function that takes list[str] and returns array-like embeddings.
                       Used for embedding documents on add().
            query_fn: Optional separate function for embedding queries on query().
                      If None, encode_fn is used for both. Useful for models with
                      asymmetric encoding (e.g., Qwen3-Embedding adds instruction prefix for queries).
            adapter_name: Identifier returned by name() for ChromaDB config persistence.
        """
        self._encode_fn = encode_fn
        self._query_fn = query_fn or encode_fn
        self._name = adapter_name

    def __call__(self, input: list[str]) -> list[list[float]]:
        """Embed documents (called by ChromaDB on add/upsert)."""
        embeddings = self._encode_fn(input, normalize=True)
        return embeddings.tolist()

    def embed_query(self, input: list[str]) -> list[list[float]]:
        """Embed queries (called by ChromaDB on query).

        Uses query_fn if provided, which may add instruction prefixes
        for asymmetric retrieval models.
        """
        embeddings = self._query_fn(input)
        return embeddings.tolist()

    @staticmethod
    def name() -> str:
        return "custom_embedding"

    def get_config(self) -> dict:
        return {"name": self._name}

    @classmethod
    def build_from_config(cls, config: dict) -> "ChromaEmbeddingAdapter":
        raise NotImplementedError(
            "ChromaEmbeddingAdapter requires encode_fn at construction time. "
            "Reconstruct manually with the embedding model."
        )
