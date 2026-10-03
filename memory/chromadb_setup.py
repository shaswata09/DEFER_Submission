"""
Initialize ChromaDB collections for a given domain.

Reads the collection definitions from:
    domains/{domain}/configs/memory_collections.json

Format:
    {
        "collections": [
            {"id": "M1", "name": "threat_repository"},
            {"id": "M2", "name": "asset_inventory"},
            ...
        ]
    }

Creates a PersistentClient at db-path/{domain}/ and provisions each
collection using the ChromaEmbeddingAdapter backed by Qwen3-Embedding-8B.

Usage:
    python -m memory.chromadb_setup --domain cyberops --db-path ./data/chromadb
"""

import argparse
import json
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

from config import BASE_DIR
from memory.embedding_adapter import ChromaEmbeddingAdapter


def load_collection_config(domain: str) -> list[dict]:
    """Load memory_collections.json for the given domain.

    Returns:
        List of dicts with 'id' and 'name' keys.
    """
    config_path = BASE_DIR / "domains" / domain / "configs" / "memory_collections.json"
    with open(config_path, "r") as f:
        data = json.load(f)
    return data["collections"]


def build_embedding_adapter(model_path: str | Path) -> ChromaEmbeddingAdapter:
    """Load SentenceTransformer and wrap in ChromaEmbeddingAdapter.

    Args:
        model_path: Path to the embedding model directory.

    Returns:
        ChromaEmbeddingAdapter ready for use with ChromaDB collections.
    """
    model = SentenceTransformer(str(model_path), device="cpu")

    def encode_fn(texts: list[str], normalize: bool = True) -> "np.ndarray":
        return model.encode(texts, normalize_embeddings=normalize, device="cpu")

    adapter = ChromaEmbeddingAdapter(
        encode_fn=encode_fn,
        adapter_name="qwen3_embedding_8b",
    )
    return adapter


def setup_collections(
    domain: str,
    db_path: str | Path,
    model_path: str | Path | None = None,
) -> dict[str, "chromadb.Collection"]:
    """Create or retrieve all ChromaDB collections for a domain.

    Args:
        domain: Domain identifier (e.g. "cyberops").
        db_path: Base path for ChromaDB persistence. Collections are
                 stored under db_path/{domain}/.
        model_path: Path to the embedding model. Defaults to
                    BASE_DIR / "models" / "Qwen" / "Qwen3-Embedding-8B".

    Returns:
        Dict mapping collection ID (e.g. "M1") to chromadb.Collection.
    """
    if model_path is None:
        # Default to 0.6B for CPU speed; use --model-path for 8B on GPU
        model_path = BASE_DIR / "models" / "Qwen" / "Qwen3-Embedding-0.6B"

    db_path = Path(db_path) / domain
    db_path.mkdir(parents=True, exist_ok=True)

    client = chromadb.PersistentClient(path=str(db_path))
    adapter = build_embedding_adapter(model_path)

    collections_config = load_collection_config(domain)
    created: dict[str, chromadb.Collection] = {}

    for coll in collections_config:
        coll_id = coll["id"]
        coll_name = coll["name"]

        collection = client.get_or_create_collection(
            name=coll_name,
            embedding_function=adapter,
            metadata={"store_id": coll_id},
        )
        created[coll_id] = collection
        print(f"  [{coll_id}] {coll_name} — {collection.count()} documents")

    return created


def main():
    parser = argparse.ArgumentParser(
        description="Initialize ChromaDB collections for a DEFER domain.",
    )
    parser.add_argument(
        "--domain",
        type=str,
        default="cyberops",
        help="Domain identifier (default: cyberops).",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default="./data/chromadb",
        help="Base path for ChromaDB persistence (default: ./data/chromadb).",
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default=None,
        help="Path to embedding model (default: models/Qwen/Qwen3-Embedding-8B).",
    )
    args = parser.parse_args()

    print(f"Setting up ChromaDB collections for domain: {args.domain}")
    print(f"Database path: {args.db_path}/{args.domain}/")

    setup_collections(
        domain=args.domain,
        db_path=args.db_path,
        model_path=args.model_path,
    )

    print("Done.")


if __name__ == "__main__":
    main()
