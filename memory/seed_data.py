"""
Seed ChromaDB collections from domain seed files.

Reads seed files from domains/{domain}/seed_data/{collection_name}.json.
Each file is a JSON array of:
    {"id": "unique_id", "text": "document content", "metadata": {"key": "value"}}

Usage:
    python -m memory.seed_data --domain cyberops --db-path ./data/chromadb
"""

import argparse
import json
from pathlib import Path

import chromadb

from config import BASE_DIR


def seed_domain(domain: str, db_path: str):
    """Load seed data into ChromaDB collections for a domain."""

    # Load collection definitions
    collections_file = BASE_DIR / "domains" / domain / "configs" / "memory_collections.json"
    if not collections_file.exists():
        print(f"Error: {collections_file} not found")
        return

    with open(collections_file) as f:
        config = json.load(f)

    collections = config.get("collections", [])
    seed_dir = BASE_DIR / "domains" / domain / "seed_data"

    # Connect to ChromaDB
    client = chromadb.PersistentClient(path=str(Path(db_path) / domain))

    total_seeded = 0

    for coll_def in collections:
        coll_id = coll_def["id"]
        coll_name = coll_def["name"]

        # Find seed file
        seed_file = seed_dir / f"{coll_name}.json"
        if not seed_file.exists():
            print(f"  [{coll_id}] {coll_name}: no seed file, skipping")
            continue

        with open(seed_file) as f:
            entries = json.load(f)

        if not entries:
            print(f"  [{coll_id}] {coll_name}: empty seed file, skipping")
            continue

        # Get or create collection
        collection = client.get_or_create_collection(name=coll_name)

        # Prepare batch
        ids = [e["id"] for e in entries]
        documents = [e["text"] for e in entries]
        metadatas = [e.get("metadata", {}) for e in entries]

        # Upsert (idempotent — safe to re-run)
        collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
        )

        total_seeded += len(entries)
        print(f"  [{coll_id}] {coll_name}: {len(entries)} entries seeded")

    print(f"\nTotal: {total_seeded} entries across {len(collections)} collections")


def main():
    parser = argparse.ArgumentParser(description="Seed ChromaDB collections from domain seed data")
    parser.add_argument("--domain", required=True, help="Domain name (cyberops, healthcare, etc.)")
    parser.add_argument("--db-path", default="./data/chromadb", help="ChromaDB persistent storage path")
    args = parser.parse_args()

    print(f"Seeding {args.domain} collections from domains/{args.domain}/seed_data/")
    print(f"Database path: {args.db_path}/{args.domain}/")
    print()
    seed_domain(args.domain, args.db_path)


if __name__ == "__main__":
    main()
