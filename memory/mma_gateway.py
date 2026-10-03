"""
Memory Management Agent (MMA) Gateway -- FastAPI server.

Mediates ALL memory access in the DEFER configuration.
Enforces P4 (write-boundary filtering) and P5 (phase-partitioned access control).

Endpoints:
    POST /memory/read   -- query a collection (checks P5)
    POST /memory/write  -- write to a collection (checks P5 then P4)
    GET  /memory/list   -- list accessible stores for a phase

Usage:
    python -m memory.mma_gateway --domain cyberops --port 9100
"""

import argparse
import json
import time
from pathlib import Path
from typing import Optional

import chromadb
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from config import BASE_DIR, MODELS_DIR
from logging_utils import ExperimentLogger
from memory.access_control import AccessController, _normalize_store_id
from memory.write_filter import WriteFilter
from memory.memory_integrity import MemoryIntegrity
from memory.access_isolation import AccessIsolation


# ------------------------------------------------------------------ #
#  Request / Response schemas
# ------------------------------------------------------------------ #

class MemoryReadRequest(BaseModel):
    phase: str
    store_id: str
    query: str
    n_results: int = 5
    auth_token: str = ""  # Fix #7: request signing (no underscore for Pydantic)
    # Ablation switches forwarded by the orchestrator when running
    # principle-isolation experiments.  Default False -> full enforcement.
    skip_p5: bool = False
    # incident text for the P5-L3 relevance check (v3.1)
    context: str = ""


class MemoryWriteRequest(BaseModel):
    phase: str
    store_id: str
    document: str
    doc_id: str
    incident_evidence: str
    metadata: Optional[dict] = None
    auth_token: str = ""  # Fix #7: request signing
    # Ablation switches.  When set, MMA bypasses the corresponding check;
    # used by the host orchestrator when --disable-principles includes P4
    # or P5.  No-op for the production code path.
    skip_p4: bool = False
    skip_p5: bool = False
    # Harness pre-seeding (H5 ``memory`` channel): the entry is assumed to
    # already be in the store, so P4 / P5 are bypassed and the document is
    # tagged ``seeded`` + ``trial_id`` for /admin/reset.  Only honoured when
    # the gateway runs with HARNESS_INJECTION=1.
    harness_seed: bool = False


class AdminResetRequest(BaseModel):
    """Per-trial reset (H3): clears P4/P5 state and trial-tagged documents."""
    auth_token: str = ""
    trial_id: Optional[str] = None   # only this trial's documents; default: every tagged one


class AdminResetResponse(BaseModel):
    deleted_documents: int
    collections_touched: int
    integrity_reset: bool
    read_history_reset: bool


class MemoryListRequest(BaseModel):
    phase: str
    mode: str = "read"  # "read" or "write"


class MemoryReadResponse(BaseModel):
    store_id: str
    documents: list[str]
    metadatas: list[dict]
    distances: list[float]


class MemoryWriteResponse(BaseModel):
    store_id: str
    doc_id: str
    accepted: bool
    similarity_score: float


class MemoryListResponse(BaseModel):
    phase: str
    mode: str
    accessible_stores: list[str]


# ------------------------------------------------------------------ #
#  Application factory
# ------------------------------------------------------------------ #

def create_app(
    domain: str = "cyberops",
    db_path: str = "./data/chromadb",
    embedding_model_path: str | None = None,
    similarity_threshold: float = 0.5,
) -> FastAPI:
    """Build and return the FastAPI application with all dependencies wired up.

    Args:
        domain: Domain identifier.
        db_path: Base path to ChromaDB persistence.
        embedding_model_path: Path to embedding model for WriteFilter.
        similarity_threshold: Cosine similarity threshold for P4 filtering.

    Returns:
        Configured FastAPI app.
    """
    if embedding_model_path is None:
        embedding_model_path = str(MODELS_DIR / "Qwen" / "Qwen3-Embedding-8B")

    app = FastAPI(
        title="MMA Gateway",
        description="Memory Management Agent -- mediates all memory access in DEFER.",
        version="0.1.0",
    )

    # -- Fix #7: Load shared secret for request signing ----------------
    import os as _os
    import hmac as _hmac
    import hashlib as _hashlib

    _mma_secret = _os.environ.get("MMA_SHARED_SECRET", "")
    if not _mma_secret:
        _secret_path = BASE_DIR / "configs" / "hmac_key.txt"
        if _secret_path.exists():
            _mma_secret = _secret_path.read_text().strip()

    def _verify_auth_token(phase: str, store_id: str, token: str) -> bool:
        """Verify request came from the orchestrator, not a rogue caller."""
        if not _mma_secret:
            return True  # No secret configured — skip verification
        expected = _hmac.new(
            _mma_secret.encode(),
            f"{phase}:{store_id}".encode(),
            _hashlib.sha256,
        ).hexdigest()[:16]
        return token == expected

    # -- Dependencies ---------------------------------------------------

    access_controller = AccessController(domain=domain)

    write_filter = WriteFilter(
        embedding_model_path=embedding_model_path,
        similarity_threshold=similarity_threshold,
    )

    # Enhanced P4: multi-layer memory integrity (wraps WriteFilter)
    memory_integrity = MemoryIntegrity(
        domain=domain,
        write_filter=write_filter,
        embedding_model=write_filter._model,  # share the loaded model
    )

    # Enhanced P5: multi-layer access isolation (wraps AccessController)
    access_isolation = AccessIsolation(
        domain=domain,
        access_controller=access_controller,
        embedding_model=write_filter._model,
    )

    chroma_path = Path(db_path) / domain
    chroma_client = chromadb.PersistentClient(path=str(chroma_path))

    # Load collection name mapping: store_id -> collection_name
    collections_config_path = (
        BASE_DIR / "domains" / domain / "configs" / "memory_collections.json"
    )
    with open(collections_config_path, "r") as f:
        coll_data = json.load(f)
    store_id_to_name: dict[str, str] = {
        c["id"]: c["name"] for c in coll_data["collections"]
    }

    logger = ExperimentLogger(
        eval_name="mma_gateway",
        domain=domain,
        config="agenticcyops",
        model="Qwen3-Embedding-8B",
    )

    # -- Helpers --------------------------------------------------------

    def _get_collection(store_id: str):
        # Accept either short ("M1") or long-form ("M1_threat_repository")
        # IDs.  Caller may pass whichever the agent emitted; normalization
        # mirrors AccessController.can_read/can_write.
        coll_name = (store_id_to_name.get(store_id)
                     or store_id_to_name.get(_normalize_store_id(store_id)))
        if coll_name is None:
            raise HTTPException(
                status_code=404,
                detail=f"Unknown store_id: {store_id}",
            )
        return chroma_client.get_or_create_collection(name=coll_name)

    # -- Endpoints ------------------------------------------------------

    @app.post("/memory/read", response_model=MemoryReadResponse)
    def memory_read(req: MemoryReadRequest):
        """Query a collection. Enforces P5 L1-L5."""
        start = time.perf_counter()

        # Fix #7: Verify request came from orchestrator
        if _mma_secret and not _verify_auth_token(req.phase, req.store_id, req.auth_token):
            raise HTTPException(status_code=403, detail="Invalid auth token.")

        # P5-L1: Phase-store access control (skipped under -P5 ablation)
        if (not req.skip_p5
                and not access_controller.can_read(req.phase, req.store_id)):
            latency = (time.perf_counter() - start) * 1000
            logger.log_memory_read(
                agent=req.phase,
                store=req.store_id,
                auth_decision="deny",
                mechanism="P5_access_control",
                latency_ms=latency,
            )
            raise HTTPException(
                status_code=403,
                detail=f"Phase '{req.phase}' is not allowed to read from '{req.store_id}'.",
            )

        # P5-L3 / L4: query scope and read-pattern checks.  Skipped under
        # the -P5 ablation and for the flat / acl_hardened systems, which
        # have no gateway defenses (the host sets skip_p5 for them, H4).
        if not req.skip_p5:
            context = req.context
            ok, reason, details = access_isolation.validate_query(
                req.phase, req.store_id, req.query, context
            )
            if not ok:
                latency = (time.perf_counter() - start) * 1000
                logger.log_memory_read(
                    agent=req.phase,
                    store=req.store_id,
                    auth_decision="deny",
                    mechanism=reason,
                    latency_ms=latency,
                )
                raise HTTPException(status_code=422, detail=reason)

            ok, reason, details = access_isolation.check_read_pattern(
                req.phase, req.store_id, req.query
            )
            if not ok:
                latency = (time.perf_counter() - start) * 1000
                logger.log_memory_read(
                    agent=req.phase,
                    store=req.store_id,
                    auth_decision="deny",
                    mechanism=reason,
                    latency_ms=latency,
                )
                raise HTTPException(status_code=429, detail=reason)

        # Execute query
        collection = _get_collection(req.store_id)
        results = collection.query(
            query_texts=[req.query],
            n_results=req.n_results,
        )

        documents = results["documents"][0] if results["documents"] else []
        metadatas = results["metadatas"][0] if results["metadatas"] else []
        distances = results["distances"][0] if results["distances"] else []

        if not req.skip_p5:
            # P5-L5: Sanitize results (strip prompt injections)
            result_entries = [
                {"text": doc, "metadata": meta}
                for doc, meta in zip(documents, metadatas)
            ]
            sanitized = access_isolation.sanitize_results(result_entries, req.phase)
            documents = [e.get("text", "") for e in sanitized]
            metadatas = [e.get("metadata", {}) for e in sanitized]

            # P5-L2: Field-level filtering
            filtered = access_isolation.filter_fields(
                req.phase, req.store_id,
                [{"text": d, "metadata": m} for d, m in zip(documents, metadatas)]
            )
            documents = [e.get("text", "") for e in filtered]
            metadatas = [e.get("metadata", {}) for e in filtered]

        latency = (time.perf_counter() - start) * 1000
        logger.log_memory_read(
            agent=req.phase,
            store=req.store_id,
            auth_decision="allow",
            mechanism="P5_disabled_accept" if req.skip_p5 else "P5_access_control",
            latency_ms=latency,
            num_results=len(documents),
        )

        return MemoryReadResponse(
            store_id=req.store_id,
            documents=documents,
            metadatas=metadatas,
            distances=distances,
        )

    @app.post("/memory/write", response_model=MemoryWriteResponse)
    def memory_write(req: MemoryWriteRequest):
        """Write to a collection. Enforces P5-L1 then P4 L1-L6."""
        start = time.perf_counter()

        # Fix #7: Verify request came from orchestrator
        if _mma_secret and not _verify_auth_token(req.phase, req.store_id, req.auth_token):
            raise HTTPException(status_code=403, detail="Invalid auth token.")

        if req.harness_seed:
            if _os.environ.get("HARNESS_INJECTION", "") != "1":
                raise HTTPException(status_code=403,
                                    detail="seeding disabled (HARNESS_INJECTION != 1)")
            req.skip_p4 = True
            req.skip_p5 = True

        # P5-L1: Phase-store access control (skipped under -P5 ablation)
        if (not req.skip_p5
                and not access_controller.can_write(req.phase, req.store_id)):
            latency = (time.perf_counter() - start) * 1000
            logger.log_memory_write(
                agent=req.phase,
                store=req.store_id,
                auth_decision="deny",
                mechanism="P5_access_control",
                latency_ms=latency,
            )
            raise HTTPException(
                status_code=403,
                detail=f"Phase '{req.phase}' is not allowed to write to '{req.store_id}'.",
            )

        # P4: Multi-layer memory integrity (skipped under -P4 ablation)
        score = 0.0
        if not req.skip_p4:
            metadata = req.metadata or {}
            allowed, reason, details = memory_integrity.validate_write(
                store_id=req.store_id,
                content=req.document,
                metadata=metadata,
                incident_evidence=req.incident_evidence,
            )
            score = details.get("similarity", 0.0)

            if not allowed:
                latency = (time.perf_counter() - start) * 1000
                logger.log_memory_write(
                    agent=req.phase,
                    store=req.store_id,
                    auth_decision="deny",
                    mechanism=reason,
                    latency_ms=latency,
                    payload=req.document,
                    cosine_similarity=score,
                )
                raise HTTPException(
                    status_code=422,
                    detail=f"Write rejected: {reason}. {details}",
                )
        else:
            metadata = req.metadata or {}

        # Write accepted — upsert into ChromaDB
        collection = _get_collection(req.store_id)
        metadata["phase"] = req.phase
        metadata["store_id"] = req.store_id
        # Every harness write is tagged with its trial so /admin/reset can
        # remove it; untagged (seed) documents are never touched.
        metadata.setdefault("trial_id", "")
        if req.harness_seed:
            metadata["seeded"] = True

        collection.upsert(
            ids=[req.doc_id],
            documents=[req.document],
            metadatas=[metadata],
        )

        latency = (time.perf_counter() - start) * 1000
        # When -P4 ablation is in effect we accept the write without
        # running integrity checks; flag this in the mechanism string so
        # analytics can tell the ablation accepts apart from genuine
        # P4 approvals.
        success_mech = ("harness_seed" if req.harness_seed
                        else "P4_disabled_accept" if req.skip_p4
                        else "P4_memory_integrity")
        logger.log_memory_write(
            agent=req.phase,
            store=req.store_id,
            auth_decision="allow",
            mechanism=success_mech,
            latency_ms=latency,
            payload=req.document,
            cosine_similarity=score,
        )

        return MemoryWriteResponse(
            store_id=req.store_id,
            doc_id=req.doc_id,
            accepted=True,
            similarity_score=round(score, 4),
        )

    @app.post("/admin/reset", response_model=AdminResetResponse)
    def admin_reset(req: AdminResetRequest):
        """Return the gateway to its baseline between trials (H3).

        Deletes every document whose metadata carries a ``trial_id`` (or
        only ``req.trial_id`` when given), so seed documents written
        without a tag survive; clears P4 write hashes / centroids and the
        P5-L4 read history.
        """
        if _mma_secret and not _verify_auth_token("admin", "reset", req.auth_token):
            raise HTTPException(status_code=403, detail="Invalid auth token.")
        deleted = 0
        touched = 0
        for coll_name in set(store_id_to_name.values()):
            try:
                collection = chroma_client.get_or_create_collection(name=coll_name)
                # Chroma's $ne also matches documents that have no such key
                # at all (the seed data), so the filter is applied here.
                got = collection.get(include=["metadatas"])
                ids = [i for i, m in zip(got.get("ids") or [], got.get("metadatas") or [])
                       if isinstance(m, dict) and m.get("trial_id")
                       and (not req.trial_id or m.get("trial_id") == req.trial_id)]
                if ids:
                    collection.delete(ids=ids)
                    deleted += len(ids)
                    touched += 1
            except Exception:
                # a collection with no metadata index yet raises on `where`
                continue
        memory_integrity.reset()
        access_isolation.reset()
        logger.log(source="host", destination="mma_gateway", action="admin_reset",
                   extra={"deleted_documents": deleted, "collections_touched": touched,
                          "trial_id": req.trial_id})
        return AdminResetResponse(deleted_documents=deleted, collections_touched=touched,
                                  integrity_reset=True, read_history_reset=True)

    @app.get("/memory/list", response_model=MemoryListResponse)
    def memory_list(phase: str, mode: str = "read", auth_token: str = ""):
        """List accessible stores for a given phase and mode."""
        if _mma_secret and not _verify_auth_token(phase, f"list_{mode}", auth_token):
            raise HTTPException(status_code=403, detail="Invalid auth token.")
        stores = access_controller.accessible_stores(phase, mode)

        logger.log(
            source=phase,
            destination="mma_gateway",
            action="memory_list",
            extra={"mode": mode, "accessible_stores": stores},
        )

        return MemoryListResponse(
            phase=phase,
            mode=mode,
            accessible_stores=stores,
        )

    return app


# ------------------------------------------------------------------ #
#  CLI entry point
# ------------------------------------------------------------------ #

def main():
    parser = argparse.ArgumentParser(
        description="MMA Gateway -- FastAPI server for DEFER memory access.",
    )
    parser.add_argument(
        "--domain",
        type=str,
        default="cyberops",
        help="Domain identifier (default: cyberops).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9100,
        help="Port to listen on (default: 9100).",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0).",
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
    parser.add_argument(
        "--similarity-threshold",
        type=float,
        default=0.5,
        help="Cosine similarity threshold for P4 write filter (default: 0.5).",
    )
    args = parser.parse_args()

    import uvicorn

    app = create_app(
        domain=args.domain,
        db_path=args.db_path,
        embedding_model_path=args.model_path,
        similarity_threshold=args.similarity_threshold,
    )

    print(f"Starting MMA Gateway on {args.host}:{args.port}")
    print(f"Domain: {args.domain}")
    print(f"ChromaDB path: {args.db_path}/{args.domain}/")

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
