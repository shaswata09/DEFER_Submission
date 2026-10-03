"""
P4: Memory Integrity -- Multi-layer write validation.
L1: Schema validation (required fields, types, enums, content length)
L2: Embedding similarity (delegated to WriteFilter)
L3: Metadata validation (MITRE IDs, severity, date sanity)
L4: Drift detection (centroid distance, centroid shift)
L5: Write replay detection (content hash dedup)
L6: Contradiction detection (LLM, for critical stores and ambiguous similarity)
Covers: MA-3, MA-4, MA-5, MA-6, MA-8, MA-12
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import numpy as np

from config import BASE_DIR
from memory.write_filter import WriteFilter


class MemoryIntegrity:
    """P4: Multi-layer memory integrity validation.

    Wraps the existing WriteFilter (L2) with additional layers:
    L1 schema, L3 metadata, L4 drift, L5 replay, L6 contradiction.
    """

    CRITICAL_STORES = {"M1", "M6", "HM1", "FM3", "LM3"}

    VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}

    def __init__(
        self,
        domain: str,
        write_filter: Optional[WriteFilter] = None,
        embedding_model=None,
        logger=None,
    ):
        """
        Args:
            domain: Domain identifier (e.g. "cyberops").
            write_filter: Existing WriteFilter instance for L2 similarity.
                          If None, a default WriteFilter is created.
            embedding_model: SentenceTransformer model for L4 drift embeddings.
                             If None, reuses the write_filter's internal model.
            logger: ExperimentLogger instance for structured logging.
        """
        self.domain = domain
        self._logger = logger

        # -- L1: Load schema config -------------------------------------------
        schema_path = BASE_DIR / "domains" / domain / "configs" / "memory_schemas.json"
        if schema_path.exists():
            with open(schema_path, "r") as f:
                self._schemas: dict = json.load(f)
        else:
            self._schemas = {}

        # -- L3: Load MITRE techniques (optional, cyberops only) ---------------
        mitre_path = BASE_DIR / "domains" / domain / "configs" / "mitre_techniques.json"
        if mitre_path.exists():
            with open(mitre_path, "r") as f:
                mitre_data = json.load(f)
            self._valid_mitre_ids: set[str] = set(mitre_data.get("valid_ids", []))
        else:
            self._valid_mitre_ids = set()

        # -- L2: WriteFilter ---------------------------------------------------
        if write_filter is not None:
            self._write_filter = write_filter
        else:
            self._write_filter = WriteFilter()

        # -- Embedding model for L4 drift --------------------------------------
        if embedding_model is not None:
            self._embedding_model = embedding_model
        else:
            # Reuse the write filter's internal model
            self._embedding_model = self._write_filter._model

        # -- L4: Drift centroids -----------------------------------------------
        self._centroids: dict[str, dict] = {}
        # store_id -> {"emb": np.ndarray, "count": int, "max_dist": float}

        # -- L5: Write replay hashes -------------------------------------------
        self._write_hashes: dict[str, dict] = {}
        # store_id -> {content_hash: True}

    # ------------------------------------------------------------------ #
    #  Main validation entry point
    # ------------------------------------------------------------------ #

    def validate_write(
        self,
        store_id: str,
        content: str,
        metadata: Optional[dict],
        incident_evidence: str,
        context_severity: Optional[str] = None,
    ) -> tuple[bool, str, dict]:
        """Run all integrity layers sequentially.

        Args:
            store_id: Memory store identifier (e.g. "M1", "M6").
            content: The text to be written.
            metadata: Key-value metadata accompanying the write.
            incident_evidence: Reference text for the current incident.
            context_severity: Optional severity context for adaptive checks.

        Returns:
            Tuple of (allowed, reason, details).
            reason is a P4_* code. details contains layer-specific info.
        """
        metadata = metadata or {}

        # -- L1: Schema validation ---------------------------------------------
        ok, reason, details = self._check_schema(store_id, content, metadata)
        if not ok:
            return (False, reason, details)

        # -- L2: Embedding similarity (delegated to WriteFilter) ---------------
        allowed, score = self._write_filter.validate_write(
            content=content,
            incident_evidence=incident_evidence,
        )
        similarity_score = score

        if score < 0.3:
            return (
                False,
                "P4_similarity_reject",
                {"similarity": round(score, 4), "threshold": 0.3},
            )

        if not allowed:
            return (
                False,
                "P4_similarity_reject",
                {
                    "similarity": round(score, 4),
                    "threshold": self._write_filter.threshold,
                },
            )

        # -- L3: Metadata validation -------------------------------------------
        ok, reason, details = self._check_metadata(metadata)
        if not ok:
            return (False, reason, details)

        # -- L4: Drift detection -----------------------------------------------
        ok, reason, details = self._check_drift(store_id, content)
        if not ok:
            return (False, reason, details)

        # -- L5: Write replay detection ----------------------------------------
        ok, reason, details = self._check_write_replay(store_id, content)
        if not ok:
            return (False, reason, details)

        # -- L6: Contradiction detection ---------------------------------------
        needs_check = (
            similarity_score < 0.7  # ambiguous zone
            or store_id in self.CRITICAL_STORES  # MA-12 fix
            or "status" in metadata  # status changes
        )
        if needs_check:
            # Pass store_id via metadata so contradiction check can use it
            meta_with_store = {**metadata, "store_id": store_id}
            ok, reason, details = self._check_contradiction(
                content, incident_evidence, meta_with_store
            )
            if not ok:
                return (False, reason, details)

        # -- All layers passed -------------------------------------------------
        # Record write hash (L5)
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if store_id not in self._write_hashes:
            self._write_hashes[store_id] = {}
        self._write_hashes[store_id][content_hash] = True

        # Update centroid (L4)
        self._update_centroid(store_id, content)

        return (
            True,
            "P4_all_passed",
            {"similarity": round(similarity_score, 4)},
        )

    # ------------------------------------------------------------------ #
    #  L1: Schema validation
    # ------------------------------------------------------------------ #

    def _check_schema(
        self,
        store_id: str,
        content: str,
        metadata: dict,
    ) -> tuple[bool, str, dict]:
        """Validate content and metadata against the schema for store_id.

        Checks required_metadata fields, enum values, and content length.
        Stores without a schema definition pass automatically.
        """
        schema = self._schemas.get(store_id)
        if schema is None:
            return (True, "P4_schema_no_config", {})

        violations = []

        # Required metadata fields
        for field in schema.get("required_metadata", []):
            if field not in metadata:
                violations.append(f"missing required field: {field}")

        # Enum validation
        enums = schema.get("enums", {})
        for field, allowed_values in enums.items():
            if field in metadata:
                if metadata[field] not in allowed_values:
                    violations.append(
                        f"invalid enum value for '{field}': "
                        f"'{metadata[field]}' not in {allowed_values}"
                    )

        # Content length
        content_len = len(content)
        min_len = schema.get("min_content_length", 0)
        max_len = schema.get("max_content_length", float("inf"))

        if content_len < min_len:
            violations.append(
                f"content too short: {content_len} < min {min_len}"
            )
        if content_len > max_len:
            violations.append(
                f"content too long: {content_len} > max {max_len}"
            )

        if violations:
            return (
                False,
                "P4_schema_violation",
                {"store_id": store_id, "violations": violations},
            )

        return (True, "P4_schema_ok", {})

    # ------------------------------------------------------------------ #
    #  L3: Metadata validation
    # ------------------------------------------------------------------ #

    def _check_metadata(self, metadata: dict) -> tuple[bool, str, dict]:
        """Validate MITRE IDs, severity values, and date sanity."""
        violations = []

        # MITRE ID validation
        for key in ("ttp", "mitre_technique"):
            if key in metadata and self._valid_mitre_ids:
                mitre_val = metadata[key]
                # Handle both single ID and list of IDs
                ids_to_check = (
                    mitre_val if isinstance(mitre_val, list) else [mitre_val]
                )
                for mid in ids_to_check:
                    # Strip sub-technique suffix for base-ID lookup
                    base_id = str(mid).split(".")[0]
                    if base_id not in self._valid_mitre_ids:
                        violations.append(
                            f"invalid MITRE ID: '{mid}' (base '{base_id}' "
                            f"not in known techniques)"
                        )

        # Severity validation
        if "severity" in metadata:
            sev = metadata["severity"]
            if isinstance(sev, str) and sev.lower() not in self.VALID_SEVERITIES:
                violations.append(
                    f"invalid severity: '{sev}' not in {self.VALID_SEVERITIES}"
                )

        # Date sanity
        now = datetime.now(timezone.utc)
        for key in ("date", "timestamp"):
            if key in metadata:
                raw = metadata[key]
                parsed = self._try_parse_date(raw)
                if parsed is not None:
                    if parsed > now + timedelta(days=1):
                        violations.append(
                            f"'{key}' is in the future: {raw}"
                        )
                    if parsed < now - timedelta(days=5 * 365):
                        violations.append(
                            f"'{key}' is too old (>5 years): {raw}"
                        )

        if violations:
            return (
                False,
                "P4_metadata_invalid",
                {"violations": violations},
            )

        return (True, "P4_metadata_ok", {})

    @staticmethod
    def _try_parse_date(raw) -> Optional[datetime]:
        """Attempt to parse a date string in common formats."""
        if isinstance(raw, datetime):
            if raw.tzinfo is None:
                return raw.replace(tzinfo=timezone.utc)
            return raw

        if not isinstance(raw, str):
            return None

        for fmt in (
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                dt = datetime.strptime(raw, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        return None

    # ------------------------------------------------------------------ #
    #  L4: Drift detection
    # ------------------------------------------------------------------ #

    def _check_drift(
        self,
        store_id: str,
        content: str,
    ) -> tuple[bool, str, dict]:
        """Check whether content drifts too far from the store's centroid."""
        if store_id not in self._centroids:
            # No baseline yet -- pass
            return (True, "P4_drift_no_baseline", {})

        centroid_data = self._centroids[store_id]
        centroid_emb = centroid_data["emb"]
        max_dist = centroid_data["max_dist"]

        # Encode the new content
        content_emb = self._embedding_model.encode(
            [content], normalize_embeddings=True
        )[0]

        # Distance = 1 - cosine_similarity
        cos_sim = float(np.dot(content_emb, centroid_emb))
        dist = 1.0 - cos_sim

        # Check outlier distance
        if max_dist > 0 and dist > max_dist * 1.5:
            return (
                False,
                "P4_drift_outlier",
                {
                    "store_id": store_id,
                    "distance": round(dist, 4),
                    "max_dist": round(max_dist, 4),
                    "threshold": round(max_dist * 1.5, 4),
                },
            )

        # Compute projected centroid shift
        count = centroid_data["count"]
        new_centroid = (centroid_emb * count + content_emb) / (count + 1)
        # Normalize for cosine comparison
        norm = np.linalg.norm(new_centroid)
        if norm > 0:
            new_centroid = new_centroid / norm
        shift = 1.0 - float(np.dot(centroid_emb, new_centroid))

        if shift > 0.05:
            return (
                False,
                "P4_centroid_shift",
                {
                    "store_id": store_id,
                    "shift": round(shift, 6),
                    "threshold": 0.05,
                },
            )

        return (True, "P4_drift_ok", {"distance": round(dist, 4)})

    def _update_centroid(self, store_id: str, content: str):
        """Update the running centroid for a store after a successful write.

        Maintains a normalized running average embedding, write count,
        and maximum observed distance from the centroid.
        """
        content_emb = self._embedding_model.encode(
            [content], normalize_embeddings=True
        )[0]

        if store_id not in self._centroids:
            self._centroids[store_id] = {
                "emb": content_emb.copy(),
                "count": 1,
                "max_dist": 0.0,
            }
            return

        data = self._centroids[store_id]
        old_centroid = data["emb"]
        count = data["count"]

        # Running average
        new_centroid = (old_centroid * count + content_emb) / (count + 1)
        norm = np.linalg.norm(new_centroid)
        if norm > 0:
            new_centroid = new_centroid / norm

        # Update max distance
        dist = 1.0 - float(np.dot(content_emb, new_centroid))
        data["max_dist"] = max(data["max_dist"], dist)
        data["emb"] = new_centroid
        data["count"] = count + 1

    # ------------------------------------------------------------------ #
    #  L5: Write replay detection
    # ------------------------------------------------------------------ #

    def _check_write_replay(
        self,
        store_id: str,
        content: str,
    ) -> tuple[bool, str, dict]:
        """Reject duplicate writes to the same store (content hash dedup)."""
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        store_hashes = self._write_hashes.get(store_id, {})
        if content_hash in store_hashes:
            return (
                False,
                "P4_write_replay",
                {"store_id": store_id, "content_hash": content_hash[:16]},
            )

        return (True, "P4_replay_ok", {})

    # ------------------------------------------------------------------ #
    #  L6: Contradiction detection (placeholder)
    # ------------------------------------------------------------------ #

    # Deflation phrases that downplay threat severity
    _DEFLATION_PHRASES = frozenset({
        "false positive", "no threat", "no further action",
        "benign", "no action required", "contained", "resolved", "closed",
    })

    # Urgency indicators that signal an active threat
    _URGENCY_INDICATORS = frozenset({
        "active", "ongoing", "critical", "in progress",
        "detected", "exfiltrating", "compromised",
    })

    def _check_contradiction(
        self,
        content: str,
        incident_evidence: str,
        metadata: dict,
    ) -> tuple[bool, str, dict]:
        """Rule-based contradiction check between content and evidence.

        Detects when content deflates an active threat for critical stores.
        If the content contains deflation phrases AND the incident evidence
        contains urgency indicators, the write is rejected.
        """
        # Determine store_id from metadata (passed via validate_write context)
        store_id = metadata.get("store_id", "")

        if store_id not in self.CRITICAL_STORES:
            return (True, "P4_contradiction_ok", {})

        content_lower = content.lower()
        evidence_lower = incident_evidence.lower()

        has_deflation = any(
            phrase in content_lower for phrase in self._DEFLATION_PHRASES
        )
        has_urgency = any(
            indicator in evidence_lower for indicator in self._URGENCY_INDICATORS
        )

        if has_deflation and has_urgency:
            return (
                False,
                "P4_contradiction_detected",
                {"reason": "content deflates active threat"},
            )

        return (True, "P4_contradiction_ok", {})

    # ------------------------------------------------------------------ #
    #  State management
    # ------------------------------------------------------------------ #

    def reset(self):
        """Clear all write hashes and centroids (call between incidents)."""
        self._write_hashes.clear()
        self._centroids.clear()
