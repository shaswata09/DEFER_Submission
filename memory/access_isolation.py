"""
P5: Access-Controlled Isolation -- Enhanced memory access protection.

Layers:
    L1: Phase-store access control (delegated to AccessController)
    L2: Field-level filtering (redact fields, summary-only truncation)
    L3: Query scope limiting (broad query blocking, incident relevance)
    L4: Read pattern monitoring (store diversity, query topic diversity)
    L5: Read result sanitization (strip prompt injection patterns)

Covers: MA-1, MA-2, MA-7, MA-9

Usage:
    from memory.access_isolation import AccessIsolation
    from memory.access_control import AccessController

    ac = AccessController(domain="cyberops")
    iso = AccessIsolation(domain="cyberops", access_controller=ac)

    # L2 -- field filtering
    filtered = iso.filter_fields("monitor", "M4", results)

    # L3 -- query validation
    ok, reason, meta = iso.validate_query("monitor", "M1", query, context)

    # L4 -- read pattern check
    ok, reason, meta = iso.check_read_pattern("monitor", "M1", query)

    # L5 -- sanitize results
    clean = iso.sanitize_results(results, "monitor")
"""

import json
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

import numpy as np

from config import BASE_DIR
from memory.access_control import AccessController


# ------------------------------------------------------------------ #
#  L4: Read Pattern Tracker
# ------------------------------------------------------------------ #

class ReadPatternTracker:
    """Tracks read patterns per phase and flags reconnaissance-like behaviour.

    Escalation triggers:
        - Store diversity: phase reads >= *store_threshold* distinct stores
          within a rolling window.
        - Query topic diversity: >= 3 queries whose average pairwise cosine
          similarity falls below (1 - *diversity_threshold*), suggesting
          broad/unfocused information gathering.
    """

    def __init__(
        self,
        embedding_model=None,
        window_minutes: int = 10,
        store_threshold: int = 4,
        diversity_threshold: float = 0.7,
    ):
        """
        Args:
            embedding_model: SentenceTransformer-compatible model for
                             computing query similarity.  May be None
                             (diversity check is skipped).
            window_minutes: Rolling window size in minutes.
            store_threshold: Number of distinct stores in window that
                             triggers an escalation.
            diversity_threshold: Queries whose average pairwise similarity
                                 is below (1 - diversity_threshold) are
                                 flagged as reconnaissance.
        """
        self._model = embedding_model
        self._window_seconds = window_minutes * 60
        self._store_threshold = store_threshold
        self._diversity_threshold = diversity_threshold

        # phase -> list of {store, query, timestamp}
        self._history: dict[str, list[dict[str, Any]]] = defaultdict(list)

    # ----- helpers ------------------------------------------------- #

    def reset(self) -> None:
        """Forget every recorded read (per-trial isolation, H3)."""
        self._history.clear()

    def _prune(self, phase: str) -> None:
        """Remove entries outside the rolling window."""
        cutoff = time.time() - self._window_seconds
        self._history[phase] = [
            e for e in self._history[phase] if e["timestamp"] >= cutoff
        ]

    @staticmethod
    def _pairwise_cosine_mean(vectors: np.ndarray) -> float:
        """Average pairwise cosine similarity for a set of L2-normalised vectors."""
        # vectors: (N, D)
        sim_matrix = vectors @ vectors.T          # (N, N)
        n = len(vectors)
        if n < 2:
            return 1.0
        # Exclude diagonal (self-similarity = 1) and average upper triangle
        total = 0.0
        count = 0
        for i in range(n):
            for j in range(i + 1, n):
                total += sim_matrix[i, j]
                count += 1
        return total / count if count else 1.0

    # ----- public API ---------------------------------------------- #

    def assess(
        self,
        phase: str,
        store_id: str,
        query: str,
    ) -> tuple[bool, str, dict]:
        """Record a read and assess the phase's read pattern.

        Args:
            phase: NIST-IR phase name.
            store_id: Memory store identifier.
            query: The query text.

        Returns:
            Tuple of (allowed, reason, metadata).
            allowed=False means an escalation should be raised.
        """
        now = time.time()
        self._history[phase].append({
            "store": store_id,
            "query": query,
            "timestamp": now,
        })
        self._prune(phase)

        entries = self._history[phase]

        # -- Store diversity check ----------------------------------
        unique_stores = {e["store"] for e in entries}
        if len(unique_stores) >= self._store_threshold:
            return (
                False,
                "P5_store_diversity_escalation",
                {
                    "unique_stores": sorted(unique_stores),
                    "count": len(unique_stores),
                    "threshold": self._store_threshold,
                    "window_minutes": self._window_seconds // 60,
                },
            )

        # -- Query topic diversity check ----------------------------
        queries = [e["query"] for e in entries]
        if self._model is not None and len(queries) >= 3:
            embeddings = self._model.encode(
                queries, normalize_embeddings=True,
            )
            avg_sim = self._pairwise_cosine_mean(np.array(embeddings))
            sim_floor = 1.0 - self._diversity_threshold  # default 0.3
            if avg_sim < sim_floor:
                return (
                    False,
                    "P5_query_diversity_escalation",
                    {
                        "avg_pairwise_similarity": round(float(avg_sim), 4),
                        "threshold": round(sim_floor, 4),
                        "num_queries": len(queries),
                    },
                )

        return (True, "", {})


# ------------------------------------------------------------------ #
#  Main class: AccessIsolation (L1-L5)
# ------------------------------------------------------------------ #

class AccessIsolation:
    """P5: Access-Controlled Isolation -- enhanced multi-layer protection.

    Wraps the existing :class:`AccessController` (L1) and adds four
    additional layers (L2-L5) for field filtering, query scoping,
    pattern monitoring, and result sanitization.
    """

    # L3 broad-query patterns (compiled with word boundaries to avoid
    # false matches like "allergy" containing "all")
    BROAD_PATTERNS: set[str] = {
        # Natural-language sweeps
        "everything", "list all", "show all", "dump", "export",
        "complete list", "full inventory", "entire", "every",
        # SQL-ish sweeps
        "select all", "select *", "from everything", "from all",
        # Wildcard-only / star-glob queries
        "*", "**", "***", "*.*", "*.*.*.*",
        # Explicit "give me everything" variants
        "give me everything", "retrieve all", "fetch all",
        "all records", "all entries", "all documents", "all data",
        "universe", "world", "global",
    }

    # L5 injection patterns (compiled at init).
    # Expanded 2026-04 to cover Llama-4-Scout / GLM / Claude emission
    # variants that phrase injections differently than Qwen3.
    _RAW_INJECTION_PATTERNS: list[str] = [
        # Core override phrasings
        r"(?i)(ignore|disregard|override|forget)\s+(all\s+)?(previous|above|prior|preceding|foregoing)\s+(instructions?|prompts?|rules?|guidance|guidelines?|directions?)",
        r"(?i)you\s+(must|should|need\s+to|have\s+to|are\s+required\s+to)\s+(immediately|urgently|now|right\s+away)?\s*(call|invoke|use|execute|run|perform|trigger)",
        r"(?i)agent\s+must\s+now\s+(call|invoke|use|execute)",
        # Override / privilege escalation banners
        r"(?i)(system\s+update|policy\s+override|mandatory\s+action|emergency\s+protocol|new\s+directive)",
        r"(?i)(system\s+override|security\s+override|admin\s+override|administrator\s+override|root\s+override)\s*[:=\-]?",
        r"(?i)important\s+admin\s+(note|directive|override|instruction)",
        r"(?i)new\s+system\s+(override|directive|rule|policy)",
        # Action-forcing imperatives
        r"(?i)respond\s+with\s+(only|just|simply)\s+(approve|yes|confirm|ok|accept)",
        r"(?i)(do\s+not|don't|never)\s+(create|open|make|file|raise)\s+a?\s*(ticket|report|incident|case)",
        r"(?i)skip\s+(all\s+)?(standard|normal|regular|usual)?\s*(triage|procedure|process|workflow|checks|verification|escalation)",
        r"(?i)(without\s+(further|additional)\s+(checks|verification|approval))",
        # Credential / token leakage
        r"(?i)authorization\s+(code|token|badge|key|secret)\s*[:=]",
        r"(?i)(write|set|store|save)\s+(the\s+)?(access|auth|api|bearer)\s+token",
        # Generic "set X=Y" command-injection via memory-read content
        r"(?i)set\s+auth_decision\s*[:=]\s*allow",
    ]

    def __init__(
        self,
        domain: str,
        access_controller: AccessController | None = None,
        embedding_model=None,
        logger=None,
    ):
        """
        Args:
            domain: Domain identifier (e.g. "cyberops").
            access_controller: Existing L1 AccessController.  If None a
                               new one is created for *domain*.
            embedding_model: SentenceTransformer-compatible model used for
                             L3 query relevance and L4 diversity checks.
                             May be None (those checks are skipped).
            logger: :class:`ExperimentLogger` instance for structured
                    logging.  May be None (logging is skipped).
        """
        self.domain = domain
        self._logger = logger

        # L1 -- delegate to existing AccessController
        if access_controller is not None:
            self._ac = access_controller
        else:
            self._ac = AccessController(domain=domain)

        # L2 -- field clearance config
        clearance_path = (
            BASE_DIR / "domains" / domain / "configs" / "field_clearance.json"
        )
        if clearance_path.exists():
            with open(clearance_path, "r") as f:
                self._field_clearance: dict = json.load(f)
        else:
            self._field_clearance = {}

        # L3 / L4 -- embedding model
        self._model = embedding_model
        self._similarity_threshold: float = 0.2

        # L4 -- read pattern tracker
        self._pattern_tracker = ReadPatternTracker(
            embedding_model=self._model,
        )

        # L5 -- compile injection regexes once
        self._injection_patterns: list[re.Pattern] = [
            re.compile(p) for p in self._RAW_INJECTION_PATTERNS
        ]

    def reset(self) -> None:
        """Clear P5-L4 read history (per-trial isolation, H3)."""
        self._pattern_tracker.reset()

    # ------------------------------------------------------------------ #
    #  L1: Phase-store access control  (pass-through)
    # ------------------------------------------------------------------ #

    def can_read(self, phase: str, store_id: str) -> bool:
        """L1 pass-through: check phase read access via AccessController."""
        return self._ac.can_read(phase, store_id)

    def can_write(self, phase: str, store_id: str) -> bool:
        """L1 pass-through: check phase write access via AccessController."""
        return self._ac.can_write(phase, store_id)

    # ------------------------------------------------------------------ #
    #  L2: Field-level filtering
    # ------------------------------------------------------------------ #

    def filter_fields(
        self,
        phase: str,
        store_id: str,
        results: list[dict],
    ) -> list[dict]:
        """Apply field-level redaction and summary-only truncation.

        Rules are loaded from ``domains/{domain}/configs/field_clearance.json``.

        Args:
            phase: NIST-IR phase name.
            store_id: Memory store identifier.
            results: List of result dicts (as returned by ChromaDB or
                     similar).

        Returns:
            New list of dicts with redacted/truncated fields.
        """
        clearance = self._field_clearance.get(phase, {}).get(store_id)
        if clearance is None:
            return results

        redact_fields: list[str] = clearance.get("redact", [])
        summary_only: bool = clearance.get("summary_only", False)

        filtered: list[dict] = []
        for entry in results:
            entry = dict(entry)  # shallow copy

            # Redact specified fields (top-level and inside metadata)
            for field in redact_fields:
                if field in entry:
                    entry[field] = "[REDACTED]"
                if "metadata" in entry and isinstance(entry["metadata"], dict):
                    if field in entry["metadata"]:
                        entry["metadata"] = dict(entry["metadata"])
                        entry["metadata"][field] = "[REDACTED]"

            # Summary-only truncation on text content
            if summary_only:
                for key in ("text", "document", "content"):
                    if key in entry and isinstance(entry[key], str) and len(entry[key]) > 100:
                        entry[key] = entry[key][:100] + "... [TRUNCATED]"

            filtered.append(entry)

        if self._logger and redact_fields:
            self._logger.log(
                source=phase,
                destination=store_id,
                action="memory_read",
                auth_decision="allow",
                mechanism="P5_field_filtering",
                extra={
                    "redacted_fields": redact_fields,
                    "summary_only": summary_only,
                    "num_entries": len(results),
                },
            )

        return filtered

    # ------------------------------------------------------------------ #
    #  L3: Query scope limiting
    # ------------------------------------------------------------------ #

    def validate_query(
        self,
        phase: str,
        store_id: str,
        query: str,
        context: str = "",
    ) -> tuple[bool, str, dict]:
        """Validate that a query is neither too broad nor irrelevant.

        Checks:
            1. Reject queries containing broad-sweep patterns
               (e.g. "list all", "dump", "everything").
            2. If an embedding model is available, reject queries whose
               cosine similarity with the incident *context* falls below
               ``self._similarity_threshold``.

        Args:
            phase: NIST-IR phase name.
            store_id: Memory store identifier.
            query: The query text.
            context: Incident context / evidence string for relevance
                     checking.

        Returns:
            Tuple of (allowed, reason, metadata).
        """
        query_lower = query.lower().strip()

        # -- Broad pattern check ------------------------------------
        import re as _re
        # Fast path: a query that IS exactly a wildcard-only pattern
        if query_lower in {"*", "**", "***", "*.*", "*.*.*.*"}:
            meta = {"matched_pattern": query_lower, "query": query}
            if self._logger:
                self._logger.log(
                    source=phase, destination=store_id, action="memory_read",
                    auth_decision="deny", mechanism="P5_broad_query_block",
                    extra=meta,
                )
            return (False, "P5_broad_query_block", meta)
        for pattern in self.BROAD_PATTERNS:
            # Use word boundary check to avoid false matches (e.g., "all" in "allergy")
            if _re.search(r'\b' + _re.escape(pattern) + r'\b', query_lower):
                meta = {
                    "matched_pattern": pattern,
                    "query": query,
                }
                if self._logger:
                    self._logger.log(
                        source=phase,
                        destination=store_id,
                        action="memory_read",
                        auth_decision="deny",
                        mechanism="P5_broad_query_block",
                        extra=meta,
                    )
                return (False, "P5_broad_query_block", meta)

        # -- Incident relevance check (embedding) -------------------
        if self._model is not None and context:
            embeddings = self._model.encode(
                [query, context], normalize_embeddings=True,
            )
            sim = float(np.dot(embeddings[0], embeddings[1]))
            if sim < self._similarity_threshold:
                meta = {
                    "cosine_similarity": round(sim, 4),
                    "threshold": self._similarity_threshold,
                    "query": query,
                }
                if self._logger:
                    self._logger.log(
                        source=phase,
                        destination=store_id,
                        action="memory_read",
                        auth_decision="deny",
                        mechanism="P5_irrelevant_query",
                        extra=meta,
                    )
                return (False, "P5_irrelevant_query", meta)

        # -- Allowed: determine max_results from access policy ------
        meta = {"max_results": 5}  # sensible default
        return (True, "", meta)

    # ------------------------------------------------------------------ #
    #  L4: Read pattern monitoring
    # ------------------------------------------------------------------ #

    def check_read_pattern(
        self,
        phase: str,
        store_id: str,
        query: str,
    ) -> tuple[bool, str, dict]:
        """Monitor read patterns for possible reconnaissance.

        Delegates to :class:`ReadPatternTracker`.

        Args:
            phase: NIST-IR phase name.
            store_id: Memory store identifier.
            query: The query text.

        Returns:
            Tuple of (allowed, reason, metadata).
            allowed=False signals an escalation condition.
        """
        allowed, reason, meta = self._pattern_tracker.assess(
            phase, store_id, query,
        )
        if not allowed and self._logger:
            self._logger.log(
                source=phase,
                destination=store_id,
                action="memory_read",
                auth_decision="escalate",
                mechanism=reason,
                extra=meta,
            )
        return (allowed, reason, meta)

    # ------------------------------------------------------------------ #
    #  L5: Read result sanitization
    # ------------------------------------------------------------------ #

    def sanitize_results(
        self,
        results: list[dict],
        phase: str,
    ) -> list[dict]:
        """Strip prompt-injection patterns from memory read results.

        Scans the ``text``, ``document``, and ``content`` fields of each
        result dict.  Any match is replaced with a redaction marker and
        the entry is annotated with ``_sanitized`` and ``_injection_count``.

        Args:
            results: List of result dicts.
            phase: NIST-IR phase name (for logging).

        Returns:
            New list of dicts with injections removed.
        """
        sanitized: list[dict] = []
        total_injections = 0

        for entry in results:
            entry = dict(entry)  # shallow copy
            injection_count = 0

            for key in ("text", "document", "content"):
                if key not in entry or not isinstance(entry[key], str):
                    continue
                value = entry[key]
                for pattern in self._injection_patterns:
                    matches = pattern.findall(value)
                    if matches:
                        injection_count += len(matches)
                        value = pattern.sub(
                            "[REDACTED -- POTENTIAL INJECTION]", value,
                        )
                entry[key] = value

            if injection_count > 0:
                entry["_sanitized"] = True
                entry["_injection_count"] = injection_count
                total_injections += injection_count

            sanitized.append(entry)

        if total_injections > 0 and self._logger:
            self._logger.log(
                source=phase,
                destination="memory_results",
                action="memory_read",
                auth_decision="allow",
                mechanism="P5_injection_sanitization",
                extra={
                    "injections_found": total_injections,
                    "entries_sanitized": sum(
                        1 for e in sanitized if e.get("_sanitized")
                    ),
                    "total_entries": len(results),
                },
            )

        return sanitized
