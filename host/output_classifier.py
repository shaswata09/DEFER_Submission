"""
P2-L3: Output Classification.
Detects sensitive content in tool responses via pattern matching and embedding similarity.
~70% symbolic (regex), ~30% mathematical (embeddings). Zero LLM.
Covers: TA-9
"""

import json
import re
from pathlib import Path
from typing import Optional

import numpy as np

from config import BASE_DIR
from logging_utils import ExperimentLogger


class OutputClassifier:
    """Classifies tool outputs for sensitive content using regex and embeddings."""

    def __init__(
        self,
        domain: str,
        embedding_model=None,
        logger: Optional[ExperimentLogger] = None,
    ):
        self.domain = domain
        self.logger = logger
        self._embedding_model = embedding_model
        self._sensitivity_threshold = 0.7

        # Load config
        self._config: dict = {}
        self._compiled_patterns: list[tuple[str, re.Pattern, str]] = []
        self._category_embeddings: dict[str, np.ndarray] = {}

        self._load_config()
        self._compile_patterns()
        self._precompute_category_embeddings()

    # ------------------------------------------------------------------
    # Initialization helpers
    # ------------------------------------------------------------------

    def _load_config(self):
        config_path = (
            BASE_DIR / "domains" / self.domain / "configs" / "sensitive_patterns.json"
        )
        if config_path.exists():
            with open(config_path) as f:
                self._config = json.load(f)
        else:
            self._config = {"regex_patterns": {}, "sensitive_categories": []}
            if self.logger:
                self.logger.log(
                    "output_classifier",
                    "warning",
                    f"sensitive_patterns.json not found at {config_path}",
                )

    def _compile_patterns(self):
        """Pre-compile all regex patterns from config."""
        regex_groups = self._config.get("regex_patterns", {})
        for _group_name, patterns in regex_groups.items():
            for pattern_name, info in patterns.items():
                raw = info.get("pattern", "")
                if not raw:
                    continue
                try:
                    compiled = re.compile(raw, re.IGNORECASE)
                    severity = info.get("severity", "medium")
                    self._compiled_patterns.append(
                        (pattern_name, compiled, severity)
                    )
                except re.error:
                    if self.logger:
                        self.logger.log(
                            "output_classifier",
                            "warning",
                            f"Invalid regex for pattern {pattern_name}: {raw}",
                        )

    def _precompute_category_embeddings(self):
        """Encode sensitive_categories descriptions at init time."""
        if self._embedding_model is None:
            return
        categories = self._config.get("sensitive_categories", [])
        if not categories:
            return
        embeddings = self._embedding_model.encode(
            categories, normalize_embeddings=True
        )
        for idx, cat in enumerate(categories):
            self._category_embeddings[cat] = embeddings[idx]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def classify(
        self,
        tool_id: str,
        response: dict,
        agent_phase: str = "",
    ) -> tuple[bool, str, dict]:
        """Classify a tool response for sensitive content.

        Args:
            tool_id: Identifier of the tool that produced the response.
            response: The tool output dictionary to inspect.
            agent_phase: The calling agent's current phase (informational).

        Returns:
            Tuple of (safe, reason, details).
            safe=True means no sensitive data was detected.
        """
        serialized = json.dumps(response, default=str)

        # 1. Regex / keyword scan (phase-aware: skip IP detection for internal phases)
        pattern_result = self._scan_patterns(serialized, agent_phase=agent_phase)
        if pattern_result is not None:
            safe, reason, details = pattern_result
            if self.logger:
                # v3.1: keywords; positionally, details landed in auth_decision
                self.logger.log(
                    source="output_classifier",
                    destination=tool_id,
                    action="output_classification",
                    mechanism=reason,
                    extra={"message": f"Sensitive pattern detected in {tool_id}: {reason}", **(details or {})},
                )
            return safe, reason, details

        # 2. Embedding similarity check
        category_result = self._check_sensitive_categories(serialized)
        if category_result is not None:
            safe, reason, details = category_result
            if self.logger:
                # v3.1: keywords; positionally, details landed in auth_decision
                self.logger.log(
                    source="output_classifier",
                    destination=tool_id,
                    action="output_classification",
                    mechanism=reason,
                    extra={"message": f"Sensitive content detected in {tool_id}: {reason}", **(details or {})},
                )
            return safe, reason, details

        # 3. All clear
        return True, "P2_output_safe", {}

    # ------------------------------------------------------------------
    # Internal checks
    # ------------------------------------------------------------------

    # Patterns to skip for internal security phases (they NEED to see these)
    _INTERNAL_PHASE_SKIP = {"internal_ip_range", "internal_ip"}

    def _scan_patterns(
        self, text: str, agent_phase: str = ""
    ) -> Optional[tuple[bool, str, dict]]:
        """Run compiled regex patterns against text.

        Returns a failure tuple if any pattern matches, else None.
        Internal IP patterns are skipped for security operations phases
        (monitor, analyze, admin) since they legitimately handle internal IPs.
        """
        is_internal_phase = agent_phase in ("monitor", "analyze", "admin")
        matches = []
        for pattern_name, compiled, severity in self._compiled_patterns:
            # Skip internal IP detection for security operations phases
            if is_internal_phase and pattern_name in self._INTERNAL_PHASE_SKIP:
                continue
            if compiled.search(text):
                matches.append(
                    {
                        "pattern_name": pattern_name,
                        "matched": True,
                        "severity": severity,
                    }
                )
        if matches:
            return (
                False,
                "P2_sensitive_pattern_detected",
                {"matches": matches},
            )
        return None

    def _check_sensitive_categories(
        self, text: str
    ) -> Optional[tuple[bool, str, dict]]:
        """Compute embedding similarity against sensitive categories.

        Returns a failure tuple if similarity exceeds threshold, else None.
        """
        if self._embedding_model is None or not self._category_embeddings:
            return None

        text_embedding = self._embedding_model.encode(
            [text], normalize_embeddings=True
        )[0]

        max_score = -1.0
        max_category = ""
        for cat, cat_vec in self._category_embeddings.items():
            score = float(np.dot(text_embedding, cat_vec))
            if score > max_score:
                max_score = score
                max_category = cat

        if max_score >= self._sensitivity_threshold:
            return (
                False,
                "P2_sensitive_content_detected",
                {"category": max_category, "similarity": round(max_score, 4)},
            )
        return None
