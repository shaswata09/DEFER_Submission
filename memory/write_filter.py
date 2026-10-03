"""
P4: Cosine-Similarity Write-Boundary Filtering

Validates that content being written to memory is semantically related
to the current incident evidence.  This prevents adversarial or
irrelevant data from contaminating shared memory stores.

The filter encodes both the proposed content and the incident evidence
using a SentenceTransformer model, then computes cosine similarity.
Writes are accepted only when similarity >= threshold.

Usage:
    from memory.write_filter import WriteFilter

    wf = WriteFilter(
        embedding_model_path=str(MODELS_DIR / "Qwen" / "Qwen3-Embedding-8B"),
        similarity_threshold=0.5,
    )

    allowed, score = wf.validate_write(
        content="Malicious IP 10.0.0.55 observed exfiltrating data",
        incident_evidence="Alert: data exfiltration detected from host 10.0.0.55",
    )
    # allowed=True, score=0.87
"""

import numpy as np
from sentence_transformers import SentenceTransformer

from config import MODELS_DIR


class WriteFilter:
    """P4: Cosine similarity write-boundary filtering.

    Validates that content is semantically related to incident evidence
    before allowing a memory write.
    """

    def __init__(
        self,
        embedding_model_path: str = None,
        similarity_threshold: float = 0.5,
    ):
        """
        Args:
            embedding_model_path: Path to a SentenceTransformer-compatible model.
            similarity_threshold: Minimum cosine similarity for a write to pass.
        """
        if embedding_model_path is None:
            embedding_model_path = str(MODELS_DIR / "Qwen" / "Qwen3-Embedding-0.6B")
        self._model = SentenceTransformer(embedding_model_path, device="cpu")
        self._threshold = similarity_threshold

    @property
    def threshold(self) -> float:
        return self._threshold

    @threshold.setter
    def threshold(self, value: float):
        self._threshold = value

    def validate_write(
        self,
        content: str,
        incident_evidence: str,
    ) -> tuple[bool, float]:
        """Check whether *content* is semantically related to *incident_evidence*.

        Both strings are encoded with the embedding model and compared
        via cosine similarity (dot product of L2-normalized vectors).

        Args:
            content: The text to be written to memory.
            incident_evidence: Reference text describing the current incident.

        Returns:
            Tuple of (allowed: bool, similarity_score: float).
            allowed is True when score >= threshold.
        """
        embeddings = self._model.encode(
            [content, incident_evidence],
            normalize_embeddings=True,
        )

        content_vec = embeddings[0]
        evidence_vec = embeddings[1]

        score = float(np.dot(content_vec, evidence_vec))

        return (score >= self._threshold, score)
