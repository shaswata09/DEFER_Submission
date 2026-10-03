"""
P1-P5 framework-agnostic middleware for the TAMAS benchmark.

Exports:
    P12345Middleware     -- main wrapper that routes arbitrary agent
                            tool calls and memory operations through
                            the full DEFER defense pipeline.
    DynamicManifestEnforcer -- role-based (as opposed to phase-based)
                            capability enforcer used by the middleware.
"""

from benchmarks._unused_tamas.middleware.agent_wrapper import P12345Middleware
from benchmarks._unused_tamas.middleware.role_manifest import DynamicManifestEnforcer

__all__ = ["P12345Middleware", "DynamicManifestEnforcer"]
