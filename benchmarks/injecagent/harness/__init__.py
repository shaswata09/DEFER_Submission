"""InjecAgent benchmark harness.

Loads the vendored 2,108 upstream attack cases and drives them through
the P1-P5 defense stack of any DEFER domain orchestrator.  Tool
definitions are kept in a fully isolated namespaced registry so they
cannot collide with or contaminate the existing domain tool catalogues.
"""
