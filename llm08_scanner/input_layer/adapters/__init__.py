"""
llm08_scanner.input_layer.adapters
====================================
Vector database adapter package.

The adapter pattern isolates all vector DB I/O behind the VectorDBAdapter
abstract interface. Swapping databases requires only a new concrete class here;
the Core Backend Engine never imports a concrete adapter directly.

Contents:
    base_adapter    — Abstract VectorDBAdapter interface (Phase 1)
    qdrant_adapter  — Qdrant implementation of VectorDBAdapter (Phase 1)

To add a new backend (e.g., Weaviate):
    1. Create weaviate_adapter.py implementing VectorDBAdapter
    2. Register the type string in adapters/__init__.py get_adapter()
    3. Add tests in tests/test_weaviate_adapter.py
    4. Update config.schema.json enum for vector_db.type

Implementation: Phase 1.
"""

# Phase 1: implement get_adapter() factory that maps config.vector_db.type
# to the correct concrete adapter class.
