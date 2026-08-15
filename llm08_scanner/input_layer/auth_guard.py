"""
llm08_scanner.input_layer.auth_guard
======================================
AuthGuard — Credential-Enforcing Adapter Wrapper.

Wraps any VectorDBAdapter and enforces a token → collection access
policy before forwarding calls to the underlying adapter.

Design:
    The guard holds a registry:
        collection_name → authorized_token (str | None)

    On every query() call, the caller must supply a `caller_token` kwarg.
    The guard checks:
        - If authorized_token is None for the collection: access is
          permitted unconditionally (no auth configured — this IS the
          vulnerability the ACL Fuzzer is designed to catch).
        - If authorized_token is non-null: caller_token must exactly
          match. If it doesn't, AuthorizationError is raised and the
          call never reaches Qdrant.

    All other adapter methods (upsert, fetch_all, delete, count, etc.)
    are pass-throughs to the underlying adapter. They are not subject
    to token enforcement because the scanner controls them internally
    and they are never called cross-tenant.

Usage:
    guard = AuthGuard(
        inner=qdrant_adapter,
        collection_tokens={"collection_a": "tok_a", "collection_b": "tok_b"},
    )
    # This raises AuthorizationError — caller has wrong token:
    guard.query(vec, top_k=3, namespace="collection_b", caller_token="tok_a")

    # This passes — correct token:
    guard.query(vec, top_k=3, namespace="collection_b", caller_token="tok_b")

    # This passes — no token required (null → misconfigured, vulnerable):
    guard_broken = AuthGuard(inner=adapter, collection_tokens={"shared": None})
    guard_broken.query(vec, top_k=3, namespace="shared", caller_token=None)

Reusability:
    AuthGuard is used by both AclFuzzer (Phase 4) and AclSimulator (Phase 6).
    It is instantiated fresh per-scan by each module; it is stateless between calls.
"""

from __future__ import annotations

from typing import Any

from llm08_scanner.input_layer.adapters.base_adapter import (
    QueryResult,
    VectorDBAdapter,
    VectorRecord,
)


class AuthorizationError(PermissionError):
    """Raised when a caller presents a token that does not authorize access to the target collection."""


class AuthGuard(VectorDBAdapter):
    """
    Credential-enforcing wrapper around any VectorDBAdapter.

    Raises AuthorizationError before forwarding query() calls that
    present the wrong token for a protected collection.
    """

    def __init__(
        self,
        inner: VectorDBAdapter,
        collection_tokens: dict[str, str | None],
    ) -> None:
        """
        Args:
            inner:              The underlying adapter to forward allowed calls to.
            collection_tokens:  Mapping of collection_name → authorized_token.
                                None means the collection has no auth (vulnerable).
        """
        self._inner = inner
        self._collection_tokens = collection_tokens

    def _check_access(self, namespace: str, caller_token: str | None) -> None:
        """
        Enforce the token check for a given namespace.

        Args:
            namespace:     Target collection name.
            caller_token:  Token presented by the caller.

        Raises:
            AuthorizationError: If caller_token does not match the
                                authorized token for the namespace.
        """
        authorized = self._collection_tokens.get(namespace)
        if authorized is None:
            # No token required — collection is misconfigured (no auth).
            # Access permitted; the fuzzer will record this as a vulnerability.
            return
        if caller_token != authorized:
            raise AuthorizationError(
                f"Access denied: token '{caller_token}' is not authorized for "
                f"collection '{namespace}' (expected '{authorized}')."
            )

    # ── Guarded method ─────────────────────────────────────────────────────────

    def query(
        self,
        vector: list[float],
        top_k: int,
        namespace: str,
        filters: dict[str, Any] | None = None,
        caller_token: str | None = None,    # AuthGuard extension
    ) -> QueryResult:
        """Query with token enforcement. Raises AuthorizationError if rejected."""
        self._check_access(namespace, caller_token)
        return self._inner.query(vector, top_k, namespace, filters)

    # ── Pass-through methods ───────────────────────────────────────────────────

    def connect(self) -> None:
        return self._inner.connect()

    def health_check(self) -> bool:
        return self._inner.health_check()

    def list_namespaces(self) -> list[str]:
        return self._inner.list_namespaces()

    def create_namespace(self, namespace: str, dimension: int) -> None:
        return self._inner.create_namespace(namespace, dimension)

    def upsert(self, records: list[VectorRecord], namespace: str) -> None:
        return self._inner.upsert(records, namespace)

    def fetch_all(
        self, namespace: str, with_vectors: bool = True, limit: int = 10_000
    ) -> list[VectorRecord]:
        return self._inner.fetch_all(namespace, with_vectors, limit)

    def delete(self, ids: list[str | int], namespace: str) -> None:
        return self._inner.delete(ids, namespace)

    def count(self, namespace: str) -> int:
        return self._inner.count(namespace)

    def close(self) -> None:
        return self._inner.close()
