"""
llm08_scanner.input_layer.adapters.base_adapter
================================================
Abstract base class that ALL vector database adapters must implement.

Every method raises NotImplementedError in this base class; concrete
adapters (e.g., QdrantAdapter) must override all methods.

The Core Backend Engine ONLY imports VectorDBAdapter (this class).
It never imports a concrete adapter. The appropriate concrete class
is instantiated by the adapter factory in adapters/__init__.py.

Implementation: Phase 1.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class VectorRecord:
    """A single vector record returned from the database.

    Attributes:
        id:         Unique identifier for this vector.
        vector:     The embedding as a list of floats.
        payload:    Metadata key-value pairs stored alongside the vector.
        score:      Similarity score from the query (None if not a query result).
        namespace:  Collection/namespace this record belongs to.
    """

    id: str | int
    vector: list[float]
    payload: dict[str, Any] = field(default_factory=dict)
    score: float | None = None
    namespace: str = ""


@dataclass
class QueryResult:
    """Result of a similarity search query.

    Attributes:
        query_vector:   The query vector that produced these results.
        records:        Ordered list of matching records (highest similarity first).
        namespace:      Collection/namespace that was queried.
        top_k:          Number of results requested.
    """

    query_vector: list[float]
    records: list[VectorRecord]
    namespace: str
    top_k: int


class VectorDBAdapter(ABC):
    """Abstract interface for vector database operations.

    All vector DB I/O in the scanner goes through this interface.
    Concrete implementations must be provided for each supported backend.

    Design decision: see DESIGN_DECISIONS.md DD-001 (Qdrant selection)
    and DD-008 (adapter pattern rationale).
    """

    @abstractmethod
    def connect(self) -> None:
        """Establish connection to the vector database.

        Raises:
            ConnectionError: If the database is unreachable.
            AuthenticationError: If credentials are invalid.
        """

    @abstractmethod
    def health_check(self) -> bool:
        """Return True if the database is reachable and responding.

        Does not raise on unhealthy state — returns False instead,
        so callers can handle the state explicitly.
        """

    @abstractmethod
    def list_namespaces(self) -> list[str]:
        """Return all collection/namespace names visible to the current connection.

        Returns:
            List of namespace/collection name strings.
        """

    @abstractmethod
    def create_namespace(self, namespace: str, dimension: int) -> None:
        """Create a new collection/namespace if it does not exist.

        Args:
            namespace:  Collection name to create.
            dimension:  Vector dimension for this collection (must be consistent).

        Raises:
            ValueError: If the namespace already exists with a different dimension.
        """

    @abstractmethod
    def upsert(
        self,
        records: list[VectorRecord],
        namespace: str,
    ) -> None:
        """Insert or update a batch of vector records in the specified namespace.

        Args:
            records:    List of VectorRecord objects to upsert.
            namespace:  Target collection/namespace name.

        Raises:
            DimensionMismatchError: If any vector has the wrong dimension.
        """

    @abstractmethod
    def query(
        self,
        vector: list[float],
        top_k: int,
        namespace: str,
        filters: dict[str, Any] | None = None,
    ) -> QueryResult:
        """Perform a similarity search.

        Args:
            vector:     Query vector (must match collection dimension).
            top_k:      Maximum number of results to return.
            namespace:  Collection/namespace to search.
            filters:    Optional metadata filter (backend-specific format).

        Returns:
            QueryResult with matched records ordered by similarity descending.
        """

    @abstractmethod
    def fetch_all(
        self,
        namespace: str,
        with_vectors: bool = True,
        limit: int = 10_000,
    ) -> list[VectorRecord]:
        """Fetch all records from a namespace (used by drift detector and heatmap).

        Args:
            namespace:      Collection/namespace to read.
            with_vectors:   Whether to include vector data (vs. payload only).
            limit:          Maximum records to return (safety cap).

        Returns:
            List of VectorRecord objects.
        """

    @abstractmethod
    def delete(self, ids: list[str | int], namespace: str) -> None:
        """Delete records by ID from the specified namespace.

        Args:
            ids:        List of record IDs to delete.
            namespace:  Collection/namespace to delete from.
        """

    @abstractmethod
    def count(self, namespace: str) -> int:
        """Return the number of vectors in a namespace.

        Args:
            namespace: Collection/namespace to count.

        Returns:
            Integer count of stored vectors.
        """

    @abstractmethod
    def close(self) -> None:
        """Close the database connection and release resources."""
