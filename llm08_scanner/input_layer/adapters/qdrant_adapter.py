"""
llm08_scanner.input_layer.adapters.qdrant_adapter
===================================================
Qdrant implementation of the VectorDBAdapter interface.
"""

from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.http import models
from qdrant_client.http.exceptions import UnexpectedResponse

from llm08_scanner.input_layer.adapters.base_adapter import (
    QueryResult,
    VectorDBAdapter,
    VectorRecord,
)


class QdrantAdapter(VectorDBAdapter):
    """Qdrant-specific implementation of VectorDBAdapter."""

    def __init__(self, host: str, port: int, grpc_port: int | None, api_key: str | None, tls: bool, timeout: float) -> None:
        self._host = host
        self._port = port
        self._grpc_port = grpc_port
        self._api_key = api_key
        self._tls = tls
        self._timeout = timeout
        self._client: QdrantClient | None = None

    def connect(self) -> None:
        """Establish connection to Qdrant."""
        self._client = QdrantClient(
            host=self._host,
            port=self._port,
            grpc_port=self._grpc_port,
            prefer_grpc=bool(self._grpc_port),
            api_key=self._api_key,
            timeout=self._timeout,
            https=self._tls
        )

    def health_check(self) -> bool:
        if not self._client:
            return False
        try:
            # list_collections is a lightweight way to check if the API responds
            self._client.get_collections()
            return True
        except Exception:
            return False

    def list_namespaces(self) -> list[str]:
        if not self._client:
            raise ConnectionError("Not connected to Qdrant")
        response = self._client.get_collections()
        return [c.name for c in response.collections]

    def create_namespace(self, namespace: str, dimension: int) -> None:
        if not self._client:
            raise ConnectionError("Not connected to Qdrant")
        
        # Check if exists
        existing = self.list_namespaces()
        if namespace in existing:
            # We could verify dimension here, but for simplicity we assume it's correct
            # or rely on Qdrant to throw on upsert if dimension mismatches.
            return
            
        self._client.create_collection(
            collection_name=namespace,
            vectors_config=models.VectorParams(
                size=dimension,
                distance=models.Distance.COSINE
            )
        )

    def upsert(self, records: list[VectorRecord], namespace: str) -> None:
        if not self._client:
            raise ConnectionError("Not connected to Qdrant")
        if not records:
            return
            
        points = [
            models.PointStruct(
                id=r.id,
                vector=r.vector,
                payload=r.payload
            )
            for r in records
        ]
        
        try:
            self._client.upsert(
                collection_name=namespace,
                points=points,
                wait=True
            )
        except UnexpectedResponse as e:
            if "dimension" in str(e).lower() or "size" in str(e).lower():
                raise ValueError("Dimension mismatch") from e
            raise

    def query(self, vector: list[float], top_k: int, namespace: str, filters: dict[str, Any] | None = None) -> QueryResult:
        if not self._client:
            raise ConnectionError("Not connected to Qdrant")
            
        # Optional: map generic filters to Qdrant Filter models if required by ACL fuzzer later.
        # For Phase 1 we pass None.
        qdrant_filter = None
        
        results = self._client.query_points(
            collection_name=namespace,
            query=vector,
            limit=top_k,
            query_filter=qdrant_filter,
            with_payload=True
        )
        
        out_records = [
            VectorRecord(
                id=hit.id,
                vector=[], # Qdrant doesn't return vector by default on search unless with_vectors=True
                payload=hit.payload or {},
                score=hit.score,
                namespace=namespace
            )
            for hit in results.points
        ]
        return QueryResult(
            query_vector=vector,
            records=out_records,
            namespace=namespace,
            top_k=top_k
        )

    def fetch_all(self, namespace: str, with_vectors: bool = True, limit: int = 10_000) -> list[VectorRecord]:
        if not self._client:
            raise ConnectionError("Not connected to Qdrant")
            
        records = []
        offset = None
        
        while len(records) < limit:
            batch_size = min(1000, limit - len(records))
            response, offset = self._client.scroll(
                collection_name=namespace,
                limit=batch_size,
                offset=offset,
                with_payload=True,
                with_vectors=with_vectors
            )
            
            for pt in response:
                vec = pt.vector if pt.vector else []
                records.append(VectorRecord(
                    id=pt.id,
                    vector=vec,
                    payload=pt.payload or {},
                    namespace=namespace
                ))
                
            if offset is None:
                break
                
        return records

    def delete(self, ids: list[str | int], namespace: str) -> None:
        if not self._client:
            raise ConnectionError("Not connected to Qdrant")
        self._client.delete(
            collection_name=namespace,
            points_selector=models.PointIdsList(points=ids),
            wait=True
        )

    def count(self, namespace: str) -> int:
        if not self._client:
            raise ConnectionError("Not connected to Qdrant")
        response = self._client.count(collection_name=namespace)
        return response.count

    def delete_namespace(self, namespace: str) -> None:
        """Delete (drop) a collection entirely. No-op if it does not exist."""
        if not self._client:
            raise ConnectionError("Not connected to Qdrant")
        if namespace in self.list_namespaces():
            self._client.delete_collection(namespace)

    def close(self) -> None:
        if self._client:
            # Qdrant client handles its own connection pooling, no explicit close needed in newer versions
            self._client = None
