import os
import json
import logging
import time
from typing import Dict, List, Any, Optional
import pymongo
from pymongo.errors import ServerSelectionTimeoutError
from app.config import settings

logger = logging.getLogger("fortifyai.db")

class InMemoryMongoFallbackCollection:
    """Lightweight in-memory document collection fallback when MongoDB server is unreachable."""
    def __init__(self, name: str, persistence_file: Optional[str] = None):
        self.name = name
        self.docs: List[Dict[str, Any]] = []
        self.persistence_file = persistence_file
        self._load()

    def _load(self):
        if self.persistence_file and os.path.exists(self.persistence_file):
            try:
                with open(self.persistence_file, "r", encoding="utf-8") as f:
                    self.docs = json.load(f)
            except Exception as e:
                logger.warning(f"Fallback DB load error for {self.name}: {e}")
                self.docs = []

    def _save(self):
        if self.persistence_file:
            try:
                os.makedirs(os.path.dirname(self.persistence_file), exist_ok=True)
                with open(self.persistence_file, "w", encoding="utf-8") as f:
                    json.dump(self.docs, f, indent=2, default=str)
            except Exception as e:
                logger.warning(f"Fallback DB save error for {self.name}: {e}")

    def insert_one(self, doc: Dict[str, Any]):
        doc_copy = dict(doc)
        if "_id" not in doc_copy:
            doc_copy["_id"] = f"fallback_{int(time.time() * 1000)}_{len(self.docs)}"
        self.docs.append(doc_copy)
        self._save()
        return type('InsertOneResult', (), {'inserted_id': doc_copy["_id"]})()

    def find(self, query: Optional[Dict[str, Any]] = None, sort: Optional[List] = None, limit: int = 100) -> List[Dict[str, Any]]:
        res = list(self.docs)
        if query:
            filtered = []
            for d in res:
                match = True
                for k, v in query.items():
                    if d.get(k) != v:
                        match = False
                        break
                if match:
                    filtered.append(d)
            res = filtered

        if sort:
            key_name = sort[0][0]
            reverse = sort[0][1] == pymongo.DESCENDING
            res.sort(key=lambda x: x.get(key_name, 0), reverse=reverse)

        return res[:limit]

    def find_one(self, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        res = self.find(query, limit=1)
        return res[0] if res else None

    def update_one(self, query: Dict[str, Any], update: Dict[str, Any], upsert: bool = False):
        set_vals = update.get("$set", {})
        doc = self.find_one(query)
        if doc:
            doc.update(set_vals)
            self._save()
            return type('UpdateResult', (), {'modified_count': 1})()
        elif upsert:
            new_doc = dict(query)
            new_doc.update(set_vals)
            self.insert_one(new_doc)
            return type('UpdateResult', (), {'modified_count': 1})()
        return type('UpdateResult', (), {'modified_count': 0})()

class DatabaseManager:
    def __init__(self):
        self.client = None
        self.db = None
        self.is_connected = False
        self.fallback_dir = os.path.join(os.path.dirname(__file__), "..", "..", "data_storage")
        self.fallback_collections: Dict[str, InMemoryMongoFallbackCollection] = {}

    def connect(self):
        try:
            client = pymongo.MongoClient(
                settings.MONGODB_URI,
                serverSelectionTimeoutMS=1500
            )
            # Test connection
            client.admin.command('ping')
            self.client = client
            self.db = client[settings.DB_NAME]
            self.is_connected = True
            logger.info(f"Connected to MongoDB at {settings.MONGODB_URI} [DB: {settings.DB_NAME}]")
        except (ServerSelectionTimeoutError, Exception) as err:
            logger.warning(f"MongoDB connection unavailable ({err}). Using persistent embedded storage fallback.")
            self.is_connected = False

    def get_collection(self, collection_name: str):
        if self.is_connected and self.db is not None:
            return self.db[collection_name]
        
        if collection_name not in self.fallback_collections:
            pers_file = os.path.join(self.fallback_dir, f"{collection_name}.json")
            self.fallback_collections[collection_name] = InMemoryMongoFallbackCollection(collection_name, pers_file)
        
        return self.fallback_collections[collection_name]

db_manager = DatabaseManager()
db_manager.connect()
