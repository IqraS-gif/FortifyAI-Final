import os
from dotenv import load_dotenv
from pydantic import BaseModel

env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    load_dotenv()

class Settings(BaseModel):
    PROJECT_NAME: str = "FortifyAI Prompt Injection & Document Security Engine"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"
    
    # MongoDB Config
    MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    DB_NAME: str = os.getenv("DB_NAME", "fortify_ai")
    
    # ML Model Config
    MODERNBERT_MODEL_NAME: str = "answerdotai/ModernBERT-base"
    LOCAL_MODEL_DIR: str = os.path.join(os.path.dirname(__file__), "..", "models", "modernbert_prompt_injection")
    
    # Performance & SLA
    LATENCY_BUDGET_MS: float = 100.0
    
    # Sensitivity Threshold Defaults
    DEFAULT_SENSITIVITY: str = "BALANCED"
    
    SENSITIVITY_PROFILES: dict = {
        "FINANCE_STRICT": {
            "name": "Finance Agent (Wallet & Data Access)",
            "description": "Aggressive strict scanning for financial transactions, API keys, and sensitive data access.",
            "risk_threshold": 35.0, # Flag anything with risk >= 35
            "require_ml_scan": True,
            "scan_metadata": True
        },
        "BALANCED": {
            "name": "General Assistant / Code Reviewer",
            "description": "Balanced protection for corporate chatbots and programming assistants.",
            "risk_threshold": 60.0, # Flag risk >= 60
            "require_ml_scan": True,
            "scan_metadata": True
        },
        "SUPPORT_LENIENT": {
            "name": "Customer Support Bot",
            "description": "Lenient threshold prioritizing user experience and low false positives.",
            "risk_threshold": 85.0, # Flag risk >= 85
            "require_ml_scan": True,
            "scan_metadata": False
        }
    }

settings = Settings()
