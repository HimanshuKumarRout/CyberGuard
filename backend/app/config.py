"""
CYBERGUARD Configuration Management
Loads configuration from environment variables or .env file with robust fallbacks.
"""
from typing import List, Union
from pydantic_settings import BaseSettings, SettingsConfigDict
import json


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Core Application Settings
    app_name: str = "CYBERGUARD"
    app_env: str = "development"
    app_debug: bool = True
    port: int = 8000
    host: str = "0.0.0.0"

    # Security & Tokens
    jwt_secret: str = "cyberguard-default-dev-secret-key-do-not-use-in-prod"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 1440

    # Simulation & Containment Safeguards
    simulation_mode: bool = True
    auto_containment_threshold: int = 80

    # Database & Persistence
    supabase_url: str = ""
    supabase_key: str = ""
    database_url: str = ""

    # CORS configuration
    cors_origins: Union[str, List[str]] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000"
    ]

    def get_cors_origins(self) -> List[str]:
        if isinstance(self.cors_origins, list):
            return self.cors_origins
        try:
            parsed = json.loads(self.cors_origins)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            pass
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


# Global cached settings instance
settings = Settings()
