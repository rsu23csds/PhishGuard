from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    mongo_uri: str = "mongodb://localhost:27017"
    mongo_db_name: str = "phishing_detector"
    jwt_secret: str = "dev-only-change-me"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 1440
    backend_cors_origins: str = "http://localhost:5173,http://localhost:8080"
    rate_limit_per_minute: int = 30
    admin_email: str = "admin@example.com"
    admin_password: str = "ChangeMe123!"
    ml_model_path: str = "ml/models/phishing_model.joblib"

    # External Reputation APIs (optional; graceful fallback if absent)
    virustotal_api_key: str = ""
    google_safebrowsing_api_key: str = ""



    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.backend_cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
