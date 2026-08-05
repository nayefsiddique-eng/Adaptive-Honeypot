from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./honeypot.db"
    SECRET_KEY: str = "changeme-in-production"
    GEOIP_DB_PATH: str = "data/GeoLite2-City.mmdb"
    ML_MODEL_PATH: str = "ml/models/classifier.pkl"
    LOG_DIR: str = "logs/"

    # Comma-separated list of allowed origins for the dashboard/API.
    # Defaults cover same-origin (:8000) plus common local dev setups.
    CORS_ALLOWED_ORIGINS: str = (
        "http://localhost:8000,http://127.0.0.1:8000,"
        "http://localhost:5173,http://127.0.0.1:5173,"
        "http://localhost:5500,http://127.0.0.1:5500,"
        "http://localhost:3000,http://127.0.0.1:3000"
    )

    # Shared-secret key required (via X-Admin-Key header) for destructive
    # admin operations (reset-demo, close-sessions, guided-demo).
    ADMIN_API_KEY: str = "changeme-admin-key"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ALLOWED_ORIGINS.split(",") if o.strip()]

settings = Settings()
