from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000

    DATABASE_URL: str = "sqlite:///./honeypot.db"
    SECRET_KEY: str = "changeme-in-production"
    GEOIP_DB_PATH: str = "data/GeoLite2-City.mmdb"
    ML_MODEL_PATH: str = "ml/models/classifier.pkl"
    LOG_DIR: str = "logs/"

    # Limits
    MAX_REQUEST_BODY_BYTES: int = 1048576  # 1MB
    MAX_COMMAND_LENGTH: int = 8192
    MAX_CONCURRENT_SESSIONS: int = 500
    MAX_SESSION_DURATION: int = 3600
    API_RATE_LIMIT: int = 60
    API_RATE_WINDOW_SECONDS: int = 60

    # Log rotation configs
    LOG_MAX_BYTES: int = 10485760  # 10MB
    LOG_BACKUP_COUNT: int = 5

    # Comma-separated list of allowed origins for the dashboard/API.
    # Defaults cover same-origin (:8000) plus common local dev setups.
    CORS_ALLOWED_ORIGINS: str = (
        "http://localhost:8000,http://127.0.0.1:8000,"
        "http://localhost:5173,http://127.0.0.1:5173,"
        "http://localhost:5500,http://127.0.0.1:5500,"
        "http://localhost:3000,http://127.0.0.1:3000"
    )

    # Shared-secret key required (via X-Admin-Key header / X-Management-Key header)
    ADMIN_API_KEY: str = "changeme-admin-key"
    MANAGEMENT_API_KEY: str = "changeme-management-key"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ALLOWED_ORIGINS.split(",") if o.strip()]

    def validate_production(self):
        if self.ENVIRONMENT.lower() == "production":
            if self.SECRET_KEY == "changeme-in-production":
                raise ValueError("SECRET_KEY must be changed in production mode.")
            if self.MANAGEMENT_API_KEY == "changeme-management-key":
                raise ValueError("MANAGEMENT_API_KEY must be changed in production mode.")
            if self.ADMIN_API_KEY == "changeme-admin-key":
                raise ValueError("ADMIN_API_KEY must be changed in production mode.")

settings = Settings()
settings.validate_production()

