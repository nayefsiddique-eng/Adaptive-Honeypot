from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./honeypot.db"
    SECRET_KEY: str = "changeme-in-production"
    GEOIP_DB_PATH: str = "data/GeoLite2-City.mmdb"
    ML_MODEL_PATH: str = "ml/models/classifier.pkl"
    LOG_DIR: str = "logs/"

    class Config:
        env_file = ".env"

settings = Settings()
