from sqlalchemy import create_engine, text, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from backend.config import settings

engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_db():
    from backend.models import attack, session, reputation  # noqa
    Base.metadata.create_all(bind=engine)
    migrate_db()

def migrate_db():
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    
    if "attack_logs" in tables:
        columns = [c['name'] for c in inspector.get_columns('attack_logs')]
        with engine.begin() as conn:
            if 'session_id' not in columns:
                conn.execute(text("ALTER TABLE attack_logs ADD COLUMN session_id VARCHAR"))
            if 'city' not in columns:
                conn.execute(text("ALTER TABLE attack_logs ADD COLUMN city VARCHAR"))
            if 'latitude' not in columns:
                conn.execute(text("ALTER TABLE attack_logs ADD COLUMN latitude FLOAT"))
            if 'longitude' not in columns:
                conn.execute(text("ALTER TABLE attack_logs ADD COLUMN longitude FLOAT"))
            if 'response_time_ms' not in columns:
                conn.execute(text("ALTER TABLE attack_logs ADD COLUMN response_time_ms FLOAT DEFAULT 0.0"))
                
    if "attacker_sessions" in tables:
        columns = [c['name'] for c in inspector.get_columns('attacker_sessions')]
        with engine.begin() as conn:
            if 'session_duration' not in columns:
                conn.execute(text("ALTER TABLE attacker_sessions ADD COLUMN session_duration FLOAT DEFAULT 0.0"))
            if 'commands_issued' not in columns:
                conn.execute(text("ALTER TABLE attacker_sessions ADD COLUMN commands_issued JSON"))
            if 'payload_hashes' not in columns:
                conn.execute(text("ALTER TABLE attacker_sessions ADD COLUMN payload_hashes JSON"))
            if 'interaction_depth' not in columns:
                conn.execute(text("ALTER TABLE attacker_sessions ADD COLUMN interaction_depth INTEGER DEFAULT 0"))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()