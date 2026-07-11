import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.api import logs, decisions, geoip, threat_intel, timeline, sessions, research, dashboard, attacks, admin
from backend.database import init_db, SessionLocal
from backend.services.classifier import load_models
from backend.api.adaptive import router as adaptive_router
from backend.models.session import AttackerSession
from backend.core.rl_engine import update_q_table_for_session

async def session_reaper():
    """
    Background task to automatically reap (close) inactive sessions and trigger Q-learning updates.
    """
    while True:
        try:
            await asyncio.sleep(5)  # check every 5 seconds
            db = SessionLocal()
            try:
                # Find active sessions inactive for more than 15 seconds
                time_limit = datetime.utcnow() - timedelta(seconds=15)
                expired_sessions = db.query(AttackerSession).filter(
                    AttackerSession.is_active == True,
                    AttackerSession.last_seen < time_limit
                ).all()

                for session in expired_sessions:
                    session.is_active = False
                    if session.rl_state and session.rl_action:
                        update_q_table_for_session(
                            db=db,
                            session_id=session.session_id,
                            state_str=session.rl_state,
                            action_str=session.rl_action,
                            deception_score=session.rl_deception_score or 0.0
                        )
                db.commit()
            except Exception as e:
                db.rollback()
                print(f"Error in session reaper iteration: {e}")
            finally:
                db.close()
        except Exception as e:
            print(f"General error in session reaper: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    load_models()
    asyncio.create_task(session_reaper())
    yield
    # Shutdown (nothing to clean up currently)

app = FastAPI(title="Adaptive AI Honeypot", version="1.0.0", lifespan=lifespan)

# Setup CORS to allow React dev ports and local file execution (origin 'null')
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "null"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Register API Routers
app.include_router(logs.router, prefix="/api/logs", tags=["Logs"])
app.include_router(decisions.router, prefix="/api/decisions", tags=["Decisions"])
app.include_router(sessions.router)
app.include_router(admin.router)
app.include_router(adaptive_router)
app.include_router(geoip.router)
app.include_router(timeline.router)
app.include_router(research.router)
app.include_router(dashboard.router)
app.include_router(attacks.router)

@app.get("/")
def root():
    return {"status": "Honeypot active", "version": "1.0.0"}
