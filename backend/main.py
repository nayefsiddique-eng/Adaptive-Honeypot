from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.api import logs, decisions, geoip, threat_intel, timeline, sessions, research, dashboard, attacks
from backend.database import init_db
from backend.services.classifier import load_models
from backend.api.adaptive import router as adaptive_router

app = FastAPI(title="Adaptive AI Honeypot", version="1.0.0")

# Setup CORS to allow React dev ports and local file execution (origin 'null')
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "null"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.on_event("startup")
async def startup():
    init_db()
    load_models()

# Register API Routers
app.include_router(logs.router, prefix="/api/logs", tags=["Logs"])
app.include_router(decisions.router, prefix="/api/decisions", tags=["Decisions"])
app.include_router(adaptive_router)
app.include_router(geoip.router)
app.include_router(threat_intel.router)
app.include_router(timeline.router)
app.include_router(sessions.router)
app.include_router(research.router)
app.include_router(dashboard.router)
app.include_router(attacks.router)

@app.get("/")
def root():
    return {"status": "Honeypot active", "version": "1.0.0"}