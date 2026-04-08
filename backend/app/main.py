from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import stix

app = FastAPI(title="STIX Threat Analyzer", version="1.0.0")

# Allow CORS for local development with frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict to frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(stix.router, prefix="/api/stix", tags=["stix"])

@app.get("/")
def read_root():
    return {"message": "Welcome to the STIX Threat Analyzer API"}
