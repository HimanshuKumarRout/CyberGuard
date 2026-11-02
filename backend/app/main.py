"""
CYBERGUARD Application Entry Point
FastAPI Application, Middleware, Lifecycle Hooks & Router Registration.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from contextlib import asynccontextmanager
import logging

from app.config import settings
from app.api.endpoints import router as api_router
from app.db.supabase import db

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.app_debug else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("cyberguard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup actions
    logger.info(f"Starting {settings.app_name} in {settings.app_env} mode (Simulation: {settings.simulation_mode})")
    db.init_db()
    logger.info("CYBERGUARD ready for real-time threat ingestion.")

    yield

    # Teardown actions
    logger.info(f"Shutting down {settings.app_name}.")


app = FastAPI(
    title=f"{settings.app_name} - AI-Powered Cyber Threat Detection & Response Platform",
    description="Institutional-grade autonomous cyber defense and digital-trust system.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS Middleware
origins = settings.get_cors_origins()
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GZip Response Compression Middleware (compresses responses >= 1KB)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Include API Router
app.include_router(api_router)


@app.get("/", summary="Root status check")
async def root():
    return {
        "system": settings.app_name,
        "version": "1.0.0",
        "status": "Operational",
        "docs": "/docs",
        "api_prefix": "/api"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.app_debug
    )
