import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import settings
from .routes import scan, health
from .middleware import HMACAuthenticationMiddleware


# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)
logger = structlog.get_logger()

# Create FastAPI app
app = FastAPI(
    title="Virus Scanner API",
    description="High-accuracy virus scanning API with multi-engine detection",
    version="1.0.0"
)

# Add HMAC authentication middleware (before CORS)
app.add_middleware(HMACAuthenticationMiddleware)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan.router, prefix="/api", tags=["scan"])
app.include_router(health.router, tags=["health"])


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests with structured logging."""
    try:
        response = await call_next(request)
        logger.info(
            "request_processed",
            method=request.method,
            url=str(request.url),
            status_code=response.status_code
        )
        return response
    except Exception as e:
        logger.error(
            "request_failed",
            method=request.method,
            url=str(request.url),
            error=str(e)
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"}
        )


@app.on_event("startup")
async def startup_event():
    """Initialize resources on startup."""
    logger.info(
        "server_starting",
        host=settings.HOST,
        port=settings.PORT
    )


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup resources on shutdown."""
    logger.info("server_shutting_down") 