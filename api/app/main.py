from fastapi import FastAPI

from app.config import settings

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    docs_url="/docs",
    openapi_url="/openapi.json",
)


@app.get("/health")
def health():
    return {"status": "ok", "service": settings.app_name}


@app.get("/api/v1/meta")
def meta():
    return {
        "service": settings.app_name,
        "stack": ["wireguard", "xray", "fastapi", "caddy"],
    }
