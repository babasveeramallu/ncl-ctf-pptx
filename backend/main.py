from __future__ import annotations

import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .routers import core, crypto, forensics, jobs, network, osint, passwords
from .startup import check_tools, initialize_database
from .state import CONFIG, TOOL_STATUS


@asynccontextmanager
async def lifespan(app: FastAPI):
    db_path = CONFIG.database.path
    schema_path = str(Path(__file__).parent / "db" / "schema.sql")
    initialize_database(db_path=db_path, schema_path=schema_path)
    TOOL_STATUS.clear()
    TOOL_STATUS.update(check_tools())
    yield


app = FastAPI(title="CTF Master Toolkit API", version="0.1.0", docs_url=None, redoc_url=None, lifespan=lifespan)


@app.middleware("http")
async def processing_time_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    response.headers["X-Processing-Time-Ms"] = str(elapsed_ms)
    return response


@app.exception_handler(NotImplementedError)
async def not_implemented_handler(_: Request, exc: NotImplementedError):
    return JSONResponse(
        status_code=501,
        content={
            "ok": False,
            "error": {
                "code": "NOT_IMPLEMENTED",
                "message": str(exc) or "Endpoint not implemented",
                "fallback_used": False,
            },
        },
    )


app.include_router(core.router)
app.include_router(crypto.router)
app.include_router(passwords.router)
app.include_router(osint.router)
app.include_router(network.router)
app.include_router(forensics.router)
app.include_router(jobs.router)
