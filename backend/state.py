from __future__ import annotations

import asyncio
from typing import Any, Dict

from fastapi.responses import JSONResponse

from .config import load_config

CONFIG = load_config()
TOOL_STATUS: Dict[str, Any] = {}
JOBS: Dict[str, Dict[str, Any]] = {}
JOB_TASKS: Dict[str, asyncio.Task] = {}


def success(data: Dict[str, Any], elapsed_ms: int = 0) -> Dict[str, Any]:
    return {"ok": True, "data": data, "elapsed_ms": elapsed_ms}


def error(code: str, message: str, status_code: int = 400, fallback_used: bool = False) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"ok": False, "error": {"code": code, "message": message, "fallback_used": fallback_used}},
    )
