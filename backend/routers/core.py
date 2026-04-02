from __future__ import annotations

from html import escape
from typing import Any, Dict

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ..modules.capability_registry import build_capability_registry
from ..state import CONFIG, TOOL_STATUS, success

router = APIRouter()


@router.get("/")
async def root() -> Dict[str, Any]:
    return success(
        {
            "service": "CTF Master Toolkit API",
            "version": "0.1.0",
            "health": "/api/v1/health",
            "docs": "/docs",
            "docs_local": "/docs-local",
        }
    )


@router.get("/api/v1")
async def api_root() -> Dict[str, Any]:
    return success(
        {"message": "API v1 online", "health": "/api/v1/health", "docs": "/docs", "docs_local": "/docs-local"}
    )


@router.get("/api/v1/health")
async def health() -> Dict[str, Any]:
    return success(
        {
            "status": "ok",
            "version": "0.1.0",
            "tool_status": TOOL_STATUS,
            "config_loaded": CONFIG is not None,
        }
    )


@router.get("/api/v1/capabilities")
async def capabilities() -> Dict[str, Any]:
    return success(
        {
            "service": "CTF Master Toolkit API",
            "version": "0.1.0",
            "registry": build_capability_registry(TOOL_STATUS),
        }
    )


def _render_docs_html(request: Request) -> str:
    spec = request.app.openapi()
    paths = spec.get("paths", {})
    path_rows: list[str] = []
    for path, methods in sorted(paths.items()):
        for method, op in methods.items():
            summary = escape(str(op.get("summary", "")))
            m = escape(method.upper())
            p = escape(path)
            suffix = f" - {summary}" if summary else ""
            path_rows.append(f"<div class='path'><span class='method {method.lower()}'>{m}</span> {p}{suffix}</div>")

    rows_html = "\n".join(path_rows) if path_rows else "<div>No paths found.</div>"
    head = """
<!doctype html>
<html>
<head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>CTF Toolkit Local Docs</title>
    <style>
        body { font-family: Consolas, monospace; margin: 24px; background: #0f1115; color: #e8ecf1; }
        h1 { margin: 0 0 8px; }
        .muted { color: #9fb0c3; margin-bottom: 18px; }
        .path { margin: 10px 0; padding: 10px; border: 1px solid #2b3340; border-radius: 8px; background: #151922; }
        .method { display:inline-block; min-width: 62px; font-weight: 700; }
        .get { color:#53d1ff; } .post { color:#7df36a; } .delete { color:#ff9d66; }
        a { color:#9ac8ff; }
    </style>
</head>
<body>
    <h1>CTF Toolkit Local Docs</h1>
    <div class=\"muted\">Fully offline docs page rendered on the server. OpenAPI JSON: <a href=\"/openapi.json\">/openapi.json</a></div>
</body>
</html>
"""
    return head.replace("</body>", rows_html + "\n</body>")


@router.get("/docs", response_class=HTMLResponse)
async def docs(request: Request) -> str:
    return _render_docs_html(request)


@router.get("/docs-local", response_class=HTMLResponse)
async def docs_local(request: Request) -> str:
    return _render_docs_html(request)
