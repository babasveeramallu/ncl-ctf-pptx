from __future__ import annotations

import json
import sqlite3

from fastapi import APIRouter

from ..modules.job_service import job_view
from ..state import CONFIG, JOBS, JOB_TASKS, error, success

router = APIRouter(prefix="/api/v1/jobs", tags=["jobs"])


@router.get("/{job_id}")
async def jobs_get(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return error("JOB_NOT_FOUND", f"No job found for id '{job_id}'", status_code=404)
    return success(job_view(job_id, job))


@router.delete("/{job_id}")
async def jobs_delete(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return error("JOB_NOT_FOUND", f"No job found for id '{job_id}'", status_code=404)

    task = JOB_TASKS.get(job_id)
    if task and not task.done():
        task.cancel()
    else:
        job["status"] = "cancelled"
        job["error"] = {"code": "JOB_CANCELLED", "message": "Job cancelled by user"}

    return success({"job_id": job_id, "status": "cancelled"})


@router.get("/history")
async def jobs_history(limit: int = 25, module: str | None = None):
    safe_limit = max(1, min(limit, 200))

    where_clause = ""
    params: tuple = ()
    if module:
        where_clause = "WHERE module = ?"
        params = (module,)

    query = f"""
        SELECT id, challenge_id, module, operation, input_summary, output_json, elapsed_ms, success, created_at
        FROM tool_outputs
        {where_clause}
        ORDER BY created_at DESC, id DESC
        LIMIT ?
    """

    with sqlite3.connect(CONFIG.database.path) as conn:
        rows = conn.execute(query, (*params, safe_limit)).fetchall()

    entries = []
    for row in rows:
        entries.append(
            {
                "id": row[0],
                "challenge_id": row[1],
                "module": row[2],
                "operation": row[3],
                "input_summary": row[4],
                "elapsed_ms": row[6],
                "success": bool(row[7]),
                "created_at": row[8],
            }
        )

    return success({"entries": entries, "count": len(entries), "limit": safe_limit, "module": module})


@router.get("/history/{entry_id}")
async def jobs_history_detail(entry_id: int):
    with sqlite3.connect(CONFIG.database.path) as conn:
        row = conn.execute(
            """
            SELECT id, challenge_id, module, operation, input_summary, output_json, elapsed_ms, success, created_at
            FROM tool_outputs
            WHERE id = ?
            LIMIT 1
            """,
            (entry_id,),
        ).fetchone()

    if not row:
        return error("JOB_NOT_FOUND", f"No log entry found for id '{entry_id}'", status_code=404)

    try:
        output_payload = json.loads(row[5] or "{}")
    except Exception:
        output_payload = {}

    return success(
        {
            "id": row[0],
            "challenge_id": row[1],
            "module": row[2],
            "operation": row[3],
            "input_summary": row[4],
            "output": output_payload,
            "elapsed_ms": row[6],
            "success": bool(row[7]),
            "created_at": row[8],
        }
    )
