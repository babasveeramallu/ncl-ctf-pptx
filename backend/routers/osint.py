from __future__ import annotations

import asyncio
import time

from fastapi import APIRouter

from ..modules.job_service import new_job_id, run_job
from ..modules.request_models import OsintSubdomainsRequest, OsintUsernameRequest
from ..modules.worker_service import osint_subdomains_worker, osint_username_worker
from ..state import CONFIG, JOBS, JOB_TASKS, error, success

router = APIRouter(prefix="/api/v1/osint", tags=["osint"])


@router.post("/subdomains")
async def osint_subdomains(req: OsintSubdomainsRequest):
    if not req.domain.strip():
        return error("SCHEMA_MISMATCH", "Field 'domain' must not be empty", status_code=422)

    job_id = new_job_id("osi")
    JOBS[job_id] = {
        "status": "queued",
        "progress_pct": 0,
        "result": None,
        "error": None,
        "started_at": time.perf_counter(),
    }
    task = asyncio.create_task(
        run_job(
            job_id,
            jobs=JOBS,
            job_tasks=JOB_TASKS,
            db_path=CONFIG.database.path,
            module="osint",
            operation="subdomains",
            input_summary=req.domain,
            challenge_id=req.challenge_id,
            timeout_s=req.timeout_s,
            worker_coro=osint_subdomains_worker(req),
        )
    )
    JOB_TASKS[job_id] = task

    return success({"job_id": job_id, "status": "running", "poll_url": f"/api/v1/jobs/{job_id}"})


@router.post("/username")
async def osint_username(req: OsintUsernameRequest):
    if not req.username.strip():
        return error("SCHEMA_MISMATCH", "Field 'username' must not be empty", status_code=422)

    job_id = new_job_id("osi")
    JOBS[job_id] = {
        "status": "queued",
        "progress_pct": 0,
        "result": None,
        "error": None,
        "started_at": time.perf_counter(),
    }
    task = asyncio.create_task(
        run_job(
            job_id,
            jobs=JOBS,
            job_tasks=JOB_TASKS,
            db_path=CONFIG.database.path,
            module="osint",
            operation="username",
            input_summary=req.username,
            challenge_id=req.challenge_id,
            timeout_s=req.timeout_s,
            worker_coro=osint_username_worker(req),
        )
    )
    JOB_TASKS[job_id] = task

    return success({"job_id": job_id, "status": "running", "poll_url": f"/api/v1/jobs/{job_id}"})
