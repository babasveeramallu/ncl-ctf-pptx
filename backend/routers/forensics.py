from __future__ import annotations

import asyncio
import time
from typing import Optional

from fastapi import APIRouter, File, Form, UploadFile

from ..modules.job_service import new_job_id, persist_tool_output, run_job
from ..modules.worker_service import forensics_steg_worker
from ..state import CONFIG, JOBS, JOB_TASKS, TOOL_STATUS, error, success

router = APIRouter(prefix="/api/v1/forensics", tags=["forensics"])


@router.post("/steg/analyze")
async def forensics_steg_analyze(
    file: UploadFile = File(...),
    timeout_s: Optional[int] = Form(default=30),
    challenge_id: Optional[int] = Form(default=None),
):
    content = await file.read()
    size_mb = len(content) / (1024 * 1024)
    if size_mb > 50:
        return error("INPUT_TOO_LARGE", "Forensics file exceeds 50MB limit", status_code=413)

    if size_mb <= CONFIG.performance.steg_async_threshold_mb:
        started = time.perf_counter()
        data = await forensics_steg_worker(file.filename or "upload.bin", content, TOOL_STATUS, CONFIG)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        persist_tool_output(
            db_path=CONFIG.database.path,
            module="forensics",
            operation="steg_analyze",
            input_summary=file.filename or "upload.bin",
            output_payload=data,
            elapsed_ms=elapsed_ms,
            success_flag=True,
            challenge_id=challenge_id,
        )
        return success(data, elapsed_ms=elapsed_ms)

    job_id = new_job_id("steg")
    JOBS[job_id] = {
        "status": "queued",
        "progress_pct": 0,
        "result": None,
        "error": None,
        "started_at": time.perf_counter(),
        "kind": "forensics_steg",
    }
    worker = forensics_steg_worker(file.filename or "upload.bin", content, TOOL_STATUS, CONFIG)
    task = asyncio.create_task(
        run_job(
            job_id,
            jobs=JOBS,
            job_tasks=JOB_TASKS,
            db_path=CONFIG.database.path,
            module="forensics",
            operation="steg_analyze",
            input_summary=file.filename or "upload.bin",
            challenge_id=challenge_id,
            timeout_s=timeout_s,
            worker_coro=worker,
        )
    )
    JOB_TASKS[job_id] = task
    return success({"job_id": job_id, "status": "running", "poll_url": f"/api/v1/jobs/{job_id}"})
