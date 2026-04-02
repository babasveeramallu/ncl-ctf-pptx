from __future__ import annotations

import asyncio
import time
from typing import Optional

from fastapi import APIRouter, File, Form, UploadFile

from ..modules.job_service import new_job_id, run_job
from ..modules.worker_service import network_pcap_worker
from ..state import CONFIG, JOBS, JOB_TASKS, TOOL_STATUS, error, success

router = APIRouter(prefix="/api/v1/network", tags=["network"])


@router.post("/pcap/upload")
async def network_pcap_upload(
    file: UploadFile = File(...),
    extract_creds: bool = Form(default=True),
    max_size_mb: Optional[int] = Form(default=None),
    timeout_s: Optional[int] = Form(default=60),
    challenge_id: Optional[int] = Form(default=None),
):
    content = await file.read()
    configured_max = max_size_mb if max_size_mb is not None else CONFIG.performance.pcap_max_mb
    file_size_mb = len(content) / (1024 * 1024)

    if file_size_mb > configured_max:
        return error("INPUT_TOO_LARGE", f"PCAP exceeds {configured_max}MB limit", status_code=413)

    job_id = new_job_id("pcap")
    JOBS[job_id] = {
        "status": "queued",
        "progress_pct": 0,
        "result": None,
        "error": None,
        "started_at": time.perf_counter(),
        "kind": "network_pcap",
    }

    worker = network_pcap_worker(file.filename or "upload.pcap", content, extract_creds, TOOL_STATUS, CONFIG)
    task = asyncio.create_task(
        run_job(
            job_id,
            jobs=JOBS,
            job_tasks=JOB_TASKS,
            db_path=CONFIG.database.path,
            module="network",
            operation="pcap_upload",
            input_summary=file.filename or "upload.pcap",
            challenge_id=challenge_id,
            timeout_s=timeout_s,
            worker_coro=worker,
        )
    )
    JOB_TASKS[job_id] = task

    return success(
        {
            "job_id": job_id,
            "size_mb": round(file_size_mb, 2),
            "estimated_s": max(1, int(file_size_mb * 2)),
        }
    )


@router.get("/pcap/{job_id}/summary")
async def network_pcap_summary(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return error("JOB_NOT_FOUND", f"No job found for id '{job_id}'", status_code=404)

    if job.get("kind") != "network_pcap":
        return error("UNSUPPORTED_FORMAT", "Job is not a network PCAP analysis job", status_code=415)

    if job["status"] != "complete":
        return success(
            {
                "job_id": job_id,
                "status": job["status"],
                "progress_pct": job.get("progress_pct", 0),
            }
        )

    return success(job["result"])
