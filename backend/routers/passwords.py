from __future__ import annotations

import asyncio
import time

from fastapi import APIRouter, File, Form, UploadFile

from ..modules.job_service import new_job_id, run_job
from ..modules.password_crack_service import extract_office_hash_from_file_bytes
from ..modules.request_models import PasswordCrackRequest, WifiPSKCrackRequest
from ..modules.worker_service import password_crack_worker, wifi_psk_crack_worker
from ..state import CONFIG, JOBS, JOB_TASKS, TOOL_STATUS, error, success

router = APIRouter(prefix="/api/v1/passwords", tags=["passwords"])


@router.post("/extract/office-hash")
async def passwords_extract_office_hash(
    file: UploadFile = File(...),
    timeout_s: int = Form(20),
):
    payload = await file.read()
    result = extract_office_hash_from_file_bytes(file.filename or "office.bin", payload, timeout_s=timeout_s)
    if not result.get("ok"):
        return error("OFFICE_HASH_EXTRACT_FAILED", str(result.get("error", "Unknown extraction error")), details=result)
    return success(result)


@router.post("/crack/hashcat")
async def passwords_crack_hashcat(req: PasswordCrackRequest):
    if not req.hashes:
        return error("SCHEMA_MISMATCH", "Field 'hashes' must contain at least one hash", status_code=422)

    job_id = new_job_id("hc")
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
            module="passwords",
            operation="crack_hashcat",
            input_summary=f"hashes={len(req.hashes)} hash_mode={req.hash_mode}",
            challenge_id=req.challenge_id,
            timeout_s=req.timeout_s,
                worker_coro=password_crack_worker(req, TOOL_STATUS, CONFIG),
        )
    )
    JOB_TASKS[job_id] = task

    return success({"job_id": job_id, "status": "running", "poll_url": f"/api/v1/jobs/{job_id}"})


@router.post("/crack/wifi-psk")
async def passwords_crack_wifi_psk(req: WifiPSKCrackRequest):
    if not req.config_text.strip():
        return error("SCHEMA_MISMATCH", "Field 'config_text' must not be empty", status_code=422)

    job_id = new_job_id("wifi")
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
            module="passwords",
            operation="crack_wifi_psk",
            input_summary="wifi psk config",
            challenge_id=req.challenge_id,
            timeout_s=req.timeout_s,
            worker_coro=wifi_psk_crack_worker(req, CONFIG),
        )
    )
    JOB_TASKS[job_id] = task

    return success({"job_id": job_id, "status": "running", "poll_url": f"/api/v1/jobs/{job_id}"})
