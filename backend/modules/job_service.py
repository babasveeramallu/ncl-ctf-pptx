from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from typing import Any, Dict, Optional
from uuid import uuid4


def persist_tool_output(
    db_path: str,
    module: str,
    operation: str,
    input_summary: str,
    output_payload: Dict[str, Any],
    elapsed_ms: int,
    success_flag: bool,
    challenge_id: Optional[int] = None,
) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO tool_outputs (challenge_id, module, operation, input_summary, output_json, elapsed_ms, success)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                challenge_id,
                module,
                operation,
                input_summary[:200],
                json.dumps(output_payload),
                elapsed_ms,
                1 if success_flag else 0,
            ),
        )
        conn.commit()


def new_job_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:6]}"


def job_elapsed_ms(job: Dict[str, Any]) -> int:
    return int((time.perf_counter() - job["started_at"]) * 1000)


def job_view(job_id: str, job: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "job_id": job_id,
        "status": job["status"],
        "progress_pct": job.get("progress_pct", 0),
        "elapsed_ms": job_elapsed_ms(job),
        "result": job.get("result"),
        "error": job.get("error"),
    }


async def run_job(
    job_id: str,
    *,
    jobs: Dict[str, Dict[str, Any]],
    job_tasks: Dict[str, asyncio.Task],
    db_path: str,
    module: str,
    operation: str,
    input_summary: str,
    challenge_id: Optional[int],
    timeout_s: Optional[int],
    worker_coro,
) -> None:
    job = jobs[job_id]
    job["status"] = "running"
    job["progress_pct"] = 10

    try:
        result = await asyncio.wait_for(worker_coro, timeout=timeout_s) if timeout_s else await worker_coro
        job["status"] = "complete"
        job["progress_pct"] = 100
        job["result"] = result
        persist_tool_output(
            db_path=db_path,
            module=module,
            operation=operation,
            input_summary=input_summary,
            output_payload=result,
            elapsed_ms=job_elapsed_ms(job),
            success_flag=True,
            challenge_id=challenge_id,
        )
    except asyncio.CancelledError:
        job["status"] = "cancelled"
        job["error"] = {"code": "JOB_CANCELLED", "message": "Job cancelled by user"}
        persist_tool_output(
            db_path=db_path,
            module=module,
            operation=operation,
            input_summary=input_summary,
            output_payload={"status": "cancelled", "error": job["error"]},
            elapsed_ms=job_elapsed_ms(job),
            success_flag=False,
            challenge_id=challenge_id,
        )
    except asyncio.TimeoutError:
        job["status"] = "failed"
        job["error"] = {"code": "JOB_TIMEOUT", "message": "Async job exceeded timeout"}
        persist_tool_output(
            db_path=db_path,
            module=module,
            operation=operation,
            input_summary=input_summary,
            output_payload={"status": "failed", "error": job["error"]},
            elapsed_ms=job_elapsed_ms(job),
            success_flag=False,
            challenge_id=challenge_id,
        )
    except Exception as exc:
        job["status"] = "failed"
        job["error"] = {"code": "TOOL_FAILED", "message": str(exc)}
        persist_tool_output(
            db_path=db_path,
            module=module,
            operation=operation,
            input_summary=input_summary,
            output_payload={"status": "failed", "error": job["error"]},
            elapsed_ms=job_elapsed_ms(job),
            success_flag=False,
            challenge_id=challenge_id,
        )
    finally:
        job_tasks.pop(job_id, None)
