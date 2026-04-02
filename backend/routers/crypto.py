from __future__ import annotations

import asyncio
import json
import sqlite3
import time

from fastapi import APIRouter, File, Form, UploadFile

from ..modules.crypto_service import auto_detect, identify_hash, run_recipe, strategy_run
from ..modules.job_service import persist_tool_output
from ..modules.media_extract_service import extract_text_from_media
from ..modules.request_models import (
    AutoDetectRequest,
    CryptoStrategyExploreRequest,
    CryptoStrategyRequest,
    HashIdentifyRequest,
    RecipeRequest,
)
from ..state import CONFIG, error, success

router = APIRouter(prefix="/api/v1/crypto", tags=["crypto"])


@router.post("/auto-detect")
async def crypto_auto_detect(req: AutoDetectRequest):
    if len(req.input.encode("utf-8")) > 50 * 1024:
        return error("INPUT_TOO_LARGE", "Input exceeds 50KB limit for auto-detect", status_code=413)

    patterns = [req.flag_pattern] if req.flag_pattern else CONFIG.flag_patterns
    started = time.perf_counter()
    data = auto_detect(
        input_text=req.input,
        max_depth=req.max_depth,
        flag_patterns=patterns,
        timeout_ms=req.timeout_ms,
    )
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    persist_tool_output(
        db_path=CONFIG.database.path,
        module="crypto",
        operation="auto_detect",
        input_summary=req.input,
        output_payload=data,
        elapsed_ms=elapsed_ms,
        success_flag=True,
        challenge_id=req.challenge_id,
    )
    return success(data=data, elapsed_ms=elapsed_ms)


@router.post("/recipe/run")
async def crypto_recipe_run(req: RecipeRequest):
    if len(req.input.encode("utf-8")) > 50 * 1024:
        return error("INPUT_TOO_LARGE", "Input exceeds 50KB limit for recipe execution", status_code=413)

    patterns = [req.flag_pattern] if req.flag_pattern else CONFIG.flag_patterns
    started = time.perf_counter()
    data = run_recipe(
        input_text=req.input,
        steps=[step.model_dump() for step in req.steps],
        stop_on_flag=req.stop_on_flag,
        flag_patterns=patterns,
        timeout_ms=req.timeout_ms,
    )
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    persist_tool_output(
        db_path=CONFIG.database.path,
        module="crypto",
        operation="recipe_run",
        input_summary=req.input,
        output_payload=data,
        elapsed_ms=elapsed_ms,
        success_flag=True,
        challenge_id=req.challenge_id,
    )
    return success(data=data, elapsed_ms=elapsed_ms)


@router.post("/hash/identify")
async def crypto_hash_identify(req: HashIdentifyRequest):
    if not req.hash.strip():
        return error("SCHEMA_MISMATCH", "Field 'hash' must not be empty", status_code=422)

    started = time.perf_counter()
    try:
        data = await asyncio.wait_for(asyncio.to_thread(identify_hash, req.hash), timeout=req.timeout_ms / 1000)
    except asyncio.TimeoutError:
        return error("JOB_TIMEOUT", "Hash identify operation timed out", status_code=200)

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    persist_tool_output(
        db_path=CONFIG.database.path,
        module="crypto",
        operation="hash_identify",
        input_summary=req.hash,
        output_payload=data,
        elapsed_ms=elapsed_ms,
        success_flag=True,
        challenge_id=req.challenge_id,
    )
    return success(data=data, elapsed_ms=elapsed_ms)


@router.post("/strategy/run")
async def crypto_strategy_run(req: CryptoStrategyRequest):
    if len(req.input.encode("utf-8")) > 50 * 1024:
        return error("INPUT_TOO_LARGE", "Input exceeds 50KB limit for strategy execution", status_code=413)

    patterns = [req.flag_pattern] if req.flag_pattern else CONFIG.flag_patterns
    started = time.perf_counter()
    data = strategy_run(
        input_text=req.input,
        max_depth=req.max_depth,
        flag_patterns=patterns,
        timeout_ms=req.timeout_ms,
        max_candidates=req.max_candidates,
        vigenere_max_key_len=CONFIG.crypto.vigenere_max_key_len,
        xor_max_key_len=CONFIG.crypto.xor_max_key_len,
    )
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    persist_tool_output(
        db_path=CONFIG.database.path,
        module="crypto",
        operation="strategy_run",
        input_summary=req.input,
        output_payload=data,
        elapsed_ms=elapsed_ms,
        success_flag=True,
        challenge_id=req.challenge_id,
    )
    return success(data=data, elapsed_ms=elapsed_ms)


@router.post("/strategy/explore")
async def crypto_strategy_explore(req: CryptoStrategyExploreRequest):
    if len(req.input.encode("utf-8")) > 50 * 1024:
        return error("INPUT_TOO_LARGE", "Input exceeds 50KB limit for strategy execution", status_code=413)

    patterns = [req.flag_pattern] if req.flag_pattern else CONFIG.flag_patterns
    started = time.perf_counter()
    data = strategy_run(
        input_text=req.input,
        max_depth=req.max_depth,
        flag_patterns=patterns,
        timeout_ms=req.timeout_ms,
        max_candidates=req.max_candidates,
        vigenere_max_key_len=CONFIG.crypto.vigenere_max_key_len,
        xor_max_key_len=CONFIG.crypto.xor_max_key_len,
    )
    elapsed_ms = int((time.perf_counter() - started) * 1000)

    candidates = data.get("candidates", []) if isinstance(data, dict) else []
    method_buckets = {}
    for cand in candidates:
        method = str(cand.get("method") or "unknown")
        method_buckets[method] = int(method_buckets.get(method, 0)) + 1

    explore_payload = {
        **data,
        "requested_max_candidates": req.max_candidates,
        "method_buckets": method_buckets,
    }

    persist_tool_output(
        db_path=CONFIG.database.path,
        module="crypto",
        operation="strategy_explore",
        input_summary=req.input,
        output_payload=explore_payload,
        elapsed_ms=elapsed_ms,
        success_flag=True,
        challenge_id=req.challenge_id,
    )
    return success(data=explore_payload, elapsed_ms=elapsed_ms)


@router.post("/strategy/upload")
async def crypto_strategy_upload(
    file: UploadFile = File(...),
    mode: str = Form("auto"),
    max_depth: int = Form(5),
    timeout_ms: int = Form(5000),
    max_candidates: int = Form(10),
    flag_pattern: str | None = Form(default=None),
    challenge_id: int | None = Form(default=None),
):
    raw = await file.read()
    if len(raw) > 10 * 1024 * 1024:
        return error("INPUT_TOO_LARGE", "Uploaded file exceeds 10MB limit", status_code=413)

    safe_depth = max(1, min(max_depth, 10))
    safe_timeout = max(1, min(timeout_ms, 12000))
    safe_candidates = max(1, min(max_candidates, 30))
    patterns = [flag_pattern] if flag_pattern else CONFIG.flag_patterns

    try:
        extraction = extract_text_from_media(
            raw=raw,
            filename=file.filename or "upload.bin",
            content_type=file.content_type or "application/octet-stream",
            mode=mode,
        )
    except RuntimeError as exc:
        return error("TOOL_UNAVAILABLE", str(exc), status_code=422)
    except ValueError as exc:
        return error("SCHEMA_MISMATCH", str(exc), status_code=422)

    extracted_text = str(extraction.get("extracted_text", ""))
    if not extracted_text.strip():
        return error("SCHEMA_MISMATCH", "No extractable text found in upload", status_code=422)

    started = time.perf_counter()
    data = strategy_run(
        input_text=extracted_text,
        max_depth=safe_depth,
        flag_patterns=patterns,
        timeout_ms=safe_timeout,
        max_candidates=safe_candidates,
        vigenere_max_key_len=CONFIG.crypto.vigenere_max_key_len,
        xor_max_key_len=CONFIG.crypto.xor_max_key_len,
    )
    elapsed_ms = int((time.perf_counter() - started) * 1000)

    payload = {
        "upload": {
            "filename": file.filename,
            "content_type": file.content_type,
            "mode": extraction.get("mode"),
            "engine": extraction.get("engine"),
        },
        "extracted_text": extracted_text,
        "strategy": data,
    }

    persist_tool_output(
        db_path=CONFIG.database.path,
        module="crypto",
        operation="strategy_upload",
        input_summary=f"{file.filename or 'upload.bin'} ({mode})",
        output_payload=payload,
        elapsed_ms=elapsed_ms,
        success_flag=True,
        challenge_id=challenge_id,
    )

    return success(data=payload, elapsed_ms=elapsed_ms)


@router.get("/strategy/history")
async def crypto_strategy_history(limit: int = 10):
    safe_limit = max(1, min(limit, 100))
    rows = []
    with sqlite3.connect(CONFIG.database.path) as conn:
        rows = conn.execute(
            """
            SELECT id, operation, input_summary, output_json, elapsed_ms, success, created_at
            FROM tool_outputs
            WHERE module = ? AND operation IN (?, ?)
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            ("crypto", "strategy_run", "strategy_rerun", safe_limit),
        ).fetchall()

    entries = []
    for row in rows:
        output_payload = {}
        try:
            output_payload = json.loads(row[3] or "{}")
        except Exception:
            output_payload = {}

        entries.append(
            {
                "id": row[0],
                "operation": row[1],
                "input_summary": row[2],
                "best_method": output_payload.get("best_method"),
                "best_output": output_payload.get("best_output"),
                "candidate_count": output_payload.get("candidate_count"),
                "elapsed_ms": row[4],
                "success": bool(row[5]),
                "created_at": row[6],
            }
        )

    return success({"entries": entries, "count": len(entries)})


@router.get("/strategy/history/{entry_id}")
async def crypto_strategy_history_detail(entry_id: int):
    row = None
    with sqlite3.connect(CONFIG.database.path) as conn:
        row = conn.execute(
            """
            SELECT id, input_summary, output_json, elapsed_ms, success, created_at
            FROM tool_outputs
            WHERE id = ? AND module = ? AND operation IN (?, ?)
            LIMIT 1
            """,
            (entry_id, "crypto", "strategy_run", "strategy_rerun"),
        ).fetchone()

    if not row:
        return error("JOB_NOT_FOUND", f"No strategy history entry found for id '{entry_id}'", status_code=404)

    output_payload = {}
    try:
        output_payload = json.loads(row[2] or "{}")
    except Exception:
        output_payload = {}

    return success(
        {
            "id": row[0],
            "input_summary": row[1],
            "output": output_payload,
            "elapsed_ms": row[3],
            "success": bool(row[4]),
            "created_at": row[5],
        }
    )


@router.get("/strategy/history/compare/runs")
async def crypto_strategy_history_compare(left_id: int, right_id: int):
    with sqlite3.connect(CONFIG.database.path) as conn:
        rows = conn.execute(
            """
            SELECT id, operation, input_summary, output_json, elapsed_ms, success, created_at
            FROM tool_outputs
            WHERE id IN (?, ?) AND module = ? AND operation IN (?, ?)
            """,
            (left_id, right_id, "crypto", "strategy_run", "strategy_rerun"),
        ).fetchall()

    if len(rows) != 2:
        return error("JOB_NOT_FOUND", "One or both strategy history entries were not found", status_code=404)

    parsed = {}
    for row in rows:
        try:
            output_payload = json.loads(row[3] or "{}")
        except Exception:
            output_payload = {}
        parsed[row[0]] = {
            "id": row[0],
            "operation": row[1],
            "input_summary": row[2],
            "output": output_payload,
            "elapsed_ms": row[4],
            "success": bool(row[5]),
            "created_at": row[6],
        }

    left = parsed[left_id]
    right = parsed[right_id]

    left_best = str((left["output"] or {}).get("best_output") or "")
    right_best = str((right["output"] or {}).get("best_output") or "")
    left_methods = {str(c.get("method")) for c in (left["output"] or {}).get("candidates", []) if c.get("method")}
    right_methods = {str(c.get("method")) for c in (right["output"] or {}).get("candidates", []) if c.get("method")}

    return success(
        {
            "left": {
                "id": left["id"],
                "operation": left["operation"],
                "best_method": (left["output"] or {}).get("best_method"),
                "best_output": left_best,
                "candidate_count": len((left["output"] or {}).get("candidates", [])),
                "elapsed_ms": left["elapsed_ms"],
            },
            "right": {
                "id": right["id"],
                "operation": right["operation"],
                "best_method": (right["output"] or {}).get("best_method"),
                "best_output": right_best,
                "candidate_count": len((right["output"] or {}).get("candidates", [])),
                "elapsed_ms": right["elapsed_ms"],
            },
            "diff": {
                "same_best_output": left_best == right_best and left_best != "",
                "shared_methods": sorted(left_methods.intersection(right_methods)),
                "left_only_methods": sorted(left_methods - right_methods),
                "right_only_methods": sorted(right_methods - left_methods),
                "elapsed_delta_ms": int(left["elapsed_ms"] or 0) - int(right["elapsed_ms"] or 0),
            },
        }
    )


@router.get("/strategy/history/{entry_id}/report")
async def crypto_strategy_history_report(entry_id: int):
    with sqlite3.connect(CONFIG.database.path) as conn:
        row = conn.execute(
            """
            SELECT id, operation, input_summary, output_json, elapsed_ms, success, created_at
            FROM tool_outputs
            WHERE id = ? AND module = ? AND operation IN (?, ?)
            LIMIT 1
            """,
            (entry_id, "crypto", "strategy_run", "strategy_rerun"),
        ).fetchone()

    if not row:
        return error("JOB_NOT_FOUND", f"No strategy history entry found for id '{entry_id}'", status_code=404)

    try:
        output_payload = json.loads(row[3] or "{}")
    except Exception:
        output_payload = {}

    candidates = output_payload.get("candidates", []) if isinstance(output_payload, dict) else []
    top3 = candidates[:3]
    lines = [
        f"Strategy Entry #{row[0]} ({row[1]})",
        f"Created At: {row[6]}",
        f"Elapsed: {row[4]} ms",
        f"Best Method: {output_payload.get('best_method')}",
        f"Best Output: {output_payload.get('best_output')}",
        f"Candidate Count: {len(candidates)}",
        "Top Candidates:",
    ]
    for idx, cand in enumerate(top3, start=1):
        lines.append(
            f"{idx}. method={cand.get('method')} score={cand.get('score')} conf={cand.get('confidence')} preview={str(cand.get('preview', ''))[:80]}"
        )

    return success({"entry_id": row[0], "report": "\n".join(lines), "lines": lines})


@router.post("/strategy/history/{entry_id}/rerun")
async def crypto_strategy_history_rerun(
    entry_id: int,
    max_depth: int = 5,
    timeout_ms: int = 5000,
    max_candidates: int = 5,
):
    row = None
    with sqlite3.connect(CONFIG.database.path) as conn:
        row = conn.execute(
            """
            SELECT id, input_summary
            FROM tool_outputs
            WHERE id = ? AND module = ? AND operation IN (?, ?)
            LIMIT 1
            """,
            (entry_id, "crypto", "strategy_run", "strategy_rerun"),
        ).fetchone()

    if not row:
        return error("JOB_NOT_FOUND", f"No strategy history entry found for id '{entry_id}'", status_code=404)

    safe_depth = max(1, min(max_depth, 10))
    safe_timeout = max(1, min(timeout_ms, 12000))
    safe_candidates = max(1, min(max_candidates, 10))

    patterns = CONFIG.flag_patterns
    started = time.perf_counter()
    data = strategy_run(
        input_text=row[1],
        max_depth=safe_depth,
        flag_patterns=patterns,
        timeout_ms=safe_timeout,
        max_candidates=safe_candidates,
        vigenere_max_key_len=CONFIG.crypto.vigenere_max_key_len,
        xor_max_key_len=CONFIG.crypto.xor_max_key_len,
    )
    data["rerun_of_entry_id"] = row[0]
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    persist_tool_output(
        db_path=CONFIG.database.path,
        module="crypto",
        operation="strategy_rerun",
        input_summary=row[1],
        output_payload=data,
        elapsed_ms=elapsed_ms,
        success_flag=True,
        challenge_id=None,
    )
    return success(data=data, elapsed_ms=elapsed_ms)
