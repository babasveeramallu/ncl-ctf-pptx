from __future__ import annotations

import asyncio
import base64
import hashlib
import sqlite3
import time
from pathlib import Path

import pytest

from fastapi.testclient import TestClient

from backend.main import app
from backend import state
from backend.modules.request_models import PasswordCrackRequest
from backend.modules import worker_service


def _poll_job(client: TestClient, job_id: str, timeout_s: float = 3.0) -> dict:
    end = time.time() + timeout_s
    while time.time() < end:
        res = client.get(f"/api/v1/jobs/{job_id}")
        assert res.status_code == 200
        body = res.json()
        status = body["data"]["status"]
        if status in {"complete", "failed", "cancelled"}:
            return body
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not complete in time")


def _count_tool_outputs(db_path: Path, module: str, operation: str) -> int:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "select count(*) from tool_outputs where module=? and operation=?",
            (module, operation),
        ).fetchone()
    return int(row[0])


def test_root_and_health(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)
    state.JOBS.clear()
    state.JOB_TASKS.clear()
    state.TOOL_STATUS.clear()

    with TestClient(app) as client:
        root = client.get("/")
        assert root.status_code == 200
        assert root.json()["ok"] is True
        assert "docs_local" in root.json()["data"]

        health = client.get("/api/v1/health")
        assert health.status_code == 200
        assert health.json()["data"]["status"] == "ok"


def test_docs_local_page(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)
    with TestClient(app) as client:
        resp = client.get("/docs-local")
        assert resp.status_code == 200
        assert "CTF Toolkit Local Docs" in resp.text
        assert "/api/v1/crypto/auto-detect" in resp.text


def test_crypto_autodetect_and_persistence(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)
    state.JOBS.clear()
    state.JOB_TASKS.clear()

    with TestClient(app) as client:
        payload = {"input": "SGVsbG8gV29ybGQ=", "max_depth": 5}
        res = client.post("/api/v1/crypto/auto-detect", json=payload)
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        assert body["data"]["plaintext"] == "Hello World"

    assert _count_tool_outputs(db_path, "crypto", "auto_detect") >= 1


def test_osint_job_flow(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)
    state.JOBS.clear()
    state.JOB_TASKS.clear()

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/osint/username",
            json={"username": "sumuk", "platforms": ["github", "reddit", "instagram"]},
        )
        assert res.status_code == 200
        job_id = res.json()["data"]["job_id"]

        final = _poll_job(client, job_id)
        assert final["data"]["status"] == "complete"
        assert "found" in final["data"]["result"]

    assert _count_tool_outputs(db_path, "osint", "username") >= 1


def test_network_upload_summary_and_persistence(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)
    state.JOBS.clear()
    state.JOB_TASKS.clear()

    sample = b"GET / HTTP/1.1\nAuthorization: Basic YWRtaW46YWRtaW4xMjM=\n"

    with TestClient(app) as client:
        up = client.post(
            "/api/v1/network/pcap/upload",
            files={"file": ("sample.pcap", sample, "application/octet-stream")},
            data={"extract_creds": "true"},
        )
        assert up.status_code == 200
        job_id = up.json()["data"]["job_id"]

        _poll_job(client, job_id)
        summary = client.get(f"/api/v1/network/pcap/{job_id}/summary")
        assert summary.status_code == 200
        body = summary.json()
        assert body["ok"] is True
        assert "credentials" in body["data"]

    assert _count_tool_outputs(db_path, "network", "pcap_upload") >= 1


def test_forensics_inline_and_persistence(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)
    state.JOBS.clear()
    state.JOB_TASKS.clear()

    sample = b"... flag{hidden_in_file} ..."

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/forensics/steg/analyze",
            files={"file": ("sample.bin", sample, "application/octet-stream")},
            data={"timeout_s": "30"},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        assert "findings" in body["data"]

    assert _count_tool_outputs(db_path, "forensics", "steg_analyze") >= 1


def test_password_worker_fallback_md5_cracks_common_hash(tmp_path):
    wordlist = tmp_path / "rockyou.txt"
    wordlist.write_text("password\n123456\n", encoding="utf-8")

    state.CONFIG.wordlists.rockyou = str(wordlist)
    req = PasswordCrackRequest(
        hashes=[hashlib.md5(b"password").hexdigest()],
        hash_mode=0,
        attack_mode="dictionary",
        wordlist="rockyou",
        timeout_s=10,
    )
    tool_status = {
        "hashcat": {"available": False, "fallback": "john"},
        "john": {"available": False, "fallback": "passlib_brute"},
    }

    result = asyncio.run(worker_service.password_crack_worker(req, tool_status, state.CONFIG))

    assert result["engine"] == "fallback"
    assert result["fallback_used"] is True
    assert result["results"][0]["plaintext"] == "password"


def test_password_worker_hashcat_uses_resolved_wordlist(tmp_path, monkeypatch):
    wordlist = tmp_path / "ncl-common.txt"
    wordlist.write_text("password\n", encoding="utf-8")
    test_hash = hashlib.md5(b"password").hexdigest()

    state.CONFIG.wordlists.ncl_common = str(wordlist)
    req = PasswordCrackRequest(
        hashes=[test_hash],
        hash_mode=0,
        attack_mode="dictionary",
        wordlist="ncl-common",
        timeout_s=10,
    )

    calls = []

    async def fake_run_cli(cmd, timeout_s=20):
        calls.append(cmd)
        if "--show" in cmd:
            return {"ok": True, "code": 0, "stdout": f"{test_hash}:password\n", "stderr": ""}
        return {"ok": True, "code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(worker_service, "run_cli", fake_run_cli)

    tool_status = {
        "hashcat": {"available": True, "fallback": None},
        "john": {"available": False, "fallback": "passlib_brute"},
    }
    result = asyncio.run(worker_service.password_crack_worker(req, tool_status, state.CONFIG))

    assert result["engine"] == "hashcat"
    assert result["fallback_used"] is False
    assert result["results"][0]["plaintext"] == "password"
    assert any(str(wordlist) in " ".join(cmd) for cmd in calls)


def test_forensics_worker_marks_tools_unavailable_when_missing(monkeypatch):
    monkeypatch.setattr(worker_service.shutil, "which", lambda _: None)

    payload = b"\x89PNG\r\n\x1a\n...."
    result = asyncio.run(
        worker_service.forensics_steg_worker(
            "sample.png",
            payload,
            tool_status={"steghide": {"available": False}},
            config=state.CONFIG,
        )
    )

    assert result["file_type"] == "PNG"
    assert "steghide" in result["tools_unavailable"]
    assert "zsteg" in result["tools_unavailable"]
    assert "binwalk" in result["tools_unavailable"]


def test_password_worker_falls_back_to_john_when_hashcat_no_result(tmp_path, monkeypatch):
    wordlist = tmp_path / "rockyou.txt"
    wordlist.write_text("password\n", encoding="utf-8")
    test_hash = hashlib.md5(b"password").hexdigest()

    state.CONFIG.wordlists.rockyou = str(wordlist)
    req = PasswordCrackRequest(
        hashes=[test_hash],
        hash_mode=0,
        attack_mode="dictionary",
        wordlist="rockyou",
        timeout_s=10,
    )

    calls = []

    async def fake_run_cli(cmd, timeout_s=20):
        calls.append(cmd)
        cmd0 = str(cmd[0]).lower()
        is_show = "--show" in cmd
        if "hashcat" in cmd0 and is_show:
            return {"ok": True, "code": 0, "stdout": "", "stderr": ""}
        if "john" in cmd0 and is_show:
            return {"ok": True, "code": 0, "stdout": f"{test_hash}:password\n", "stderr": ""}
        return {"ok": True, "code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(worker_service, "run_cli", fake_run_cli)

    tool_status = {
        "hashcat": {"available": True, "fallback": None},
        "john": {"available": True, "fallback": None},
    }
    result = asyncio.run(worker_service.password_crack_worker(req, tool_status, state.CONFIG))

    assert result["engine"] == "john"
    assert result["fallback_used"] is False
    assert result["results"][0]["plaintext"] == "password"
    assert len(result["tool_attempts"]) >= 2
    assert any("hashcat" in str(cmd[0]).lower() for cmd in calls)
    assert any("john" in str(cmd[0]).lower() for cmd in calls)


def test_password_api_job_includes_tool_attempts(tmp_path, monkeypatch):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)
    state.JOBS.clear()
    state.JOB_TASKS.clear()

    wordlist = tmp_path / "rockyou.txt"
    wordlist.write_text("password\n", encoding="utf-8")
    state.CONFIG.wordlists.rockyou = str(wordlist)

    test_hash = hashlib.md5(b"password").hexdigest()

    async def fake_run_cli(cmd, timeout_s=20):
        if "--show" in cmd:
            return {"ok": True, "code": 0, "stdout": f"{test_hash}:password\n", "stderr": ""}
        return {"ok": True, "code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(worker_service, "run_cli", fake_run_cli)
    with TestClient(app) as client:
        state.TOOL_STATUS.clear()
        state.TOOL_STATUS.update(
            {
                "hashcat": {"available": True, "fallback": None},
                "john": {"available": False, "fallback": "passlib_brute"},
            }
        )
        res = client.post(
            "/api/v1/passwords/crack/hashcat",
            json={
                "hashes": [test_hash],
                "hash_mode": 0,
                "attack_mode": "dictionary",
                "wordlist": "rockyou",
                "timeout_s": 10,
            },
        )
        assert res.status_code == 200
        job_id = res.json()["data"]["job_id"]

        final = _poll_job(client, job_id)
        assert final["data"]["status"] == "complete"
        result = final["data"]["result"]
        assert result["engine"] == "hashcat"
        assert isinstance(result.get("tool_attempts"), list)
        assert len(result["tool_attempts"]) >= 1


def test_crypto_recipe_vigenere_decode(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/recipe/run",
            json={
                "input": "LXFOPVEFRNHR",
                "steps": [{"op": "vigenere_decode", "params": {"key": "lemon"}}],
                "stop_on_flag": False,
                "timeout_ms": 5000,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        assert body["data"]["final_output"] == "ATTACKATDAWN"


def test_crypto_recipe_rail_fence_decode(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/recipe/run",
            json={
                "input": "WECRLTEERDSOEEFEAOCAIVDEN",
                "steps": [{"op": "rail_fence_decode", "params": {"rails": 3}}],
                "stop_on_flag": False,
                "timeout_ms": 5000,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        assert body["data"]["final_output"] == "WEAREDISCOVEREDFLEEATONCE"


def test_crypto_recipe_affine_decode(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/recipe/run",
            json={
                "input": "IHHWVCSWFRCP",
                "steps": [{"op": "affine_decode", "params": {"a": 5, "b": 8}}],
                "stop_on_flag": False,
                "timeout_ms": 5000,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        assert body["data"]["final_output"] == "AFFINECIPHER"


def test_crypto_recipe_decimal_bytes_decode_hyphen_separated(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    sample = (
        "83-111-109-101-111-110-101-32-112-108-101-97-115-101-32-99-97-108-108-32-"
        "115-117-112-112-111-114-116-32-116-111-32-97-115-107-32-104-111-119-32-105-"
        "115-32-74-73-82-65-32-115-116-105-108-108-32-100-111-119-110-32-97-102-116-"
        "101-114-32-48-53-32-100-97-121-115"
    )

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/recipe/run",
            json={
                "input": sample,
                "steps": [{"op": "decimal_bytes_decode", "params": {}}],
                "stop_on_flag": False,
                "timeout_ms": 5000,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        assert "someone please call support" in body["data"]["final_output"].lower()


def test_crypto_recipe_vigenere_break_returns_metadata(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/recipe/run",
            json={
                "input": "LXFOPVEFRNHR",
                "steps": [{"op": "vigenere_break", "params": {"max_key_len": 8}}],
                "stop_on_flag": False,
                "timeout_ms": 5000,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        step = body["data"]["steps"][0]
        metadata = step["metadata"]
        assert isinstance(metadata["key"], str)
        assert isinstance(metadata["score"], float)
        assert isinstance(metadata["confidence"], float)
        assert 0.0 <= metadata["confidence"] <= 1.0
        assert isinstance(metadata["candidates"], list)
        assert len(metadata["candidates"]) >= 1
        assert "preview" in metadata["candidates"][0]


def test_crypto_recipe_xor_single_byte_break(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    plain = b"flag{xor_demo}"
    key = 42
    encoded_hex = "".join(f"{(b ^ key):02x}" for b in plain)

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/recipe/run",
            json={
                "input": encoded_hex,
                "steps": [{"op": "xor_single_byte_break", "params": {}}],
                "stop_on_flag": False,
                "timeout_ms": 5000,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        assert body["data"]["final_output"] == "flag{xor_demo}"
        assert body["data"]["steps"][0]["metadata"]["key"] == key


def test_crypto_recipe_xor_with_key_hex(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    plain = b"flag{hex_key}"
    key = 42
    encoded_hex = "".join(f"{(b ^ key):02x}" for b in plain)

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/recipe/run",
            json={
                "input": encoded_hex,
                "steps": [{"op": "xor_with_key_hex", "params": {"key_hex": "2a"}}],
                "stop_on_flag": False,
                "timeout_ms": 5000,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        assert body["data"]["final_output"] == "flag{hex_key}"


def test_crypto_recipe_xor_repeating_break_returns_key_metadata(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    plain = b"flag{repeat_xor_demo}"
    key = b"ICE"
    encoded = bytes(plain[i] ^ key[i % len(key)] for i in range(len(plain))).hex()

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/recipe/run",
            json={
                "input": encoded,
                "steps": [{"op": "xor_repeating_break", "params": {"max_key_len": 6}}],
                "stop_on_flag": False,
                "timeout_ms": 5000,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        assert isinstance(body["data"]["final_output"], str)
        assert len(body["data"]["final_output"]) == len(plain)
        metadata = body["data"]["steps"][0]["metadata"]
        assert metadata["key_len"] >= 2
        assert isinstance(metadata["key_hex"], str)
        assert isinstance(metadata["confidence"], float)
        assert 0.0 <= metadata["confidence"] <= 1.0
        assert isinstance(metadata["candidates"], list)
        assert len(metadata["candidates"]) >= 1
        assert "key_hex" in metadata["candidates"][0]
        assert "preview" in metadata["candidates"][0]


def test_crypto_strategy_run_returns_ranked_candidates(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    plain = b"flag{strategy_mode}"
    key = 42
    encoded_hex = "".join(f"{(b ^ key):02x}" for b in plain)

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/strategy/run",
            json={
                "input": encoded_hex,
                "max_depth": 5,
                "timeout_ms": 5000,
                "max_candidates": 5,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        data = body["data"]
        assert isinstance(data.get("best_output"), str) or data.get("best_output") is None
        assert isinstance(data.get("best_method"), str) or data.get("best_method") is None
        assert isinstance(data.get("candidates"), list)
        if data["candidates"]:
            top = data["candidates"][0]
            assert "method" in top
            assert "score" in top
            assert "confidence" in top
            assert "preview" in top
            assert isinstance(top.get("round"), int)
            assert isinstance(top.get("path"), list)
            assert isinstance(top.get("replay_recipe"), list)
            if top.get("replay_step"):
                assert top["replay_step"].get("op") in {
                    "byte_shift_decode",
                    "byte_affine_decode",
                    "mono_sub_decode",
                    "xor_with_key",
                    "xor_with_key_hex",
                    "vigenere_decode",
                    "rail_fence_decode",
                    "affine_decode",
                    "playfair_decode",
                }
                assert isinstance(top["replay_step"].get("params"), dict)
                assert len(top["replay_recipe"]) >= 1


def test_crypto_strategy_run_multipass_layered_input(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    plain = b"flag{beam_rounds}"
    key = 37
    xor_hex = "".join(f"{(b ^ key):02x}" for b in plain)
    layered = base64.b64encode(xor_hex.encode("utf-8")).decode("ascii")

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/strategy/run",
            json={
                "input": layered,
                "max_depth": 4,
                "timeout_ms": 5000,
                "max_candidates": 5,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        data = body["data"]
        assert isinstance(data.get("rounds_executed"), int)
        assert 1 <= data["rounds_executed"] <= 4
        assert isinstance(data.get("candidates"), list)
        if data["candidates"]:
            assert any("flag{" in str(c.get("output", "")).lower() for c in data["candidates"])


def test_crypto_strategy_run_accepts_decimal_byte_lists(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    nums = [
        215,
        193,
        252,
        202,
        255,
        247,
        251,
        142,
        247,
        193,
        194,
        194,
        142,
        248,
        197,
        200,
        255,
        255,
        250,
        142,
        196,
        255,
        248,
        142,
        201,
        252,
        142,
        245,
        254,
        202,
        201,
        250,
        197,
        142,
        193,
        252,
        142,
        184,
        186,
        142,
        253,
        193,
        252,
        245,
        250,
        197,
        251,
    ]
    decimal_input = " ".join(str(n) for n in nums)

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/strategy/run",
            json={
                "input": decimal_input,
                "max_depth": 4,
                "timeout_ms": 5000,
                "max_candidates": 8,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        data = body["data"]
        assert isinstance(data.get("candidates"), list)
        assert "decimal_bytes_decode" in data.get("methods_tried", [])


def test_crypto_strategy_run_cracks_decimal_byte_xor_single_byte(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    plain = b"flag{decimal_byte_xor}"
    key = 73
    encoded = [b ^ key for b in plain]
    decimal_input = " ".join(str(n) for n in encoded)

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/strategy/run",
            json={
                "input": decimal_input,
                "max_depth": 4,
                "timeout_ms": 5000,
                "max_candidates": 8,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        data = body["data"]
        outputs = [str(c.get("output", "")).lower() for c in data.get("candidates", [])]
        assert any("flag{" in out for out in outputs)


def test_crypto_strategy_run_cracks_decimal_byte_shift(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    plain = b"flag{byte_shift_layer}"
    shift = 73
    encoded = [(b + shift) % 256 for b in plain]
    decimal_input = " ".join(str(n) for n in encoded)

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/strategy/run",
            json={
                "input": decimal_input,
                "max_depth": 4,
                "timeout_ms": 5000,
                "max_candidates": 8,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        data = body["data"]
        outputs = [str(c.get("output", "")).lower() for c in data.get("candidates", [])]
        assert any("flag{" in out for out in outputs)


def test_crypto_byte_shift_rejects_plaintext_noop():
    from backend.modules.crypto_service import break_byte_shift

    with pytest.raises(ValueError, match="no convincing byte shift candidate"):
        break_byte_shift("this is already plain text")


def test_crypto_strategy_run_tries_mono_sub_break_on_alpha_text(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    sample = (
        "Xli uymgo fvsar jsb nyqtw sziv xli pedc hsk. "
        "Xli uymgo fvsar jsb nyqtw sziv xli pedc hsk. flag{mono_layer_test}"
    )

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/strategy/run",
            json={"input": sample, "max_depth": 4, "timeout_ms": 5000, "max_candidates": 8},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        data = body["data"]
        assert "mono_sub_break" in data.get("methods_tried", [])


def test_crypto_strategy_explore_endpoint_returns_bucketed_candidates(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    plain = b"flag{explore_candidate_depth}"
    key = 19
    encoded_hex = "".join(f"{(b ^ key):02x}" for b in plain)

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/strategy/explore",
            json={
                "input": encoded_hex,
                "max_depth": 4,
                "timeout_ms": 5000,
                "max_candidates": 20,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        data = body["data"]
        assert data.get("requested_max_candidates") == 20
        assert isinstance(data.get("candidates"), list)
        assert len(data["candidates"]) <= 20
        assert isinstance(data.get("method_buckets"), dict)


def test_crypto_strategy_run_prefers_hex_then_base64_chain(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    # Hex string that decodes to base64, then to readable plaintext.
    sample = "54335679494739775a584a6864476c7662694273595856755932686c63794270626941344e79426f6233567963773d3d"

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/strategy/run",
            json={"input": sample, "max_depth": 5, "timeout_ms": 5000, "max_candidates": 8},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        data = body["data"]
        out = str(data.get("best_output") or "").lower()
        assert "our operation launches in 87 hours" in out


def test_crypto_strategy_upload_text_file_runs_strategy(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    sample = "54335679494739775a584a6864476c7662694273595856755932686c63794270626941344e79426f6233567963773d3d"

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/strategy/upload",
            files={"file": ("sample.txt", sample.encode("utf-8"), "text/plain")},
            data={"mode": "auto", "max_depth": "5", "timeout_ms": "5000", "max_candidates": "8"},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        data = body["data"]
        assert data["upload"]["mode"] == "text"
        assert "strategy" in data
        assert "our operation launches in 87 hours" in str(data["strategy"].get("best_output", "")).lower()


def test_crypto_strategy_upload_audio_missing_dependency_error(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/crypto/strategy/upload",
            files={"file": ("sample.wav", b"RIFF....WAVE", "audio/wav")},
            data={"mode": "audio", "max_depth": "5", "timeout_ms": "5000", "max_candidates": "8"},
        )
        assert res.status_code == 422
        body = res.json()
        assert body["ok"] is False
        assert body.get("error", {}).get("code") == "TOOL_UNAVAILABLE"


def test_crypto_strategy_run_handles_simple_multi_format_samples(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    cases = [
        ("0x73636f7270696f6e", "scorpion"),
        ("c2NyaWJibGU=", "scribble"),
        ("01110011 01100101 01100011 01110101 01110010 01100101 01101100 01111001", "securely"),
        (
            "01100010 01000111 00111001 01110011 01100010 01000111 01101100 01110111 01100010 00110011 01000001 00111101",
            "lollipop",
        ),
    ]

    with TestClient(app) as client:
        for sample, expected in cases:
            res = client.post(
                "/api/v1/crypto/strategy/run",
                json={"input": sample, "max_depth": 5, "timeout_ms": 5000, "max_candidates": 8},
            )
            assert res.status_code == 200
            body = res.json()
            assert body["ok"] is True
            out = str(body["data"].get("best_output") or "").lower()
            assert expected in out


def test_crypto_strategy_history_endpoint(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    plain = b"flag{history_check}"
    key = 19
    encoded_hex = "".join(f"{(b ^ key):02x}" for b in plain)

    with TestClient(app) as client:
        run = client.post(
            "/api/v1/crypto/strategy/run",
            json={
                "input": encoded_hex,
                "max_depth": 4,
                "timeout_ms": 5000,
                "max_candidates": 5,
            },
        )
        assert run.status_code == 200

        hist = client.get("/api/v1/crypto/strategy/history", params={"limit": 5})
        assert hist.status_code == 200
        body = hist.json()
        assert body["ok"] is True
        data = body["data"]
        assert data["count"] >= 1
        assert isinstance(data["entries"], list)
        first = data["entries"][0]
        assert "operation" in first
        assert "best_method" in first
        assert "candidate_count" in first


def test_crypto_strategy_history_detail_endpoint(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    plain = b"flag{history_detail}"
    key = 11
    encoded_hex = "".join(f"{(b ^ key):02x}" for b in plain)

    with TestClient(app) as client:
        run = client.post(
            "/api/v1/crypto/strategy/run",
            json={
                "input": encoded_hex,
                "max_depth": 4,
                "timeout_ms": 5000,
                "max_candidates": 5,
            },
        )
        assert run.status_code == 200

        hist = client.get("/api/v1/crypto/strategy/history", params={"limit": 1})
        assert hist.status_code == 200
        hist_body = hist.json()
        assert hist_body["ok"] is True
        entry_id = hist_body["data"]["entries"][0]["id"]

        detail = client.get(f"/api/v1/crypto/strategy/history/{entry_id}")
        assert detail.status_code == 200
        detail_body = detail.json()
        assert detail_body["ok"] is True
        assert detail_body["data"]["id"] == entry_id
        assert isinstance(detail_body["data"]["output"], dict)
        assert "candidates" in detail_body["data"]["output"]


def test_crypto_strategy_history_rerun_endpoint(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    plain = b"flag{rerun_entry}"
    key = 7
    encoded_hex = "".join(f"{(b ^ key):02x}" for b in plain)

    with TestClient(app) as client:
        run = client.post(
            "/api/v1/crypto/strategy/run",
            json={
                "input": encoded_hex,
                "max_depth": 4,
                "timeout_ms": 5000,
                "max_candidates": 5,
            },
        )
        assert run.status_code == 200

        hist = client.get("/api/v1/crypto/strategy/history", params={"limit": 1})
        assert hist.status_code == 200
        entry_id = hist.json()["data"]["entries"][0]["id"]

        rerun = client.post(f"/api/v1/crypto/strategy/history/{entry_id}/rerun")
        assert rerun.status_code == 200
        body = rerun.json()
        assert body["ok"] is True
        data = body["data"]
        assert data["rerun_of_entry_id"] == entry_id
        assert isinstance(data.get("candidates"), list)

        hist = client.get("/api/v1/crypto/strategy/history", params={"limit": 2})
        assert hist.status_code == 200
        entries = hist.json()["data"]["entries"]
        rerun_entry = next((e for e in entries if e.get("operation") == "strategy_rerun"), None)
        assert rerun_entry is not None

        detail_rerun = client.get(f"/api/v1/crypto/strategy/history/{rerun_entry['id']}")
        assert detail_rerun.status_code == 200


def test_crypto_strategy_history_compare_and_report(tmp_path):
    db_path = tmp_path / "ctf_test.db"
    state.CONFIG.database.path = str(db_path)

    first_input = "".join(f"{(b ^ 3):02x}" for b in b"flag{compare_one}")
    second_input = "".join(f"{(b ^ 9):02x}" for b in b"flag{compare_two}")

    with TestClient(app) as client:
        r1 = client.post(
            "/api/v1/crypto/strategy/run",
            json={"input": first_input, "max_depth": 4, "timeout_ms": 5000, "max_candidates": 5},
        )
        r2 = client.post(
            "/api/v1/crypto/strategy/run",
            json={"input": second_input, "max_depth": 4, "timeout_ms": 5000, "max_candidates": 5},
        )
        assert r1.status_code == 200
        assert r2.status_code == 200

        hist = client.get("/api/v1/crypto/strategy/history", params={"limit": 2})
        assert hist.status_code == 200
        entries = hist.json()["data"]["entries"]
        assert len(entries) >= 2
        left_id = entries[0]["id"]
        right_id = entries[1]["id"]

        compare = client.get("/api/v1/crypto/strategy/history/compare/runs", params={"left_id": left_id, "right_id": right_id})
        assert compare.status_code == 200
        compare_data = compare.json()["data"]
        assert "left" in compare_data
        assert "right" in compare_data
        assert "diff" in compare_data
        assert "shared_methods" in compare_data["diff"]

        report = client.get(f"/api/v1/crypto/strategy/history/{left_id}/report")
        assert report.status_code == 200
        report_data = report.json()["data"]
        assert report_data["entry_id"] == left_id
        assert isinstance(report_data["report"], str)
        assert "Best Method:" in report_data["report"]
