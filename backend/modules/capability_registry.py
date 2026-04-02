from __future__ import annotations

from typing import Any, Dict


def build_capability_registry(tool_status: Dict[str, bool] | None = None) -> Dict[str, Any]:
    status = tool_status or {}

    categories = {
        "cryptanalysis": {
            "status": "ready",
            "features": [
                "auto-detect decoding strategy",
                "multi-pass strategy solver",
                "recipe execution",
                "hash identification",
                "one-click smart crack routing",
                "upload-based extraction and solve",
                "punch-card decoding",
                "wifi psk passphrase verification/cracking",
            ],
        },
        "forensics": {
            "status": "ready",
            "features": [
                "file metadata extraction",
                "string carving",
                "basic file triage",
            ],
        },
        "osint": {
            "status": "ready",
            "features": [
                "domain and username workflows",
                "job-based execution",
                "evidence persistence",
            ],
        },
        "steganography": {
            "status": "planned",
            "features": [
                "image/audio stego detection",
                "payload extraction workflows",
            ],
        },
        "reverse_engineering": {
            "status": "planned",
            "features": [
                "binary triage",
                "symbol/string analysis",
                "decompiler-assisted summaries",
            ],
        },
        "coding": {
            "status": "planned",
            "features": [
                "algorithm helpers",
                "parser and transform scaffolds",
            ],
        },
        "web_security": {
            "status": "planned",
            "features": [
                "request replay templates",
                "payload generation helpers",
            ],
        },
        "network_analysis": {
            "status": "ready",
            "features": [
                "pcap/stream summary workflows",
                "protocol-focused extraction",
            ],
        },
    }

    optional_tools = {
        "tesseract": bool(status.get("tesseract", False)),
        "ffmpeg": bool(status.get("ffmpeg", False)),
        "hashcat": bool(status.get("hashcat", False)),
        "john": bool(status.get("john", False)),
    }

    return {
        "categories": categories,
        "optional_tools": optional_tools,
        "counts": {
            "ready": sum(1 for item in categories.values() if item["status"] == "ready"),
            "planned": sum(1 for item in categories.values() if item["status"] == "planned"),
            "total": len(categories),
        },
    }
