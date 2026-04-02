from __future__ import annotations

from pathlib import Path
from typing import List

import yaml
from pydantic import BaseModel, Field


class ServerConfig(BaseModel):
    host: str = "localhost"
    port: int = 8765
    log_level: str = "info"
    workers: int = 1


class DatabaseConfig(BaseModel):
    path: str = "ctf.db"


class WordlistsConfig(BaseModel):
    rockyou: str = "wordlists/rockyou.txt"
    ncl_common: str = "wordlists/ncl-common.txt"
    realuniq: str = "realuniq.lst"
    realhuman_phill: str = "realhuman_phill.txt"
    custom: List[str] = Field(default_factory=list)


class CryptoConfig(BaseModel):
    auto_detect_timeout_ms: int = 800
    max_decode_depth: int = 5
    vigenere_max_key_len: int = 8
    xor_max_key_len: int = 16
    nist_english_freq: bool = True


class ToolsConfig(BaseModel):
    hashcat_path: str = "hashcat"
    john_path: str = "john"
    tshark_path: str = "tshark"
    exiftool_path: str = "exiftool"
    binwalk_path: str = "binwalk"


class PerformanceConfig(BaseModel):
    pcap_max_mb: int = 250
    pcap_async_threshold_mb: int = 10
    steg_async_threshold_mb: int = 5
    job_ttl_hours: int = 24


class OnlineApisConfig(BaseModel):
    crackstation: bool = True
    hashes_com: bool = True
    shodan_api_key: str = ""
    virustotal_key: str = ""
    timeout_s: int = 5


class AppConfig(BaseModel):
    server: ServerConfig = ServerConfig()
    database: DatabaseConfig = DatabaseConfig()
    wordlists: WordlistsConfig = WordlistsConfig()
    crypto: CryptoConfig = CryptoConfig()
    tools: ToolsConfig = ToolsConfig()
    performance: PerformanceConfig = PerformanceConfig()
    online_apis: OnlineApisConfig = OnlineApisConfig()
    flag_patterns: List[str] = Field(default_factory=lambda: [
        r"NCL-[A-Z0-9]{4}-[0-9]+",
        r"flag\{[^}]+\}",
        r"HTB\{[^}]+\}",
        r"picoCTF\{[^}]+\}",
        r"ctf\{[^}]+\}",
    ])


def load_config(config_path: str = "config.yml") -> AppConfig:
    path = Path(config_path)
    if not path.exists():
        return AppConfig()
    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return AppConfig.model_validate(raw)
