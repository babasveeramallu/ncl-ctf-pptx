from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class AutoDetectRequest(BaseModel):
    input: str
    input_format: Literal["text", "hex", "base64_file", "binary"] = "text"
    max_depth: int = Field(default=5, ge=1, le=10)
    flag_pattern: Optional[str] = None
    timeout_ms: int = Field(default=800, ge=1, le=2000)
    challenge_id: Optional[int] = None


class RecipeStep(BaseModel):
    op: str
    params: Dict[str, Any] = Field(default_factory=dict)


class RecipeRequest(BaseModel):
    input: str
    steps: List[RecipeStep]
    stop_on_flag: bool = True
    flag_pattern: Optional[str] = None
    timeout_ms: int = Field(default=5000, ge=1, le=5000)
    challenge_id: Optional[int] = None


class HashIdentifyRequest(BaseModel):
    hash: str
    online_lookup: bool = True
    timeout_ms: int = Field(default=1000, ge=1, le=1000)
    challenge_id: Optional[int] = None


class CryptoStrategyRequest(BaseModel):
    input: str
    max_depth: int = Field(default=5, ge=1, le=10)
    flag_pattern: Optional[str] = None
    timeout_ms: int = Field(default=5000, ge=1, le=12000)
    max_candidates: int = Field(default=5, ge=1, le=10)
    challenge_id: Optional[int] = None


class CryptoStrategyExploreRequest(BaseModel):
    input: str
    max_depth: int = Field(default=5, ge=1, le=10)
    flag_pattern: Optional[str] = None
    timeout_ms: int = Field(default=5000, ge=1, le=12000)
    max_candidates: int = Field(default=20, ge=5, le=30)
    challenge_id: Optional[int] = None


class PasswordCrackRequest(BaseModel):
    hashes: List[str] = Field(default_factory=list)
    hash_mode: int
    attack_mode: Literal["dictionary", "brute", "mask", "hybrid"]
    wordlist: Optional[str] = "rockyou"
    rule_file: Optional[str] = None
    mask: Optional[str] = None
    rules: List[str] = Field(default_factory=list)
    top_rules_limit: int = Field(default=10, ge=1, le=100)
    timeout_s: Optional[int] = 120
    challenge_id: Optional[int] = None


class WifiPSKCrackRequest(BaseModel):
    config_text: str
    wordlist: Optional[str] = "rockyou"
    timeout_s: Optional[int] = 180
    max_attempts: int = Field(default=250000, ge=1000, le=5000000)
    challenge_id: Optional[int] = None


class OsintSubdomainsRequest(BaseModel):
    domain: str
    mode: Literal["passive", "active"] = "passive"
    sources: List[str] = Field(default_factory=lambda: ["crt.sh", "subfinder"])
    timeout_s: Optional[int] = 30
    challenge_id: Optional[int] = None


class OsintUsernameRequest(BaseModel):
    username: str
    platforms: List[str] = Field(default_factory=lambda: ["github", "reddit", "twitter", "instagram"])
    timeout_s: Optional[int] = 30
    challenge_id: Optional[int] = None
