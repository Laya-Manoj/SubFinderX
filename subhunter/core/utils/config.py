"""
Configuration utilities for SubHunter.

This module centralizes configuration loading so that API keys and
runtime options can be provided via environment variables or a
future configuration file.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Optional


@dataclass(slots=True)
class APIConfig:
    """Holds API keys and settings for passive data sources."""

    virustotal_api_key: Optional[str] = None
    securitytrails_api_key: Optional[str] = None
    chaos_api_key: Optional[str] = None
    user_agent: str = "SubHunter/1.0 (+https://github.com/)"


@dataclass(slots=True)
class RuntimeConfig:
    """
    Runtime configuration derived from CLI arguments and environment.

    Full recon (passive + DNS + HTTP + historical) is always performed.
    """

    domain: str
    concurrency: int = 25
    output_json: bool = False
    output_txt: bool = False
    silent: bool = False
    only_new: bool = False


def load_api_config() -> APIConfig:
    """
    Load API configuration from environment variables.

    Environment variables:
      - SUBHUNTER_VT_API_KEY
      - SUBHUNTER_SECURITYTRAILS_API_KEY
      - SUBHUNTER_CHAOS_API_KEY
      - SUBHUNTER_USER_AGENT (optional override)
    """

    return APIConfig(
        virustotal_api_key=os.getenv("SUBHUNTER_VT_API_KEY"),
        securitytrails_api_key=os.getenv("SUBHUNTER_SECURITYTRAILS_API_KEY"),
        chaos_api_key=os.getenv("SUBHUNTER_CHAOS_API_KEY"),
        user_agent=os.getenv("SUBHUNTER_USER_AGENT", "SubHunter/1.0 (+https://github.com/)"),
    )

