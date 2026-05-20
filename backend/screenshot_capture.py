"""
Optional Playwright-based screenshot capture for live HTTP 200 hosts.
"""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("subfinderx.screenshots")

SCREENSHOTS_DIR = Path(__file__).parent / "screenshots"
SCREENSHOT_TIMEOUT_MS = 5000
MAX_QUICK_SCREENSHOTS = 2
MAX_FULL_SCREENSHOTS = 5
JPEG_QUALITY = 55
VIEWPORT = {"width": 1280, "height": 720}


def _safe_filename(host: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", host)[:120]


def is_screenshot_eligible(entry: Dict[str, Any]) -> bool:
    if not (entry.get("is_live") or entry.get("status_label") == "active"):
        return False
    try:
        return int(entry.get("status") or entry.get("http_status") or 0) == 200
    except (TypeError, ValueError):
        return False


def _target_url(entry: Dict[str, Any]) -> str:
    protocol = entry.get("protocol") or "https"
    if protocol not in ("http", "https"):
        protocol = "https"
    return f"{protocol}://{entry.get('name', '')}"


async def capture_screenshots_for_scan(
    result: Dict[str, Any],
    session_id: str,
    scan_mode: str,
) -> None:
    """
    Capture screenshots for eligible live hosts. Failures are logged and skipped.
    Mutates entries with screenshot_url when successful.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.warning("Playwright not installed; skipping screenshots (pip install playwright)")
        return

    targets = [e for e in result.get("subdomains", []) if is_screenshot_eligible(e)]
    max_count = MAX_QUICK_SCREENSHOTS if scan_mode == "quick" else MAX_FULL_SCREENSHOTS
    targets = targets[:max_count]

    if not targets:
        return

    session_dir = SCREENSHOTS_DIR / session_id
    session_dir.mkdir(parents=True, exist_ok=True)
    result["screenshot_session"] = session_id

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport=VIEWPORT,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 SubFinderX/1.0"
                ),
            )

            for entry in targets:
                host = entry.get("name", "")
                logger.info("Capturing screenshot: %s", host)
                outfile = session_dir / f"{_safe_filename(host)}.jpg"
                page = None
                try:
                    page = await context.new_page()
                    await page.goto(
                        _target_url(entry),
                        timeout=SCREENSHOT_TIMEOUT_MS,
                        wait_until="domcontentloaded",
                    )
                    await page.screenshot(
                        path=str(outfile),
                        type="jpeg",
                        quality=JPEG_QUALITY,
                        full_page=False,
                    )
                    compress_screenshot(outfile)
                    entry["screenshot_path"] = str(outfile)
                    entry["screenshot_url"] = f"/screenshots/{session_id}/{outfile.name}"
                    logger.info("Screenshot saved: %s", outfile)
                except Exception as exc:
                    logger.warning("Screenshot failed for %s: %s", host, exc)
                    entry["screenshot_url"] = None
                finally:
                    if page is not None:
                        try:
                            await page.close()
                        except Exception:
                            pass

            await browser.close()
    except Exception as exc:
        logger.warning("Screenshot batch failed: %s", exc)


def compress_screenshot(path: Path) -> None:
    """Optional extra compression via Pillow when available."""
    try:
        from PIL import Image

        with Image.open(path) as img:
            img = img.convert("RGB")
            img.save(path, format="JPEG", optimize=True, quality=JPEG_QUALITY)
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("Screenshot compression skipped: %s", exc)
