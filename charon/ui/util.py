"""Small formatting helpers shared by the panes and the queue view."""

from __future__ import annotations

import time
from datetime import datetime

_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def human_size(value: int | float) -> str:
    if value is None or value < 0:
        return ""
    size = float(value)
    for unit in _UNITS:
        if size < 1024 or unit == _UNITS[-1]:
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def human_rate(bytes_per_second: float) -> str:
    return f"{human_size(bytes_per_second)}/s" if bytes_per_second > 0 else ""


def human_eta(seconds: float) -> str:
    if seconds <= 0 or seconds > 86_400 * 7:
        return ""
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"


def human_time(stamp: float) -> str:
    if not stamp:
        return ""
    try:
        dt = datetime.fromtimestamp(stamp)
    except (OverflowError, OSError, ValueError):
        return ""
    now = time.time()
    if now - stamp < 86_400 * 300:
        return dt.strftime("%d %b %H:%M")
    return dt.strftime("%d %b %Y")


def elide(text: str, limit: int = 60) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"
