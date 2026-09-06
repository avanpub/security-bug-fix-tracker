"""Tiny JSON file cache shared by the tracker scripts.

Cache files live in the repository's `.cache/` directory (gitignored). A
missing, unreadable, or corrupt cache file is treated as a cold cache and
never fails a run; callers decide how to merge cached and fresh records.
"""
import json
import os

CACHE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".cache")


def cache_dir() -> str:
    os.makedirs(CACHE_DIR, exist_ok=True)
    return CACHE_DIR


def load_json(name: str):
    try:
        with open(os.path.join(cache_dir(), name), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def save_json(name: str, data) -> None:
    path = os.path.join(cache_dir(), name)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)
