import random
import string
from pathlib import Path


def get_unique_path(path: Path) -> Path:
    """Return a unique path by appending a random 6-character suffix to the filename."""
    new_path = path
    while new_path.exists():
        stem = path.name.split('.')[0]
        suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        new_path = path.with_name(path.name.replace(stem, f"{stem}-{suffix}", 1))
    return new_path

def noop(*args, **kwargs):
    """Default callback function that does nothing."""
    pass
