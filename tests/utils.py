import json
from pathlib import Path
import re
from nabit.lib.archive import validate_package

def append_text(path: Path, text: str) -> None:
    """Append text to a file."""
    with open(path, 'a') as f:
        f.write(text)

def _validate(bag_path: Path):
    """Capture validation output"""
    responses = []
    validate_package(
        bag_path,
        error=lambda msg, metadata=None: responses.append(f"ERROR: {msg}"),
        warn=lambda msg, metadata=None: responses.append(f"WARNING: {msg}"),
        success=lambda msg, metadata=None: responses.append(f"SUCCESS: {msg}")
    )
    out = "\n".join(responses)
    out = out.replace(str(bag_path), "<bag_path>")
    return out

def validate_failing(bag_path: Path):
    """Capture validation output, asserting that it fails"""
    output = _validate(bag_path)
    assert "ERROR:" in output
    return output

def validate_passing(bag_path: Path):
    """Capture validation output, asserting that it passes"""
    output = _validate(bag_path)
    assert "ERROR:" not in output
    return output

def replace_hashes(text: str) -> str:
    """Replace all hashes with a placeholder"""
    return re.sub(r'\b[0-9a-f]{64}\b', '<hash>', text)

def filter_str(obj, **kwargs):
    """
    Turn obj into a string, replacing any kwarg values with their keys.
    Helpful for consistent comparisons in assertions.
    """
    out = json.dumps(obj, indent=2, default=str)
    out = re.sub(r'object at 0x[0-9a-f]+', 'object at <hex>', out)
    for key, value in kwargs.items():
        out = out.replace(str(value), f"<{key}>")
    return out
