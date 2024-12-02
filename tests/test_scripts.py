from pathlib import Path
from scripts.update_docs import get_new_readme_text, readme_path

def test_get_new_readme_text():
    assert readme_path.read_text() == get_new_readme_text(), "README.md is out of date, run `uv run scripts/update_docs.py` to update"
