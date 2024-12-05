from nabit.lib.backends.path import PathCollectionTask
from inline_snapshot import snapshot
from ..utils import filter_str

def test_ds_store_ignored(tmp_path):
    """Test that files in ignore_patterns are ignored when copying directories"""
    # Setup source directory
    source_dir = tmp_path / "test_dir"
    source_dir.mkdir()
    (source_dir / ".DS_Store").write_text("ignored")
    (source_dir / "test.txt").write_text("included")

    # Setup destination directory
    dest_dir = tmp_path / "output"
    dest_dir.mkdir()

    # Test copying
    response = PathCollectionTask(path=str(source_dir)).collect(dest_dir)
    assert filter_str(response, path=tmp_path) == snapshot("""\
{
  "request": {
    "path": "<path>/test_dir",
    "output": null,
    "hard_links": false,
    "ignore_patterns": [
      ".DS_Store"
    ]
  },
  "response": {
    "path": "test_dir",
    "success": true
  }
}\
""")

    # Verify results
    assert not (dest_dir / "test_dir/.DS_Store").exists()
    assert (dest_dir / "test_dir/test.txt").read_text() == "included"