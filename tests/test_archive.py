import pytest
from nabit.lib.archive import copy_paths, validate_package


def test_ds_store_ignored(tmp_path):
    """Test that files in IGNORE_PATTERNS are ignored when copying directories"""
    # Setup source directory
    source_dir = tmp_path / "test_dir"
    source_dir.mkdir()
    (source_dir / ".DS_Store").write_text("ignored")
    (source_dir / "test.txt").write_text("included")
    
    # Setup destination directory
    dest_dir = tmp_path / "output"
    dest_dir.mkdir()

    # Test copying
    copy_paths([source_dir], dest_dir)

    # Verify results
    assert not (dest_dir / "test_dir/.DS_Store").exists()
    assert (dest_dir / "test_dir/test.txt").read_text() == "included"

def test_validate_raises(tmp_path):
    # make sure that vanilla validate_package raises an error
    # unless there's an error callback that does something else
    with pytest.raises(ValueError, match='No files in data/files'):
        validate_package(tmp_path)
