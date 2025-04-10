import pytest
from nabit.lib.archive import validate_package


def test_validate_raises(tmp_path):
    # make sure that vanilla validate_package raises an error
    # unless there's an error callback that does something else
    with pytest.raises(ValueError, match='bagit.txt does not exist'):
        validate_package(tmp_path)
