import pytest
from warcio.archiveiterator import ArchiveIterator
from nabit.lib.backends.url import UrlCollectionTask


@pytest.fixture
def capture_dir(tmp_path):
    """Create and return paths for capture testing"""
    headers_path = tmp_path / "headers.warc"
    files_dir = tmp_path / "files"
    files_dir.mkdir()
    return {
        "headers_path": headers_path,
        "files_dir": files_dir
    }


def test_capture_with_content(capture_dir, server):
    """Test capturing a 200 response with body content"""
    
    UrlCollectionTask(url=server.url_for("/test.txt")).collect(capture_dir["files_dir"])

    # Check headers.warc
    with open(capture_dir["headers_path"], 'rb') as fh:
        records = list(ArchiveIterator(fh))
        assert len(records) == 2  # request and response
        assert records[0].rec_type == 'revisit'
        assert records[1].rec_type == 'request'
        profile = records[0].rec_headers.get_header('WARC-Profile')
        assert profile.startswith('file-content')
        
    # Check captured file
    assert len(list(capture_dir["files_dir"].glob("*"))) == 1
    captured_file = next(capture_dir["files_dir"].glob("*"))
    assert captured_file.read_text() == "test content"


def test_capture_empty_response(capture_dir, server):
    """Test capturing a 200 response without body content"""
    # Add empty response to server
    server.expect_request("/empty").respond_with_data("")
    
    UrlCollectionTask(url=server.url_for("/empty")).collect(capture_dir["headers_path"])

    # Check headers.warc - should be a response record, not revisit
    with open(capture_dir["headers_path"], 'rb') as fh:
        records = list(ArchiveIterator(fh))
        assert len(records) == 2  # request and response
        assert records[0].rec_type == 'response'  # not request for empty response
        assert records[1].rec_type == 'request'
        assert 'WARC-Profile' not in records[0].rec_headers

    # Check no file was created
    assert len(list(capture_dir["files_dir"].glob("*"))) == 0


def test_capture_redirect(capture_dir, server):
    """Test capturing a redirect that leads to a 200"""
    # Add redirect to server
    redirect_url = server.url_for("/redirect")
    target_url = server.url_for("/test.txt")
    server.expect_request("/redirect").respond_with_data(
        status=302,
        headers={"Location": target_url}
    )

    UrlCollectionTask(url=redirect_url).collect(capture_dir["headers_path"])

    # Check headers.warc
    with open(capture_dir["headers_path"], 'rb') as fh:
        records = list(ArchiveIterator(fh))
        assert len(records) == 4  # two requests and two responses
        
        # First pair: redirect
        assert records[0].rec_type == 'response'
        assert records[1].rec_type == 'request'
        assert records[0].http_headers.get_statuscode() == '302'
        
        # Second pair: final destination
        assert records[2].rec_type == 'revisit'
        assert records[3].rec_type == 'request'
        assert records[2].http_headers.get_statuscode() == '200'
        
    # Check captured file
    assert len(list(capture_dir["files_dir"].glob("*"))) == 1
    captured_file = next(capture_dir["files_dir"].glob("*"))
    assert captured_file.read_text() == "test content"
