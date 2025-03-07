import pytest
from warcio.archiveiterator import ArchiveIterator
from nabit.lib.backends.url import UrlCollectionTask
import requests
from time import sleep
from inline_snapshot import snapshot
from ..utils import filter_str

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
    
    response = UrlCollectionTask(url=server.url_for("/test.txt")).collect(capture_dir["files_dir"])
    assert filter_str(response, port=server.port) == snapshot("""\
{
  "request": {
    "url": "http://localhost:<port>/test.txt",
    "output": null,
    "timeout": 5.0
  },
  "response": {
    "path": "test.txt",
    "success": true
  }
}\
""")

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
    
    response = UrlCollectionTask(url=server.url_for("/empty")).collect(capture_dir["headers_path"])
    assert filter_str(response, port=server.port) == snapshot("""\
{
  "request": {
    "url": "http://localhost:<port>/empty",
    "output": null,
    "timeout": 5.0
  },
  "response": {
    "path": "empty.txt",
    "success": true
  }
}\
""")

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

    response = UrlCollectionTask(url=redirect_url).collect(capture_dir["headers_path"])
    assert filter_str(response, port=server.port) == snapshot("""\
{
  "request": {
    "url": "http://localhost:<port>/redirect",
    "output": null,
    "timeout": 5.0
  },
  "response": {
    "path": "test.txt",
    "success": true
  }
}\
""")

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


def test_capture_timeout(capture_dir, server):
    """Test that requests timeout after the specified duration"""
    server.expect_request("/slow").respond_with_handler(lambda req: sleep(.2))
    response = UrlCollectionTask(url=server.url_for("/slow"), timeout=0.1).collect(capture_dir["files_dir"])
    assert filter_str(response, port=server.port) == snapshot("""\
{
  "request": {
    "url": "http://localhost:<port>/slow",
    "output": null,
    "timeout": 0.1
  },
  "response": {
    "success": false,
    "error": "HTTPConnectionPool(host='localhost', port=<port>): Read timed out. (read timeout=0.1)"
  }
}\
""")
