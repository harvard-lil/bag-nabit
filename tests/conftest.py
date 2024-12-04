from click.testing import CliRunner
import pytest
from pytest_httpserver import HTTPServer

from nabit.lib.archive import package
from nabit.lib.sign import KNOWN_TSAS
from nabit.lib.backends.path import PathCollectionTask
from nabit.lib.backends.url import UrlCollectionTask

@pytest.fixture
def test_files(tmp_path):
    """Create some test files to package"""
    file1 = tmp_path / "test1.txt"
    file2 = tmp_path / "test2.txt"
    signed_metadata = tmp_path / "signed-metadata.json"
    unsigned_metadata = tmp_path / "unsigned-metadata.json"
    file1.write_text("Test content 1")
    file2.write_text("Test content 2")
    signed_metadata.write_text('{"metadata": "signed"}')
    unsigned_metadata.write_text('{"metadata": "unsigned"}')
    return {"payload": [file1, file2], "signed_metadata": signed_metadata, "unsigned_metadata": unsigned_metadata}


@pytest.fixture
def test_bag(tmp_path, test_files):
    """Create a basic valid bag"""
    bag_path = tmp_path / "test_bag"
    package(
        output_path=bag_path,
        collect=[
            PathCollectionTask(path=str(test_files["payload"][0])),
            PathCollectionTask(path=str(test_files["payload"][1]))
        ],
        signed_metadata=test_files["signed_metadata"].read_text(),
        unsigned_metadata=test_files["unsigned_metadata"].read_text(),
        bag_info={"Source-Organization": "Test Org"}
    )
    return bag_path


@pytest.fixture
def warc_bag(tmp_path, server):
    """Create a basic valid bag with headers.warc"""
    bag_path = tmp_path / "warc_bag"
    package(
        output_path=bag_path,
        collect=[
            UrlCollectionTask(url=server.url_for("/"))
        ],
        bag_info={"Source-Organization": "Test Org"}
    )
    return bag_path


@pytest.fixture
def root_ca(monkeypatch):
    """Monkeypatch ROOT_CA to use our test CA so validate will accept it"""
    monkeypatch.setattr('nabit.lib.sign.ROOT_CA', 'tests/fixtures/pki/root-ca.crt')


@pytest.fixture
def signed_bag(tmp_path, test_files, root_ca):
    """Create a basic valid signed bag"""
    bag_path = tmp_path / "signed_bag"
    # TODO: don't call out to live TSA server
    package(
        output_path=bag_path,
        collect=[
            PathCollectionTask(path=str(test_files["payload"][0])),
            PathCollectionTask(path=str(test_files["payload"][1]))
        ],
        signed_metadata=test_files["signed_metadata"].read_text(),
        unsigned_metadata=test_files["unsigned_metadata"].read_text(),
        bag_info={"Source-Organization": "Test Org"},
        signatures=[
            {
                "action": "sign",
                "params": {
                    "key": "tests/fixtures/pki/domain-signing.key",
                    "cert_chain": "tests/fixtures/pki/domain-chain.pem"
                }
            },
            {
                "action": "timestamp",
                "params": KNOWN_TSAS["digicert"]
            }
        ]
    )
    return bag_path


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def server(httpserver):
    httpserver.expect_request("/").respond_with_data("root content", content_type="text/html")
    httpserver.expect_request("/another.html").respond_with_data("another content", content_type="text/html")
    httpserver.expect_request("/test.txt").respond_with_data("test content", content_type="text/plain")
    httpserver.expect_request("/empty").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/redirect").respond_with_data("", status=302, headers={"Location": "/test.txt"})
    return httpserver
