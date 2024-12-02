from nabit.bin.cli import main
from nabit.lib.sign import KNOWN_TSAS
from inline_snapshot import snapshot
import json
import re

from tests.utils import validate_passing
from .utils import validate_passing, validate_failing

### helpers

def run(runner, args, exit_code=0, output="Package created"):
    result = runner.invoke(main, args, catch_exceptions=False)
    assert result.exit_code == exit_code
    if output:
        assert output in result.output
    return result

### tests

## validate command

def test_validate_valid_bag(runner, tmp_path, test_files):
    run(runner, [
        'archive',
        str(tmp_path / 'bag'),
        '-p', str(test_files["payload"][0]),
    ])
    run(runner, [
        'validate',
        str(tmp_path / 'bag'),
    ], output='Package is valid')

def test_validate_invalid_bag(runner, tmp_path, test_files):
    run(runner, [
        'archive',
        str(tmp_path / 'bag'),
        '-p', str(test_files["payload"][0]),
    ])

    (tmp_path / 'bag' / 'data' / 'files' / 'extra.txt').write_text('extra')
    
    run(runner, [
        'validate',
        str(tmp_path / 'bag'),
    ], exit_code=1, output='Errors found in package')

## archive command - happy paths

def test_file_payload(runner, tmp_path, test_files):
    run(runner, [
        'archive',
        str(tmp_path / 'bag'),
        '-p', str(test_files["payload"][0]),
        '-p', str(test_files["payload"][1]),
    ])
    assert validate_passing(tmp_path / 'bag') == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
WARNING: No signatures found
WARNING: No timestamps found\
""")

def test_url_payload(runner, tmp_path, server):
    bag_path = tmp_path / 'bag'
    run(runner, [
        'archive',
        str(bag_path),
        '-u', server.url_for("/"),
        '-u', server.url_for("/another.html"),
        '-u', server.url_for("/test.txt"),
    ])
    assert validate_passing(bag_path) == snapshot("""\
SUCCESS: headers.warc found
SUCCESS: bag format is valid
WARNING: No signatures found
WARNING: No timestamps found\
""")
    assert (bag_path / 'data/files/data.html').read_text() == 'root content' 
    assert (bag_path / 'data/files/another.html').read_text() == 'another content'
    assert (bag_path / 'data/files/test.txt').read_text() == 'test content'

def test_metadata(runner, tmp_path, test_files):
    bag_path = tmp_path / 'bag'
    run(runner, [
        'archive',
        str(bag_path),
        '-p', str(test_files["payload"][0]),
        '-i', 'Source-Organization:Test Org',
        '-i', 'Contact-Email:test1@example.com',
        '-i', 'Contact-Email:test2@example.com',
        '--unsigned-metadata', str(test_files["unsigned_metadata"]),
        '--signed-metadata', str(test_files["signed_metadata"]),
    ])
    assert validate_passing(bag_path) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
WARNING: No signatures found
WARNING: No timestamps found\
""")

    # check metadata files
    assert json.loads((bag_path / 'unsigned-metadata.json').read_text()) == {'metadata': 'unsigned'}
    assert json.loads((bag_path / 'data/signed-metadata.json').read_text()) == {'metadata': 'signed'}

    # check bag-info.txt metadata
    bag_info = (bag_path / 'bag-info.txt').read_text()
    assert 'Source-Organization: Test Org' in bag_info
    assert 'Contact-Email: test1@example.com' in bag_info
    assert 'Contact-Email: test2@example.com' in bag_info

def test_signatures(runner, tmp_path, test_files, root_ca):
    bag_path = tmp_path / 'bag'
    run(runner, [
        'archive',
        str(bag_path),
        '-p', str(test_files["payload"][0]),
        '-s', 'tests/fixtures/pki/domain-chain.pem:tests/fixtures/pki/domain-signing.key',
        '-s', 'tests/fixtures/pki/email-chain.pem:tests/fixtures/pki/email-signing.key',
        '-t', 'digicert'
    ])
    assert validate_passing(bag_path) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
SUCCESS: signature <bag_path>/signatures/tagmanifest-sha256.txt.p7s verified
SUCCESS: signature <bag_path>/signatures/tagmanifest-sha256.txt.p7s.p7s verified
SUCCESS: Timestamp <bag_path>/signatures/tagmanifest-sha256.txt.p7s.p7s.tsr verified\
""")

def test_just_timestamp_no_signatures(runner, tmp_path, test_files, root_ca):
    bag_path = tmp_path / 'bag'
    run(runner, [
        'archive',
        str(bag_path),
        '-p', str(test_files["payload"][0]),
        '-t', 'digicert',
        '-t', f"{KNOWN_TSAS['sectigo']['cert_chain']}:{KNOWN_TSAS['sectigo']['url']}",
    ])
    assert validate_passing(bag_path) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
SUCCESS: Timestamp <bag_path>/signatures/tagmanifest-sha256.txt.tsr verified
SUCCESS: Timestamp <bag_path>/signatures/tagmanifest-sha256.txt.tsr.tsr verified
WARNING: No signatures found\
""")

def test_create_then_sign(runner, tmp_path, test_files, root_ca):
    bag_path = tmp_path / 'bag'
    run(runner, [
        'archive',
        str(bag_path),
        '-p', str(test_files["payload"][0]),
        '-t', 'digicert',
    ])
    assert validate_passing(bag_path) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
SUCCESS: Timestamp <bag_path>/signatures/tagmanifest-sha256.txt.tsr verified
WARNING: No signatures found\
""")

    # should add signatures without invalidating existing timestamp
    run(runner, [
        'archive',
        '--amend',
        str(bag_path),
        '-s', 'tests/fixtures/pki/domain-chain.pem:tests/fixtures/pki/domain-signing.key',
        '-t', 'digicert'
    ], output='Package amended')
    assert validate_passing(bag_path) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
SUCCESS: Timestamp <bag_path>/signatures/tagmanifest-sha256.txt.tsr verified
SUCCESS: signature <bag_path>/signatures/tagmanifest-sha256.txt.tsr.p7s verified
SUCCESS: Timestamp <bag_path>/signatures/tagmanifest-sha256.txt.tsr.p7s.tsr verified\
""")
    
    # changing anything else should invalidate the signatures
    (bag_path / 'data' / 'files' / 'extra.txt').write_text('extra')
    result = run(runner, [
        'archive',
        '--amend',
        str(bag_path),
    ], output='Package amended')
    assert validate_passing(bag_path) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
WARNING: No signatures found
WARNING: No timestamps found\
""")
    assert list(bag_path.glob('signatures/*')) == []

def test_recreate_tag_files(runner, tmp_path, test_files, root_ca):
    bag_path = tmp_path / 'bag'
    run(runner, [
        'archive',
        str(bag_path),
        '-p', str(test_files["payload"][0]),
    ])
    assert validate_passing(bag_path) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
WARNING: No signatures found
WARNING: No timestamps found\
""")

    # after we add a file, the bag should be invalid
    (bag_path / 'data/files/extra.txt').write_text('extra file')
    assert validate_failing(bag_path) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Bag validation failed: data/files/extra.txt exists on filesystem but is not in the manifest
WARNING: No signatures found
WARNING: No timestamps found\
""")

    # a bare amend should fix it
    run(runner, [
        'archive',
        '--amend',
        str(bag_path),
    ], output='Package amended')
    assert validate_passing(bag_path) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
WARNING: No signatures found
WARNING: No timestamps found\
""")

def test_hard_links(runner, tmp_path, test_files):
    ## in regular operation, files are not hard linked
    source_dir = tmp_path / 'source'
    source_dir.mkdir()
    (source_dir / 'payload.txt').write_text('payload')
    bag_path = tmp_path / 'bag'
    run(runner, [
        'archive',
        str(bag_path),
        '-p', str(source_dir),
        '-p', str(test_files["payload"][0]),
    ])

    # check that files are not hard linked by default
    source_file = source_dir / 'payload.txt'
    dest_file = bag_path / 'data/files/source/payload.txt'
    assert dest_file.stat().st_ino != source_file.stat().st_ino
    
    test_payload_file = test_files["payload"][0]
    dest_payload_file = bag_path / f'data/files/{test_payload_file.name}'
    assert dest_payload_file.stat().st_ino != test_payload_file.stat().st_ino

    ## with --hard-link, files should be hard linked
    bag_path = tmp_path / 'hard_linked'
    run(runner, [
        'archive',
        str(bag_path),
        '-p', str(source_dir),
        '-p', str(test_files["payload"][0]),
        '--hard-link'
    ])
    assert validate_passing(bag_path) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
WARNING: No signatures found
WARNING: No timestamps found\
""")

    # verify files are hard linked
    dest_file = bag_path / 'data/files/source/payload.txt'
    assert dest_file.stat().st_ino == source_file.stat().st_ino
    
    dest_payload_file = bag_path / f'data/files/{test_payload_file.name}'
    assert dest_payload_file.stat().st_ino == test_payload_file.stat().st_ino

def test_duplicate_file_names(runner, tmp_path, server):
    """Test handling of duplicate filenames by checking unique path generation"""
    bag_path = tmp_path / 'bag'

    # Create two files with the same name in different directories
    dir1 = tmp_path / "dir1"
    dir2 = tmp_path / "dir2"
    dir1.mkdir()
    dir2.mkdir()
    (dir1 / "data.html").write_text("content1")
    (dir2 / "data.html").write_text("content2")

    run(runner, [
        'archive',
        str(bag_path),
        '-p', str(dir1 / "data.html"),
        '-p', str(dir2 / "data.html"),
        '-u', server.url_for("/"),
    ])

    # Verify files exist; one will be data.html and the others will be data-a1b2c3.html
    files = sorted((p.name for p in (bag_path / "data" / "files").glob("data*.html")))
    assert re.match(r"data-[0-9a-zA-Z]{6}\.html;data-[0-9a-zA-Z]{6}\.html;data\.html", ";".join(files))

## validation errors

def test_invalid_metadata_file_extension(runner, tmp_path):
    (tmp_path / 'metadata.txt').write_text('test')
    run(runner, [
        'archive',
        str(tmp_path / 'bag'),
        '--signed-metadata', str(tmp_path / 'metadata.txt'),
    ], exit_code=2, output='Metadata file must be a .json file')

def test_invalid_metadata_file_contents(runner, tmp_path, test_files):
    (tmp_path / 'metadata.json').write_text('invalid')
    run(runner, [
        'archive',
        str(tmp_path / 'bag'),
        '--signed-metadata', str(tmp_path / 'metadata.json'),
    ], exit_code=2, output='Metadata file must be valid JSON')

def test_invalid_info_format(runner, tmp_path):
    run(runner, [
        'archive',
        str(tmp_path),
        '-i', 'InvalidFormat',  # missing colon
    ], exit_code=2, output='Metadata must be in "key:value" format')

def test_archive_to_non_empty_dir(runner, tmp_path):
    (tmp_path / 'extra.txt').write_text('test')
    run(runner, [
        'archive',
        str(tmp_path),
    ], exit_code=2, output='already exists and is not empty')

def test_amend_non_bagit(runner, tmp_path):
    (tmp_path / 'some_file.txt').write_text('test')
    run(runner, [
        'archive',
        '--amend',
        str(tmp_path),
    ], exit_code=2, output='No bagit.txt found')

def test_invalid_timestamp_format(runner, tmp_path):
    run(runner, [
        'archive',
        str(tmp_path),
        '-t', 'unknown',  # unknown TSA
    ], exit_code=2, output='Timestamp must be in "url:cert_chain" format')

def test_invalid_signature_format(runner, tmp_path):
    """Test error handling for malformed signature parameter"""
    run(runner, [
        'archive',
        str(tmp_path),
        '-s', 'invalid_format',  # missing colon
    ], exit_code=2, output='Sign must be in "cert_chain:key_file" format')

def test_nonexistent_key_file(runner, tmp_path):
    """Test error handling for nonexistent key file"""
    run(runner, [
        'archive',
        str(tmp_path),
        '-s', 'nonexistent.key:tests/fixtures/pki/domain-chain.pem',
    ], exit_code=2, output='does not exist')

def test_invalid_url(runner, tmp_path):
    """Test error handling for invalid URL format"""
    run(runner, [
        'archive',
        str(tmp_path),
        '-u', 'not_a_url',
    ], exit_code=2, output='Invalid URL')

def test_empty_package(runner, tmp_path):
    """Test creating a package with no content"""
    run(runner, [
        'archive',
        str(tmp_path),
    ], exit_code=1, output='No files in data/files')
