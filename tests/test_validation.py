import hashlib
import shutil
from inline_snapshot import snapshot
from nabit.lib.archive import make_manifest
from .utils import validate_failing, validate_passing, append_text, replace_hashes

## test valid packages

def test_valid_package(test_bag):
    assert validate_passing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
WARNING: No signatures found
WARNING: No timestamps found\
""")

def test_valid_warc_package(warc_bag):
    assert validate_passing(warc_bag) == snapshot("""\
SUCCESS: headers.warc found
SUCCESS: bag format is valid
WARNING: No signatures found
WARNING: No timestamps found\
""")

def test_valid_signed_package(signed_bag):
    assert validate_passing(signed_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
SUCCESS: signature <bag_path>/signatures/tagmanifest-sha256.txt.p7s verified
SUCCESS: Timestamp <bag_path>/signatures/tagmanifest-sha256.txt.p7s.tsr verified\
""")

## for errors we test from inside out, starting with changes inside data/files/

def test_modified_payload(test_bag):
    (test_bag / "data/files/test1.txt").write_text("modified payload")
    assert replace_hashes(validate_failing(test_bag)) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Bag validation failed: data/files/test1.txt sha256 validation failed: expected="<hash>" found="<hash>"
WARNING: No signatures found
WARNING: No timestamps found\
""")

def test_extra_payload(test_bag):
    (test_bag / "data/files/extra.txt").write_text("extra payload")
    assert validate_failing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Bag validation failed: data/files/extra.txt exists on filesystem but is not in the manifest
WARNING: No signatures found
WARNING: No timestamps found\
""")

def test_missing_warc_file(warc_bag):
    (warc_bag / "data/files/data.html").unlink()
    assert validate_failing(warc_bag) == snapshot("""\
SUCCESS: headers.warc found
ERROR: headers.warc specifies files that do not exist in data/files. Example: files/data.html
WARNING: No files in data/files
ERROR: bag format is invalid: Bag validation failed: data/files/data.html exists in manifest but was not found on filesystem
WARNING: Cannot verify the validity of empty directories: <bag_path>/data/files
WARNING: No signatures found
WARNING: No timestamps found\
""")

def test_extra_warc_file(warc_bag):
    (warc_bag / "data/files/extra.html").write_text("extra payload")
    assert validate_failing(warc_bag) == snapshot("""\
SUCCESS: headers.warc found
WARNING: Some files in data/files are not specified in headers.warc. Example: <bag_path>/data/files/extra.html
ERROR: bag format is invalid: Bag validation failed: data/files/extra.html exists on filesystem but is not in the manifest
WARNING: No signatures found
WARNING: No timestamps found\
""")

def test_empty_folder(test_bag):
    # make sure we warn that we can't verify the validity of empty directories,
    # since they aren't included in the manifest
    (test_bag / "data/empty").mkdir()
    assert validate_passing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
WARNING: 1 unexpected files in data/, starting with empty.
SUCCESS: bag format is valid
WARNING: Cannot verify the validity of empty directories: <bag_path>/data/empty
WARNING: No signatures found
WARNING: No timestamps found\
""")

## next look at changes inside data/

def test_extra_data(test_bag):
    (test_bag / "data/extra.txt").write_text("extra data")
    assert validate_failing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
WARNING: 1 unexpected files in data/, starting with extra.txt.
ERROR: bag format is invalid: Bag validation failed: data/extra.txt exists on filesystem but is not in the manifest
WARNING: No signatures found
WARNING: No timestamps found\
""")

def test_missing_data(test_bag):
    shutil.rmtree(test_bag / "data")
    assert validate_failing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
WARNING: No files in data/files
ERROR: bag format is invalid: Expected data directory <bag_path>/data does not exist
WARNING: No signatures found
WARNING: No timestamps found\
""")
    
def test_signed_metadata_modified(test_bag):
    append_text(test_bag / "data/signed-metadata.json", " ")
    assert replace_hashes(validate_failing(test_bag)) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Bag validation failed: data/signed-metadata.json sha256 validation failed: expected="<hash>" found="<hash>"
WARNING: No signatures found
WARNING: No timestamps found\
""")
    
def test_unsigned_metadata_modified(signed_bag):
    # modifying unsigned metadata is allowed, even in a signed bag
    append_text(signed_bag / "unsigned-metadata.json", " ")
    assert validate_passing(signed_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
SUCCESS: signature <bag_path>/signatures/tagmanifest-sha256.txt.p7s verified
SUCCESS: Timestamp <bag_path>/signatures/tagmanifest-sha256.txt.p7s.tsr verified\
""")

## next look at changes to standard BagIt tag files

# bagit.txt

def test_missing_bagit(test_bag):
    (test_bag / "bagit.txt").unlink()
    assert validate_failing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Expected bagit.txt does not exist: <bag_path>/bagit.txt
WARNING: No signatures found
WARNING: No timestamps found\
""")

def test_modified_bagit(test_bag):
    append_text(test_bag / "bagit.txt", " ")
    assert replace_hashes(validate_failing(test_bag)) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Bag validation failed: bagit.txt sha256 validation failed: expected="<hash>" found="<hash>"
WARNING: No signatures found
WARNING: No timestamps found\
""")

# bag-info.txt

def test_missing_bag_info(test_bag):
    (test_bag / "bag-info.txt").unlink()
    assert validate_failing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Bag validation failed: bag-info.txt exists in manifest but was not found on filesystem
WARNING: No signatures found
WARNING: No timestamps found\
""")

def test_modified_bag_info(test_bag):
    append_text(test_bag / "bag-info.txt", " ")
    assert replace_hashes(validate_failing(test_bag)) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Bag validation failed: bag-info.txt sha256 validation failed: expected="<hash>" found="<hash>"
WARNING: No signatures found
WARNING: No timestamps found\
""")

# manifest-sha256.txt

def test_missing_manifest(test_bag):
    (test_bag / "manifest-sha256.txt").unlink()
    assert validate_failing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: No manifest files found
WARNING: No signatures found
WARNING: No timestamps found\
""")

def test_simple_manifest_modification(test_bag):
    append_text(test_bag / "manifest-sha256.txt", " ")
    assert replace_hashes(validate_failing(test_bag)) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Bag validation failed: manifest-sha256.txt sha256 validation failed: expected="<hash>" found="<hash>"
WARNING: No signatures found
WARNING: No timestamps found\
""")

def test_modified_manifest_new_file(test_bag):
    # validation fails if we add a new file to the manifest,
    # because tagmanifest won't match
    new_file = test_bag / "data/files/extra.txt"
    new_file.write_bytes(b"extra payload")
    hash = hashlib.sha256(b"extra payload").hexdigest()
    manifest = test_bag / "manifest-sha256.txt"
    manifest.write_text(manifest.read_text() + f"{hash}  data/files/extra.txt\n")
    assert replace_hashes(validate_failing(test_bag)) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Bag validation failed: manifest-sha256.txt sha256 validation failed: expected="<hash>" found="<hash>"
WARNING: No signatures found
WARNING: No timestamps found\
""")

    # once we fix the tag manifest, validation should pass (this ensures our attempted attack is correct)
    tagmanifest = test_bag / "tagmanifest-sha256.txt"
    new_tagmanifest = make_manifest([test_bag / "bagit.txt", test_bag / "bag-info.txt", test_bag / "manifest-sha256.txt"], test_bag)
    tagmanifest.write_text(new_tagmanifest)
    assert validate_passing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
WARNING: No signatures found
WARNING: No timestamps found\
""")

# tagmanifest-sha256.txt

def test_missing_tagmanifest(test_bag):
    (test_bag / "tagmanifest-sha256.txt").unlink()
    assert validate_failing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: No tagmanifest-sha256.txt found
WARNING: No signatures found
WARNING: No timestamps found\
""")

def test_modified_tagmanifest(test_bag, signed_bag):
    # unsigned tagmanifest can be modified
    append_text(test_bag / "tagmanifest-sha256.txt", " ")
    assert validate_passing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
WARNING: No signatures found
WARNING: No timestamps found\
""")

    # signed tagmanifest cannot be modified
    append_text(signed_bag / "tagmanifest-sha256.txt", " ")
    assert validate_failing(signed_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
ERROR: Signature verification failed: Command '['openssl', 'cms', '-verify', '-binary', '-content', PosixPath('<bag_path>/tagmanifest-sha256.txt'), '-in', PosixPath('<bag_path>/signatures/tagmanifest-sha256.txt.p7s'), '-inform', 'PEM', '-purpose', 'any', '-CAfile', 'tests/fixtures/pki/root-ca.crt']' returned non-zero exit status 4.
WARNING: Unknown signature file: <bag_path>/signatures/tagmanifest-sha256.txt.p7s.tsr
WARNING: Unknown signature file: <bag_path>/signatures/tagmanifest-sha256.txt.p7s.tsr.crt
WARNING: No signatures found
WARNING: No timestamps found\
""")

## finally, look at changes to signatures/ directory

def test_invalid_signature(signed_bag):
    (signed_bag / "signatures/tagmanifest-sha256.txt.p7s").write_bytes(b"invalid signature")
    assert validate_failing(signed_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
ERROR: Signature verification failed: Command '['openssl', 'cms', '-verify', '-binary', '-content', PosixPath('<bag_path>/tagmanifest-sha256.txt'), '-in', PosixPath('<bag_path>/signatures/tagmanifest-sha256.txt.p7s'), '-inform', 'PEM', '-purpose', 'any', '-CAfile', 'tests/fixtures/pki/root-ca.crt']' returned non-zero exit status 2.
WARNING: Unknown signature file: <bag_path>/signatures/tagmanifest-sha256.txt.p7s.tsr
WARNING: Unknown signature file: <bag_path>/signatures/tagmanifest-sha256.txt.p7s.tsr.crt
WARNING: No signatures found
WARNING: No timestamps found\
""")

def test_invalid_timestamp(signed_bag):
    (signed_bag / "signatures/tagmanifest-sha256.txt.p7s.tsr").write_bytes(b"invalid timestamp")
    assert validate_failing(signed_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
SUCCESS: signature <bag_path>/signatures/tagmanifest-sha256.txt.p7s verified
ERROR: Signature verification failed: Command '['openssl', 'ts', '-verify', '-data', PosixPath('<bag_path>/signatures/tagmanifest-sha256.txt.p7s'), '-in', PosixPath('<bag_path>/signatures/tagmanifest-sha256.txt.p7s.tsr'), '-CAfile', PosixPath('<bag_path>/signatures/tagmanifest-sha256.txt.p7s.tsr.crt')]' returned non-zero exit status 1.
WARNING: Unknown signature file: <bag_path>/signatures/tagmanifest-sha256.txt.p7s.tsr.crt
WARNING: No timestamps found\
""")

def test_missing_cert(signed_bag):
    (signed_bag / "signatures/tagmanifest-sha256.txt.p7s.tsr.crt").unlink()
    assert validate_failing(signed_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
SUCCESS: bag format is valid
SUCCESS: signature <bag_path>/signatures/tagmanifest-sha256.txt.p7s verified
ERROR: timestamp response file <bag_path>/signatures/tagmanifest-sha256.txt.p7s.tsr does not have corresponding .crt file
WARNING: No timestamps found\
""")
