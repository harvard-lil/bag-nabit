import hashlib
import shutil
from inline_snapshot import snapshot
from nabit.lib.archive import make_manifest
from .utils import validate_failing, validate_passing, append_text

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
    assert validate_failing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Bag validation failed: data/files/test1.txt sha256 validation failed: expected="166cb94a04ebaef4ae79c2a0674d8cea1b7fc354eb2ea436b28c3531de10449c" found="0ef0c788f2de3fe11f1086f4a7c557ac8c812d01786b76d22477832d2e6326f9"
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
ERROR: No files in data/files
SUCCESS: headers.warc found
ERROR: headers.warc specifies files that do not exist in data/files. Example: files/data.html
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
ERROR: No files in data/files
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Expected data directory <bag_path>/data does not exist
WARNING: No signatures found
WARNING: No timestamps found\
""")
    
def test_signed_metadata_modified(test_bag):
    append_text(test_bag / "data/signed-metadata.json", " ")
    assert validate_failing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Bag validation failed: data/signed-metadata.json sha256 validation failed: expected="54de45672f15c85afecc685b1099a34fb2371c7e1c667eeb71f576ea58031d53" found="82642a7d2637303352c00bb68515059cc9f8dcd7f8939638e5bf317afd42d567"
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
    assert validate_failing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Bag validation failed: bagit.txt sha256 validation failed: expected="e91f941be5973ff71f1dccbdd1a32d598881893a7f21be516aca743da38b1689" found="aa0a5b23d0e6a29e67136c07bc81636c4c6dbf24dc4d7d100120f8271eb02b53"
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
    assert validate_failing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Bag validation failed: bag-info.txt sha256 validation failed: expected="927411016fb7c206d5a4cf304c1d6a1fbfea06a0b0d9ff38ca976052ecde5a49" found="b56b885f8a084f9aeb9d104385946b0799c0fc7cefbb307f36b170ae8b2968b5"
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
    assert validate_failing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Bag validation failed: manifest-sha256.txt sha256 validation failed: expected="1eb4ef1aeaa8f1db13cd056ce3b74060ba0cf25d60e511c3844791c41408d87f" found="deedd551235b23948fd5abfe29c7ad4ce09c721c0bb65328da210ec93c1ee757"
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
    assert validate_failing(test_bag) == snapshot("""\
WARNING: No headers.warc found; archive lacks request and response metadata
ERROR: bag format is invalid: Bag validation failed: manifest-sha256.txt sha256 validation failed: expected="1eb4ef1aeaa8f1db13cd056ce3b74060ba0cf25d60e511c3844791c41408d87f" found="fd34a1bf6f432cd8105c4ef2f8557130b2da249799d87a163cdc8f5080c8200b"
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
