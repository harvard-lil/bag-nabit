from pathlib import Path
from datetime import date
import bagit
import os
import hashlib
import json
import uuid
from .utils import noop
from .backends.url import validate_warc_headers
from .sign import validate_signatures, KNOWN_TSAS, add_signatures
from .. import __version__
from .backends.base import CollectionTask, CollectionError
from typing import Literal


def validate_bag_format(bag_path: Path, error, warn, success) -> None:
    """Verify bag format."""
    try:
        bag = bagit.Bag(str(bag_path))
        bag.validate()
        # BagIt considers tagmanifest-sha256.txt optional, but we require it
        if not (bag_path / "tagmanifest-sha256.txt").exists():
            raise bagit.BagValidationError("No tagmanifest-sha256.txt found")
    except bagit.BagError as e:
        error(f"bag format is invalid: {e}")
    else:
        success("bag format is valid")

def validate_data_files(bag_path: Path, error = None, warn = noop, success = noop) -> None:
    """Validate only expected files are present in data/."""

    # make sure there are files in files_path
    files_path = bag_path / "data/files"
    if not files_path.exists() or not any(files_path.iterdir()):
        warn("No files in data/files")

    # make sure only expected files are present
    expected_files = set(['files', 'headers.warc', 'signed-metadata.json'])
    actual_files = set(f.name for f in bag_path.glob('data/*'))
    unexpected_files = actual_files - expected_files
    if unexpected_files:
        warn(f"{len(unexpected_files)} unexpected files in data/, starting with {sorted(unexpected_files)[0]}.")

def validate_package(bag_path: Path, error = None, warn = noop, success = noop) -> None:
    """
    Validate a BagIt package.
    error, warn, and success are optional callbacks that will be called with progress messages.
    By default, errors will raise an exception.
    """
    if error is None:
        def error(message: str, metadata: dict | None = None) -> None:
            raise ValueError(message)
        
    data_path = bag_path / "data"
    headers_path = data_path / "headers.warc"
    tagmanifest_path = bag_path / "tagmanifest-sha256.txt"

    # validate from inside to outside
    validate_warc_headers(headers_path, error, warn, success)
    validate_data_files(bag_path, error, warn, success)
    validate_bag_format(bag_path, error, warn, success)
    validate_signatures(tagmanifest_path, error, warn, success)

def package(
    output_path: Path | str,
    amend: bool = False,
    collect: list[CollectionTask] | None = None,
    bag_info: dict | None = None,
    signatures: list[dict] | None = None,
    signed_metadata: dict | None = None,
    unsigned_metadata: dict | None = None,
    collect_errors: Literal['fail', 'ignore'] = 'fail',
) -> None:
    """
    Create a BagIt package.
    Capture all URLs into data/files/.
    Copy all paths, using hard links, into data/files/.
    Include bag_info in bag-info.txt.
    If signatures are provided, add them to tagmanifest-sha256.txt.
    Write signed_metadata to data/signed-metadata.json.
    Write unsigned_metadata to unsigned-metadata.json.
    """
    bag_info = bag_info or {}
    
    # add data files
    output_path = Path(output_path)
    data_path = output_path / 'data'
    signed_metadata_path = data_path / "signed-metadata.json"

    # set or extend signed metadata
    if signed_metadata is None:
        if signed_metadata_path.exists():
            signed_metadata = json.loads(signed_metadata_path.read_text())
        else:
            signed_metadata = {}
    
    if not amend and not signed_metadata.get('id'):
        signed_metadata['id'] = str(uuid.uuid4())

    # run collection tasks and record results
    if collect:
        files_path = data_path / 'files'
        files_path.mkdir(exist_ok=True, parents=True)
        results = []
        for task in collect:
            result = task.collect(files_path)
            if collect_errors == 'fail' and not result['response']['success']:
                raise CollectionError(f"Collection task failed: {result}")
            results.append(result)
        signed_metadata.setdefault('collection_tasks', []).extend(results)

    # Add metadata files
    if signed_metadata:
        data_path.mkdir(exist_ok=True, parents=True)
        (data_path / "signed-metadata.json").write_text(json.dumps(signed_metadata, indent=2))
    if unsigned_metadata:
        (output_path / "unsigned-metadata.json").write_text(json.dumps(unsigned_metadata, indent=2))
    
    ## add bag files
    bag_changed = not amend

    # write bagit.txt
    bagit_text = "BagIt-Version: 0.97\nTag-File-Character-Encoding: UTF-8\n"
    bagit_path = output_path / "bagit.txt"
    existing_bagit = bagit_path.read_text() if bagit_path.exists() else ""
    if existing_bagit != bagit_text:
        bagit_path.write_text(bagit_text)
        bag_changed = True

    # write manifest-sha256.txt
    manifest_path = output_path / "manifest-sha256.txt"
    existing_manifest = manifest_path.read_text() if manifest_path.exists() else ""
    new_manifest = make_manifest(data_path.glob('**/*'), output_path)
    if new_manifest != existing_manifest:
        manifest_path.write_text(new_manifest)
        bag_changed = True

    # write bag-info.txt
    # we only want to write a new Bagging-Date if something has changed,
    # so we don't needlessly invalidate the signature.
    if bag_changed or bag_info or not amend:
        bag_info_path = output_path / "bag-info.txt"
        existing_bag_info = bagit._load_tag_file(str(bag_info_path)) if amend and bag_info_path.exists() else {}
        bagit._make_tag_file(str(bag_info_path), {
            **existing_bag_info,
            "Bagging-Date": date.today().isoformat(),
            "Bag-Software-Agent": f"nabit v.{__version__}",
            **bag_info,
        })
        bag_changed = True

    # write tagmanifest-sha256.txt
    tagmanifest_path = output_path / "tagmanifest-sha256.txt"
    if bag_changed or not amend:
        new_tagmanifest = make_manifest([bagit_path, bag_info_path, manifest_path], output_path)
        tagmanifest_path.write_text(new_tagmanifest)

    ## add signatures
    sign_path = tagmanifest_path
    if amend:
        # when amending we may be able to keep signatures, if no content files have changed.
        # use custom handlers for validate_signatures to remove files that no longer validate,
        # and then tack on any new signatures at the end.
        def error(message: str, metadata: dict | None = None) -> None:
            print(f"Signature file {metadata['file']} no longer validates. Removing.")
            os.remove(metadata['file'])
        def warn(message: str, metadata: dict | None = None) -> None:
            if metadata and 'file' in metadata:
                print(f"Signature file {metadata['file']} unrecognized. Removing.")
                os.remove(metadata['file'])
        def success(message: str, metadata: dict | None = None) -> None:
            nonlocal sign_path
            print(f"Signature file {metadata['file']} still validates. Retaining.")
            sign_path = metadata['file']
        validate_signatures(sign_path, error=error, warn=warn, success=success)

    if signatures:
        add_signatures(sign_path, output_path / "signatures", signatures)

def make_manifest(files, base_path: Path, algorithm: str = "sha256", block_size: int = 512 * 1024) -> str:
    """
    Generate manifest contents for a directory.
    Returns the manifest contents as a sorted string.
    """
    entries = []
    
    for filepath in files:
        if not filepath.is_file():
            continue
        
        # Calculate hash
        hasher = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            while chunk := f.read(block_size):  # Using the walrus operator (:=)
                hasher.update(chunk)
                
        manifest_path = filepath.relative_to(base_path).as_posix()
        entries.append(f"{hasher.hexdigest()}  {manifest_path}")
    
    entries.sort()
    return "\n".join(entries) + "\n"