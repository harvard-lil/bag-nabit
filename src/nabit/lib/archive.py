from pathlib import Path
import shutil
from datetime import date
import bagit
import os
from .utils import get_unique_path, noop
from .capture import validate_warc_headers, capture
from .sign import validate_signatures, KNOWN_TSAS, add_signatures
from .. import __version__
import hashlib

# files to ignore when copying directories
IGNORE_PATTERNS = ['.DS_Store']

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

def copy_paths(source_paths: list[Path | str], dest_dir: Path, use_hard_links: bool = False) -> None:
    """Copy paths to a destination directory, optionally using hard links."""
    for path in source_paths:
        path = Path(path)
        dest_path = get_unique_path(dest_dir / path.name)
        # can only use hard links if source and destination are on the same device
        use_hard_links = use_hard_links and os.stat(path).st_dev == os.stat(dest_dir).st_dev
        if path.is_file():
            if use_hard_links:
                os.link(path, dest_path)
            else:
                shutil.copy2(path, dest_path)
        else:
            copy_function = os.link if use_hard_links else shutil.copy2
            # link directory contents recursively
            shutil.copytree(
                path, 
                dest_path, 
                dirs_exist_ok=True, 
                copy_function=copy_function, 
                ignore=shutil.ignore_patterns(*IGNORE_PATTERNS)
            )

def package(
    output_path: Path | str,
    amend: bool = False,
    urls: list[str] | None = None,
    paths: list[Path | str] | None = None,
    bag_info: dict | None = None,
    signatures: list[dict] | None = None,
    signed_metadata: Path | str | None = None,
    unsigned_metadata: Path | str | None = None,
    use_hard_links: bool = False,
) -> None:
    """
    Create a BagIt package.
    Capture all URLs into data/files/.
    Copy all paths, using hard links, into data/files/.
    Include bag_info in bag-info.txt.
    If signatures are provided, add them to tagmanifest-sha256.txt.
    Copy signed_metadata to data/signed-metadata.json.
    Copy unsigned_metadata to unsigned-metadata.json.
    """
    bag_info = bag_info or {}
    
    # add data files
    output_path = Path(output_path)
    data_path = output_path / 'data'
    files_path = data_path / 'files'
    files_path.mkdir(exist_ok=True, parents=True)

    if urls:
        capture(urls, data_path / 'headers.warc')
    if paths:
        copy_paths(paths, files_path, use_hard_links)

    # Add metadata files
    if signed_metadata is not None:
        os.link(signed_metadata, data_path / "signed-metadata.json")
    if unsigned_metadata is not None:
        os.link(unsigned_metadata, output_path / "unsigned-metadata.json")
    
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