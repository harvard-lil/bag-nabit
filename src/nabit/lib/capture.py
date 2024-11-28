from warcio import WARCWriter
from warcio.archiveiterator import ArchiveIterator
from warcio.capture_http import capture_http
from urllib.parse import urlparse
import mimetypes
from pathlib import Path
import requests  # requests must be imported after capture_http
import os
from nabit.lib.utils import get_unique_path
"""
This file handles capturing of URLs and request/response metadata.
We use an unpacked WARC format to make it easier to access underlying data files.
The resulting layout is:

* headers.warc:
  Request and response metadata.
  Responses are stored as "revisit" WARC records, with a custom WARC-Profile
  header indicating the relative path to the response body file. For example:

      WARC-Profile: file-content; filename="files/file.ext"

* files/...:

  Response data files are named after the last component of the URL path, defaulting
  to "data" if the URL path is empty, and guessing a file extension from the
  Content-Type response header if none is provided.

  Unlike typical WARC files, files are stored uncompressed in the files/ directory,
  even if the original response was gzip encoded in transit.
"""

class FileWriter(WARCWriter):
    """
    A WARC writer that stores response bodies uncompressed in the files/ directory.
    """
    def __init__(self, filebuf, warc_path: Path, *args, **kwargs):
        super(WARCWriter, self).__init__(*args, **kwargs)
        self.out = filebuf
        self.warc_path = Path(warc_path)
        self.files_path = self.warc_path.parent / 'files'
        self.files_path.mkdir(exist_ok=True)

    def _write_warc_record(self, out, record):
        if record.rec_type == 'response':
            # if we see a response record, convert it to a revisit record
            record.rec_type = 'revisit'
            headers = record.rec_headers
            headers.replace_header('WARC-Type', 'revisit')
            
            ## get a filename for the response body
            uri = headers.get_header('WARC-Target-URI')
            parsed_url = urlparse(uri)
            filename = Path(parsed_url.path.split('/')[-1])
            # set stem
            stem = filename.stem.lstrip('.') or 'data'
            # set extension
            extension = filename.suffix
            if not extension:
                if content_type := record.http_headers.get_header('Content-Type'):
                    extension = mimetypes.guess_extension(content_type.split(';')[0], strict=False)
                if not extension:
                    extension = '.unknown'
            out_path = get_unique_path(self.files_path / f'{stem}{extension}')
            relative_path = out_path.relative_to(self.warc_path.parent)

            # add our custom WARC-Profile header
            headers.add_header('WARC-Profile', f'file-content; filename="{relative_path}"')

            ## write the response body to the file
            # this is copied from the underlying WARCWriter._write_warc_record method,
            # except that we uncompress the response body before writing it to the file.
            try:
                with open(out_path, 'wb') as fh:
                    for buf in self._iter_stream(record.content_stream()):
                        fh.write(buf)
            finally:
                if hasattr(record, '_orig_stream'):
                    record.raw_stream.close()
                    record.raw_stream = record._orig_stream

        return super()._write_warc_record(out, record)


def capture(urls: list[str], warc_path: Path, request_kwargs: dict = {}) -> None:
    """
    Capture a list of URLs to a WARC file using our custom FileWriter.
    Appends to the WARC file if it already exists.
    """
    use_gzip = str(warc_path).endswith('.gz')
    with open(warc_path, 'ab') as fh:
        warc_writer = FileWriter(fh, warc_path, gzip=use_gzip)
        with capture_http(warc_writer):
            for url in urls:
                requests.get(url, **request_kwargs)

def validate_warc_headers(headers_path: Path, error, warn, success) -> None:
    """
    Validate a headers.warc file created by capture().
    Make sure:
    * all files specified in headers.warc exist in files/
    * all files in files/ are specified in headers.warc
    The callbacks error, warn, and success are passed in by validate().
    """
    # verify headers.warc, if any
    data_path = headers_path.parent
    files_path = data_path / "files"
    
    # make sure there are files in files_path
    if not files_path.exists() or not any(files_path.iterdir()):
        error("No files in data/files")
    if not headers_path.exists():
        warn("No headers.warc found; archive lacks request and response metadata")
    else:
        success("headers.warc found")
        # check files specified in headers.warc
        headers_files = set()
        with open(headers_path, 'rb') as fh:
            for record in ArchiveIterator(fh):
                if record.rec_type != 'revisit':
                    continue
                profile = record.rec_headers.get_header('WARC-Profile')
                if profile.startswith('file-content'):
                    # extract file path from header 'file-content; filename="..."'
                    file_path = profile.split(';')[1].split('=')[1].strip('"')
                    # normalize path to prevent directory traversal attacks
                    safe_path = os.path.normpath('/'+file_path).lstrip('/')
                    full_path = data_path / safe_path
                    if not full_path.exists():
                        error(f"headers.warc specifies files that do not exist in data/files. Example: {file_path}")
                        break
                    headers_files.add(full_path)

        # check that files in data/files are specified in headers.warc
        for file in files_path.glob('**/*'):
            if file not in headers_files:
                warn(f"Some files in data/files are not specified in headers.warc. Example: {file}")
                break
