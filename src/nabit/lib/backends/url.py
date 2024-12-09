from warcio import WARCWriter
from warcio.archiveiterator import ArchiveIterator
from warcio.capture_http import capture_http
from urllib.parse import urlparse
import mimetypes
from pathlib import Path
import requests
import os
import re
from dataclasses import dataclass
from ..utils import get_unique_path, is_url
from .base import CollectionTask

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

@dataclass
class UrlCollectionTask(CollectionTask):
    """Collect URLs and request/response metadata."""
    backend = 'url'

    url: str
    output: Path | None = None

    timeout: float = 5.0

    # if content type matches this string, use the given extension
    # instead of the extension in the URL path
    content_type_overrides = {"text/html": ".html"}

    def __post_init__(self):
        """Validate the URL."""
        if not is_url(self.url):
            raise ValueError(f"Invalid URL: {self.url}")

    def _collect(self, files_dir: Path) -> None:
        """
        Capture URL to a WARC file using our custom FileWriter.
        Appends to the WARC file if it already exists.
        """
        warc_path = files_dir.parent / 'headers.warc'
        with open(warc_path, 'ab') as fh:
            warc_writer = FileWriter(fh, warc_path, gzip=False, content_type_overrides=self.content_type_overrides)
            with capture_http(warc_writer):
                warc_writer.custom_out_path = self.output
                requests.get(self.url, timeout=self.timeout)
        return {'path': str(warc_writer.result_path)}
    
    def request_dict(self) -> dict:
        """Return a dictionary representation of the request."""
        return {
            'url': self.url,
            'output': str(self.output) if self.output else None,
            'timeout': self.timeout,
        }


class FileWriter(WARCWriter):
    """
    A WARC writer that stores response bodies uncompressed in the files/ directory.
    """
    revisit_status_codes = set(['200', '203'])
    custom_out_path = None  # override output path
    result_path = None

    def __init__(self, filebuf, warc_path: Path, content_type_overrides: dict[str, str] = {}, *args, **kwargs):
        super(WARCWriter, self).__init__(*args, **kwargs)
        self.out = filebuf
        self.warc_path = Path(warc_path)
        self.files_path = self.warc_path.parent / 'files'
        self.files_path.mkdir(exist_ok=True)
        self.content_type_overrides = content_type_overrides

    def _write_warc_record(self, out, record):
        if record.rec_type == 'response' and record.http_headers and record.http_headers.get_statuscode() in self.revisit_status_codes:
            # Convert successful responses to revisit records
            record.rec_type = 'revisit'
            headers = record.rec_headers
            headers.replace_header('WARC-Type', 'revisit')
            
            ## get a filename for the response body
            if self.custom_out_path is not None:
                out_name = self.custom_out_path
            else:
                out_name = url_to_filename(
                    headers.get_header('WARC-Target-URI'),
                    record.http_headers.get_header('Content-Type'),
                    self.content_type_overrides
                )
            out_path = get_unique_path(self.files_path / out_name)
            relative_path = out_path.relative_to(self.warc_path.parent)
            self.result_path = out_path.relative_to(self.files_path)

            # add our custom WARC-Profile header
            headers.add_header('WARC-Profile', f'file-content; filename="{relative_path}"')

            ## write the response body to the file
            # this is copied from the underlying WARCWriter._write_warc_record method,
            # except that we uncompress the response body before writing it to the file.
            output_size = 0
            try:
                with open(out_path, 'wb') as fh:
                    for buf in self._iter_stream(record.content_stream()):
                        fh.write(buf)
                        output_size += len(buf)
            finally:
                if hasattr(record, '_orig_stream'):  # pragma: no cover
                    # kept for compatibility with warcio, but not sure when used
                    record.raw_stream.close()
                    record.raw_stream = record._orig_stream

            # if the response body turns out to be empty, undo the conversion to a revisit record
            if output_size == 0:
                out_path.unlink()
                headers.replace_header('WARC-Type', 'response')
                headers.remove_header('WARC-Profile')

        return super()._write_warc_record(out, record)

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
                if profile.startswith('file-content'):  # pragma: no branch
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

def url_to_filename(url: str, content_type: str | None = None, content_type_overrides: dict[str, str] = {}) -> str:
    """
    Convert a URL to a filename based on the URL path and content type.

    >>> url_to_filename('https://example.com/path/to/file.pdf')
    'file.pdf'
    >>> url_to_filename('https://sub.example.com/', 'text/html')
    'sub_example_com.html'
    >>> url_to_filename('https://example.com/foo', 'fake/content-type')
    'foo.unknown'
    >>> url_to_filename('https://example.com/page', 'text/html')
    'page.html'
    >>> url_to_filename('https://example.com/image', 'image/jpeg')
    'image.jpg'
    >>> url_to_filename('https://example.com/path/', 'text/plain')
    'path.txt'
    >>> url_to_filename('https://example.com/page.php', 'text/html')
    'page.php'
    >>> url_to_filename('https://example.com/page.php', 'text/html; charset=utf-8', {'text/html': '.html'})
    'page.html'
    >>> url_to_filename('https://example.com/page.html?foo=bar')
    'page.html'
    >>> url_to_filename('https://127.0.0.1:8080/', 'text/html')
    '127_0_0_1.html'
    >>> url_to_filename('https://example.com/..', 'text/html')
    'dot_.html'
    >>> url_to_filename('https://example.com/.html', 'text/html')
    'dot_html.html'
    """
    parsed_url = urlparse(url)
    if parsed_url.path.strip('/'):
        filename = parsed_url.path.rstrip('/').split('/')[-1]
    else:
        filename = parsed_url.hostname.replace('.', '_')
    filename = Path(filename)

    # set stem
    stem = filename.stem
    stem = re.sub(r'^\.+', 'dot_', stem)

    # set extension
    extension = None
    content_type = (content_type or '').split(';')[0]  # strip content types like "text/html; charset=utf-8"
    if content_type in content_type_overrides:
        extension = content_type_overrides[content_type]
    elif filename.suffix:
        extension = filename.suffix
    elif content_type:
        extension = mimetypes.guess_extension(content_type, strict=False)
    if not extension:
        extension = '.unknown'
    
    return f'{stem}{extension}'