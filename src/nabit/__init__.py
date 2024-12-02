# capture_http has to be imported before requests,
# so do it right at the the top of the library.
from warcio.capture_http import capture_http

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("nabit")
except PackageNotFoundError: # pragma: no cover
    # package is not installed
    __version__ = "0.0.0.dev0"
