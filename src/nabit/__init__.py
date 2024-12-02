from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("nabit")
except PackageNotFoundError: # pragma: no cover
    # package is not installed
    __version__ = "0.0.0.dev0"
