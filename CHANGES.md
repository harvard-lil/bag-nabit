# Changelog

## [Unreleased]

### Added
- 

### Changed
- Require bagit 1.9.0 or later, which no longer depends on setuptools. Some bag format error messages now read "Bag is incomplete" instead of "Bag validation failed".

### Deprecated
- 

### Removed
- 

### Fixed
- `nabit validate` checks a signature's certificate as of the nearest later timestamp in the chain, so signatures stay valid after the signing certificate expires. Without a timestamp, the certificate is still checked as of the current time.
- Install on Python 3.14 and setuptools 81+, by replacing `pkg_resources` with `importlib.resources`.
- Test fixture certificates no longer expire after a year.

### Security
- 

## [0.1.2] - 2025-01-16

### Fixed
- Use requests streaming mode to avoid loading large URLs into memory
