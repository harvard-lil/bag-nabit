from datetime import datetime, timezone
from pathlib import Path
import shutil
import pytest
from inline_snapshot import snapshot
from nabit.lib.sign import validate_signatures, timestamp_time

# Signatures copied from a published data.gov bag
# (harvard-lil/gov-data on Source Cooperative, dataset
# 46403-llnr-984-2-southeast-shumagin-island-186-nm-se-of-shumagin-is-ak4/v1).
# The tag manifest was signed on 2025-02-06 with a GlobalSign S/MIME certificate
# that expired on 2025-12-06, and timestamped by DigiCert.
FIXTURE = Path("tests/fixtures/expired-cert")

@pytest.fixture
def expired_cert_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr('nabit.lib.sign.ROOT_CA', str(FIXTURE / "globalsign-root-r6.crt"))
    bag_path = tmp_path / "bag"
    shutil.copytree(FIXTURE / "bag", bag_path)
    return bag_path / "tagmanifest-sha256.txt"

def _validate_signatures(manifest: Path) -> str:
    responses = []
    validate_signatures(
        manifest,
        error=lambda msg, metadata=None: responses.append(f"ERROR: {msg}"),
        warn=lambda msg, metadata=None: responses.append(f"WARNING: {msg}"),
        success=lambda msg, metadata=None: responses.append(f"SUCCESS: {msg}"),
    )
    return "\n".join(responses).replace(str(manifest.parent), "<bag_path>")

def test_timestamp_time(expired_cert_manifest):
    timestamp_file = expired_cert_manifest.parent / "signatures/tagmanifest-sha256.txt.p7s.tsr"
    assert timestamp_time(timestamp_file) == datetime(2025, 2, 6, 15, 54, 2, tzinfo=timezone.utc)

def test_expired_cert_verified_as_of_timestamp(expired_cert_manifest):
    assert _validate_signatures(expired_cert_manifest) == snapshot("""\
SUCCESS: signature <bag_path>/signatures/tagmanifest-sha256.txt.p7s verified as of timestamp <bag_path>/signatures/tagmanifest-sha256.txt.p7s.tsr
SUCCESS: Timestamp <bag_path>/signatures/tagmanifest-sha256.txt.p7s.tsr verified\
""")

def test_expired_cert_without_timestamp(expired_cert_manifest):
    # with no timestamp, the certificate is checked as of the current time, and has expired
    signatures = expired_cert_manifest.parent / "signatures"
    (signatures / "tagmanifest-sha256.txt.p7s.tsr").unlink()
    (signatures / "tagmanifest-sha256.txt.p7s.tsr.crt").unlink()
    output = _validate_signatures(expired_cert_manifest)
    assert "ERROR: Signature verification failed" in output
    assert "-attime" not in output
