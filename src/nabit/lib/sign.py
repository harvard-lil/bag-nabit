from pathlib import Path
import requests
import subprocess
import tempfile
import sys
import os
import pkg_resources

from .utils import noop

# for testing, set ROOT_CA=test/fixtures/pki/root-ca.crt
ROOT_CA = os.environ.get("ROOT_CA")

# Add this constant near the top of the file, after imports
CERT_DIR = Path(pkg_resources.resource_filename('nabit', 'certs'))

# Modify KNOWN_TSAS to reference local cert files
KNOWN_TSAS = {
    "digicert": {
        "url": "http://timestamp.digicert.com",
        # downloaded from https://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt.pem
        "cert_chain": str(CERT_DIR / "digicert.crt"),
    },
    "sectigo": {
        "url": "http://timestamp.sectigo.com",
        # downloaded "SHA-2 Root : USERTrust RSA Certification Authority" from
        # https://support.sectigo.com/articles/Knowledge/Sectigo-Intermediate-Certificates
        "cert_chain": str(CERT_DIR / "sectigo.crt"),
    },
}

def run_openssl(args: list[str | Path]) -> subprocess.CompletedProcess:
    """Run openssl subprocess and handle errors."""
    command = ["openssl"] + args
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        return result
    except subprocess.CalledProcessError as e:
        command_str = ' '.join(str(arg) for arg in command)
        print(f"OpenSSL error: {command_str}\n{e.stderr}", file=sys.stderr)
        raise

def timestamp(file_path: str, output_path: str, url: str, cert_chain: str) -> None:
    """
    Create a timestamp for a file.
    Timestamp response will be written to `output_path`.
    Timestamp certificate will be written to `output_path.crt`.
    """
    with tempfile.NamedTemporaryFile(suffix='.tsq') as tsq:
        # Generate timestamp request, capturing output
        result = run_openssl([
            "ts", "-query", "-data", file_path,
            "-no_nonce", "-sha256", "-cert", "-out", tsq.name
        ])
        
        # read timestamp query file
        tsq_data = tsq.read()
        
        # send request to TSA using requests
        headers = {'Content-Type': 'application/timestamp-query'}
        response = requests.post(url, headers=headers, data=tsq_data)
        response.raise_for_status()
        
        # write the timestamp response
        output_path.write_bytes(response.content)

        # copy timestamp certificate to new destination
        output_path.with_suffix('.tsr.crt').write_bytes(Path(cert_chain).read_bytes())

def verify_timestamp(timestamp_file: Path, file_to_verify: Path, pem_file: Path) -> None:
    """Verify a timestamp for a file."""
    # first verify the timestamp certificate is trusted by this system
    # note: this will fail if a bag is timestamped by a root CA later taken out of service
    run_openssl(['verify', pem_file])

    # now verify the timestamp response with the valid timestamp certificate
    return run_openssl([
        "ts",
        "-verify",
        "-data", file_to_verify,
        "-in", timestamp_file,
        "-CAfile", pem_file,
    ])

def sign(file_path: str, output_path: str, key: str, cert_chain: str) -> None:
    """Create a detached signature with full chain in PEM format."""
    return run_openssl([
        "cms",
        "-sign",
        "-binary",  # do not modify linebreaks in the original file
        "-in", file_path,
        "-out", output_path,
        "-inkey", key,
        "-signer", cert_chain,
        "-certfile", cert_chain,  # Include the full certificate chain
        "-outform", "PEM",
    ])

def verify_signature(signature_file: Path, file_to_verify: Path) -> None:
    """Verify a detached signature."""
    args =[
        "cms",
        "-verify",
        "-binary",  # do not modify linebreaks in the original file
        "-content", file_to_verify,
        "-in", signature_file,
        "-inform", "PEM",
        "-purpose", "any",  # we are using domain and email certs
    ]
    if ROOT_CA:
        args.extend(["-CAfile", ROOT_CA])
    return run_openssl(args)

def add_signatures(file_to_sign: Path, signatures_path: Path, signatures: list[dict]) -> None:
    """
    Write signatures for a tag manifest file.

    Signatures will be written to a subdirectory named "signatures".

    `signatures` is a list of signature or timestamp operations to perform.

    Example signature operation:
    {
        "action": "sign",
        "params": {
            "key": "path/to/key",
            "cert_chain": "path/to/cert_chain"
        }
    }

    Example timestamp operation:
    {
        "action": "timestamp",
        "params": {
            "url": "http://timestamp.digicert.com",
            "cert_chain": "path/to/DigiCertAssuredIDRootCA.crt.pem",
        }
    }

    The result of running this function is a series of signature files in the
    "signatures" subdirectory, for example:

        tagmanifest-sha256.txt
        signatures/tagmanifest-sha256.txt.p7s
        signatures/tagmanifest-sha256.txt.p7s.tsr
        signatures/tagmanifest-sha256.txt.p7s.tsr.crt

    This output represents a certificate chain, indicating that the tag manifest
    file is signed by tagmanifest-sha256.txt.p7s, which in turn is signed
    by tagmanifest-sha256.txt.p7s.tsr.

    Full certificate chains are included for p7s files, but must be loaded separately
    from .tsr.crt for timestamp verification.
    """
    signatures_path.mkdir(exist_ok=True, parents=True)
    output_path = signatures_path / file_to_sign.name
    for signature in signatures:
        action = signature["action"]
        params = signature["params"]
        if action == "sign":
            output_path = output_path.with_suffix(output_path.suffix + '.p7s')
            sign(file_to_sign, output_path, **params)
        elif action == "timestamp":
            output_path = output_path.with_suffix(output_path.suffix + '.tsr')
            timestamp(file_to_sign, output_path, **params)
        file_to_sign = output_path

def validate_signatures(file_to_verify: Path, error=noop, warn=noop, success=noop) -> None:
    """
    Verify signature chain for a tag manifest file.
    The callbacks error, warn, and success are passed in by validate().
    """
    # get a list of signatures we're looking for.
    # by sorting, we'll see them shortest to longest.
    # each signature should start with the full name of the previous signature in the chain.
    has_signatures = False
    has_timestamps = False
    bag_dir = file_to_verify.parent
    signature_files = sorted(bag_dir.glob("signatures/*"))
    for signature_file in signature_files:
        try:
            # handle signature files ending in .p7s
            if signature_file.name == file_to_verify.name + ".p7s":
                verify_signature(signature_file, file_to_verify)
                success(f"signature {signature_file} verified", metadata={"file": signature_file})
                file_to_verify = signature_file
                has_signatures = True
            # handle timestamp response files ending in .tsr
            elif signature_file.name == file_to_verify.name + ".tsr":
                pem_file = signature_file.with_suffix(signature_file.suffix + '.crt')
                if not pem_file.exists():
                    error(f"timestamp response file {signature_file} does not have corresponding .crt file", metadata={"file": signature_file})
                    continue
                verify_timestamp(signature_file, file_to_verify, pem_file)
                success(f"Timestamp {signature_file} verified", metadata={"file": signature_file, "pem_file": pem_file})
                file_to_verify = signature_file
                has_timestamps = True
            elif signature_file.name == file_to_verify.name + ".crt":
                continue
            else:
                warn(f"Unknown signature file: {signature_file}", metadata={"file": signature_file})
        except subprocess.CalledProcessError as e:
            error(f"Signature verification failed: {e}", metadata={"file": signature_file})

    # warn about all empty directories in bag_dir/data/
    for dir in bag_dir.glob("data/**"):
        if not any(dir.iterdir()):
            warn(f"Cannot verify the validity of empty directories: {dir}", metadata={"dir": dir})

    if not has_signatures:
        warn("No signatures found")
    if not has_timestamps:
        warn("No timestamps found")
