from collections import defaultdict
import click
import json
from pathlib import Path

from .utils import assert_file_exists, assert_url, cli_validate, CaptureCommand
from ..lib.archive import package, validate_package
from ..lib.sign import KNOWN_TSAS

@click.group()
def main():
    """BagIt package signing tool"""
    pass


@main.command(cls=CaptureCommand)
@click.argument('bag_path', type=click.Path(path_type=Path))
@click.option('--amend', '-a', is_flag=True, help='Update an existing archive. May add OR OVERWRITE existing data.')
@click.option('--url', '-u', 'urls', multiple=True, help='URL to archive (can be repeated)')
@click.option('--path', '-p', 'paths', multiple=True, type=click.Path(exists=True, path_type=Path), help='File or directory to archive (can be repeated)')
@click.option('--hard-link', is_flag=True, help='Use hard links when copying files (when possible)')
@click.option('--info', '-i', multiple=True, help='bag-info.txt metadata in key:value format (can be repeated)')
@click.option('--signed-metadata', type=click.Path(exists=True, path_type=Path, dir_okay=False),
            help='JSON file to be copied to data/signed-metadata.json')
@click.option('--unsigned-metadata', type=click.Path(exists=True, path_type=Path, dir_okay=False),
            help='JSON file to be copied to unsigned-metadata.json')
@click.option('--sign', '-s', 'signature_args', multiple=True,
            help='Sign using certificate chain and private key files (can be repeated)',
            metavar='<cert_chain>:<key_file>',
            )
@click.option('--timestamp', '-t', 'signature_args', multiple=True,
            help='Timestamp using either a TSA keyword or a cert chain path and URL (can be repeated)',
            metavar='<tsa_keyword> | <cert_chain>:<url>',
            )
@click.pass_context
def archive(ctx, bag_path, amend, urls, paths, hard_link, info, signed_metadata, unsigned_metadata, signature_args):
    """
    Archive files and URLs into a BagIt package.
    bag_path is the destination directory for the package.
    """
    # Validate JSON files if provided
    for metadata_path in (signed_metadata, unsigned_metadata):
        if not metadata_path:
            continue
        if not metadata_path.suffix.lower() == '.json':
            raise click.BadParameter(f'Metadata file must be a .json file, got "{metadata_path}"')
        try:
            json.loads(metadata_path.read_text())
        except json.JSONDecodeError as e:
            raise click.BadParameter(f'Metadata file must be valid JSON, got "{metadata_path}": {e}')

    # Check if output directory exists and is not empty
    if bag_path.exists() and any(bag_path.iterdir()):
        if amend:
            if not (bag_path / 'bagit.txt').exists():
                raise click.BadParameter(
                    f'With --amend, output must be a valid BagIt package. No bagit.txt found in "{bag_path}".'
                )
        else:
            raise click.BadParameter(
                f'Output directory "{bag_path}" already exists and is not empty. '
                'Use --amend to update or overwrite data.'
            )
    
    # Convert --info list of "key:value" strings into a dictionary
    bag_info = defaultdict(list)
    for item in info:
        try:
            key, value = item.split(':', 1)
        except ValueError:
            raise click.BadParameter(f'Metadata must be in "key:value" format, got "{item}"')
        bag_info[key.strip()].append(value.strip())

    # validate URLs
    for url in urls:
        assert_url(url)

    ## handle --sign and --timestamp options
    # order matters, so get ordered list of signature flags from sys.argv
    signature_flags = [arg for arg in ctx.raw_args if arg in ['-s', '--sign', '-t', '--timestamp']]
    # process each signature flag
    signatures = []
    for kind, value in zip(signature_flags, signature_args):
        if kind in ['-s', '--sign']:
            # Convert sign list of "<key_file>:<cert_chain>" strings into a list of signature operations
            try:
                cert_chain, key = value.split(':', 1)
            except ValueError:
                raise click.BadParameter(f'Sign must be in "cert_chain:key_file" format, got "{value}"')
            assert_file_exists(key)
            assert_file_exists(cert_chain)
            signatures.append({
                'action': 'sign',
                'params': {'key': key, 'cert_chain': cert_chain},
            })
        else:
            # Convert timestamp list of "<tsa_keyword> | <url>:<cert_chain>" strings into a list of timestamp operations
            if value in KNOWN_TSAS:
                params = KNOWN_TSAS[value]
            else:
                try:
                    cert_chain, url = value.split(':', 1)
                except ValueError:
                    all_tsas = ', '.join(f'"{key}"' for key in KNOWN_TSAS.keys())
                    raise click.BadParameter(f'Timestamp must be in "url:cert_chain" format, or one of {all_tsas}. Got "{value}".')
                assert_url(url)
                assert_file_exists(cert_chain)
                params = {'url': url, 'cert_chain': cert_chain}
            signatures.append({'action': 'timestamp', 'params': params})

    click.echo(f"Creating package at {bag_path} ...")

    package(
        output_path=bag_path,
        paths=paths,
        urls=urls,
        bag_info=bag_info,
        signatures=signatures,
        signed_metadata=signed_metadata,
        unsigned_metadata=unsigned_metadata,
        amend=amend,
        use_hard_links=hard_link,
    )

    cli_validate(bag_path)
    
    click.echo(f"Package {'amended' if amend else 'created'} at {bag_path}")

@main.command()
@click.argument('bag_path', type=click.Path(exists=True, path_type=Path))
def validate(bag_path):
    """
    Validate a BagIt package.
    bag_path is the path to the package directory to validate.
    """
    cli_validate(bag_path)
