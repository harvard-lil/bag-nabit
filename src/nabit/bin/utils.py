from urllib.parse import urlparse
import click
from ..lib.archive import validate_package


def assert_file_exists(path):
    click.Path(exists=True, path_type=str, dir_okay=False)(path)

def assert_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ['http', 'https']:
        raise click.BadParameter(f'Expected a URL with http or https scheme, got "{url}"')
    
def cli_validate(bag_path):
    """
    Validate wrapper that prints progress messages and then exits with status 1 if errors are found.
    """
    click.echo(f"Validating package at {bag_path} ...")
    has_errors = False
    def error(message: str, metadata: dict | None = None) -> None:
        click.secho("ERROR:", fg='red', bold=True, nl=False)
        click.echo(f" {message}")
        has_errors = True

    def warn(message: str, metadata: dict | None = None) -> None:
        click.secho("WARNING:", fg='yellow', bold=True, nl=False)
        click.echo(f" {message}")

    def success(message: str, metadata: dict | None = None) -> None:
        click.secho("SUCCESS:", fg='green', bold=True, nl=False)
        click.echo(f" {message}")

    validate_package(bag_path, error, warn, success)

    if has_errors:
        click.echo("Errors found in package")
        click.exit(1)
    
    click.echo("Package is valid")