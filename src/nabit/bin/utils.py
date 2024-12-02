from urllib.parse import urlparse
import click
import requests
from ..lib.archive import validate_package


def assert_file_exists(path):
    click.Path(exists=True, path_type=str, dir_okay=False)(path)

def assert_url(url):
    try:
        requests.Request('GET', url).prepare()
    except requests.RequestException as e:
        raise click.BadParameter(str(e))
    
def cli_validate(bag_path):
    """
    Validate wrapper that prints progress messages and then exits with status 1 if errors are found.
    """
    click.echo(f"Validating package at {bag_path} ...")
    has_errors = False
    def error(message: str, metadata: dict | None = None) -> None:
        nonlocal has_errors
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
        raise click.ClickException("Errors found in package")
    
    click.echo("Package is valid")


class CaptureCommand(click.Command):
    """ Custom click command that captures raw args to the command."""
    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        ctx.raw_args = list(args)
        return super().parse_args(ctx, args)
