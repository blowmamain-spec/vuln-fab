"""Command-line interface."""

from __future__ import annotations

import typer

from vulnfab import __version__

app = typer.Typer(add_completion=False, help="Multi-stack SAST scanner.", no_args_is_help=True)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"vulnfab {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version."
    ),
) -> None:
    """vulnfab command group."""
