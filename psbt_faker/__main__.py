"""Command line entry point for running psbt_faker as a module."""

from . import main


def cli() -> None:
    """Invoke the Click command for psbt_faker."""

    main()


if __name__ == "__main__":
    cli()

