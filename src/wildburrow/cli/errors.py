import click


class Failure(click.ClickException):
    """An error shown as just its message."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code

    def show(self, file: object = None) -> None:
        click.echo(self.message, err=True)
