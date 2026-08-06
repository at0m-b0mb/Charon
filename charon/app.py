"""Application entry point."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from .paths import config_dir, log_file
from .version import APP_NAME, APP_TAGLINE, __version__


def _configure_logging(verbose: bool) -> None:
    """Log to a file in the config directory, and to stderr when asked.

    The formatter is deliberately plain and the level defaults to INFO: Charon
    never logs a password, a passphrase or a key, and keeping the log readable
    is what lets a user check that for themselves.
    """
    handlers: list[logging.Handler] = []
    try:
        handlers.append(logging.FileHandler(log_file(), encoding="utf-8"))
    except OSError:
        pass
    if verbose:
        handlers.append(logging.StreamHandler(sys.stderr))
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        handlers=handlers or [logging.NullHandler()],
    )
    # paramiko is chatty at DEBUG and its transport log includes packet dumps.
    logging.getLogger("paramiko").setLevel(logging.WARNING)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="charon", description=f"{APP_NAME} — {APP_TAGLINE}")
    parser.add_argument("--version", action="version",
                        version=f"{APP_NAME} {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="also log to stderr, at debug level")
    parser.add_argument("--where", action="store_true",
                        help="print where Charon keeps its configuration and exit")
    args = parser.parse_args(argv)

    if args.where:
        print(config_dir())
        return 0

    _configure_logging(args.verbose)

    from PyQt6.QtGui import QGuiApplication
    from PyQt6.QtWidgets import QApplication

    QGuiApplication.setApplicationDisplayName(APP_NAME)
    app = QApplication(sys.argv[:1])
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setOrganizationName("at0m-b0mb")

    from .ui.main_window import MainWindow

    window = MainWindow()
    window.show()

    if os.environ.get("CHARON_SMOKE_TEST"):
        # Used by the test suite and the screenshot tool: build the whole window,
        # prove it paints, then leave without entering the event loop.
        from PyQt6.QtCore import QTimer

        QTimer.singleShot(int(os.environ["CHARON_SMOKE_TEST"]), app.quit)

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
