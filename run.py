"""Entry point PyInstaller uses to build the command-line executable."""

import multiprocessing
import sys

from wedontlikeit.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
