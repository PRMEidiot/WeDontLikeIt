import multiprocessing
import sys

from .cli import main

if __name__ == "__main__":  # required on Windows/macOS, where worker processes use "spawn"
    multiprocessing.freeze_support()
    sys.exit(main())
