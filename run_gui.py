"""Entry point PyInstaller uses to build the desktop app."""

import multiprocessing

from wedontlikeit.gui import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
