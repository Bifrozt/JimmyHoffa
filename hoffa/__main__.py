"""Enables `python -m hoffa` by delegating to the package entry point."""

from .main import main

if __name__ == "__main__":
    main()
