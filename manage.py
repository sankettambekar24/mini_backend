#!/usr/bin/env python
"""Django management utility for Hybrid Secure Storage System backend."""

import os
import sys


def main():
    if not os.environ.get("DJANGO_SETTINGS_MODULE"):
        raise SystemExit(
            "Set DJANGO_SETTINGS_MODULE explicitly (use config.settings.local for development; "
            "production services must use config.settings.production)."
        )
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
