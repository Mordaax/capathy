"""Run integration tests against the verified external engine."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from capathy.runtime import verify_runtime


def pytest_configure(config):
    try:
        root = verify_runtime()
    except (ValueError, OSError) as error:
        raise pytest.UsageError(str(error)) from error
    sys.path.insert(0, str(root))
