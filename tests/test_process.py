import sys

import pytest

from capathy.process import run_bounded, tool_environment


def test_subprocess_limits_and_credential_removal(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-secret")
    assert "ANTHROPIC_API_KEY" not in tool_environment()
    with pytest.raises(ValueError, match="output limit"):
        run_bounded([sys.executable, "-c", "print('x'*200000)"], max_output=1024)
    with pytest.raises(ValueError, match="timed out"):
        run_bounded([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.05)
