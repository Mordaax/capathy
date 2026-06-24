"""Supply bounded source bytes to the native helper without invoking a shell."""

import subprocess
import sys
from pathlib import Path

from capathy.process import tool_environment

if __name__ == "__main__":
    with Path(sys.argv[3]).open("rb") as source:
        result = subprocess.run(
            [sys.argv[1], "analyze", "--language", sys.argv[2]], stdin=source, env=tool_environment(), check=False
        )
    raise SystemExit(result.returncode)
