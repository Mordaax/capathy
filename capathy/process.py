"""Bounded subprocess and artifact helpers for analysis tools, never target execution."""

import json
import math
import os
import signal
import subprocess
import threading
from pathlib import Path

MAX_OUTPUT = 32 << 20


def tool_environment(extra=None):
    allowed = {
        "PATH",
        "HOME",
        "XDG_CACHE_HOME",
        "JAVA_HOME",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "VIRTUAL_ENV",
        "CAPA_SCRIPT_EXTRACTOR",
        "CAPATHY_CAPA_ROOT",
    }
    result = {key: value for key, value in os.environ.items() if key in allowed}
    result.update(extra or {})
    return result


def run_bounded(command, *, timeout=120, max_output=MAX_OUTPUT, env=None, cwd=None):
    """Drain both pipes under caps, terminating the process group on timeout/overflow."""
    if not math.isfinite(timeout) or not 0 < timeout <= 3600 or not 0 < max_output <= MAX_OUTPUT:
        raise ValueError("invalid analysis tool limits")
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env or tool_environment(),
        cwd=cwd,
        start_new_session=os.name == "posix",
    )
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()

    def kill():
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass

    def consume(stream, buffer, limit):
        try:
            while chunk := stream.read(65536):
                if len(buffer) + len(chunk) > limit:
                    overflow.set()
                    kill()
                    return
                buffer.extend(chunk)
        finally:
            stream.close()

    threads = [
        threading.Thread(target=consume, args=(process.stdout, buffers[0], max_output), daemon=True),
        threading.Thread(target=consume, args=(process.stderr, buffers[1], 65536), daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        kill()
        process.wait()
        raise ValueError("analysis tool timed out") from error
    finally:
        for thread in threads:
            thread.join(timeout=2)
    if overflow.is_set():
        raise ValueError("analysis tool output limit exceeded")
    if any(thread.is_alive() for thread in threads):
        kill()
        raise ValueError("analysis tool retained open output pipes")
    if process.returncode:
        message = buffers[1].decode("utf-8", errors="replace")[-1000:]
        raise ValueError(f"analysis tool exited {process.returncode}: {message}")
    return bytes(buffers[0])


def write_json(path, document):
    """Create a private artifact without overwriting or following an existing symlink."""
    encoded = (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode()
    if len(encoded) > MAX_OUTPUT:
        raise ValueError("JSON artifact exceeds 32 MiB")
    if path is None:
        return encoded
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
    return encoded
