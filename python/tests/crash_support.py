"""Kill a writer part way through a write, in a child process, as a power cut or SIGKILL does."""
import os
import warnings
from typing import Any, Callable


def start_child() -> int:
    """os.fork(). Earlier tests leave native threads (the policy engine's) that Python warns
    about; the children here touch neither them nor any lock they hold."""
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", "This process .* is multi-threaded",
                                DeprecationWarning)
        return os.fork()


def fork(work: Callable[[], Any]) -> int:
    """Run `work` in a child process that then exits without cleaning up; its exit code."""
    pid = start_child()
    if pid == 0:                                         # pragma: no cover - the child
        code = 1
        try:
            work()
            code = 0
        finally:
            os._exit(code)
    return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])


def die_after(monkeypatch: Any, whole_lines: int, kind: str = "") -> None:
    """Make this process's next write to records.jsonl that holds a record of `kind` (any, by
    default) put down `whole_lines` whole lines and part of the next, then kill the process."""
    import aeos.log as log_module
    real_open = open

    class Dies:
        def __init__(self, f: Any) -> None:
            self.f = f

        def __enter__(self) -> "Dies":
            return self

        def __exit__(self, *exc: Any) -> None:
            self.f.close()

        def write(self, data: bytes) -> int:
            if kind and f'"kind":"{kind}"'.encode() not in data:
                return self.f.write(data)
            lines = data.split(b"\n")
            os.write(self.f.fileno(), b"".join(x + b"\n" for x in lines[:whole_lines])
                     + lines[whole_lines][:30])
            os._exit(9)

        def flush(self) -> None:
            self.f.flush()

        def fileno(self) -> int:
            return self.f.fileno()

    def dying_open(path: Any, mode: str = "r", *a: Any, **k: Any) -> Any:
        f = real_open(path, mode, *a, **k)
        return Dies(f) if str(path).endswith("records.jsonl") and "a" in mode else f

    monkeypatch.setattr(log_module, "open", dying_open, raising=False)
