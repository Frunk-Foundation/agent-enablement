from __future__ import annotations

import sys

from .runtime_core import _bootstrap_env, _rich_error
from .mcp_server import serve_stdio


def main(argv: list[str] | None = None) -> int:
    del argv
    try:
        _bootstrap_env()
        return serve_stdio()
    except Exception as e:
        _rich_error(str(e))
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
