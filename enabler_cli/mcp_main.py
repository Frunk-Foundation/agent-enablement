from __future__ import annotations

import argparse
import sys

from .runtime_core import _bootstrap_env, _rich_error
from .mcp_server import serve_stdio


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--agent-id", default="")
    args, _ = parser.parse_known_args(list(argv or []))
    try:
        _bootstrap_env()
        return serve_stdio(agent_id=str(args.agent_id or "").strip())
    except Exception as e:
        _rich_error(str(e))
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
