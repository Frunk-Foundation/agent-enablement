from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    del argv
    sys.stderr.write(
        "error: enabler agent runtime CLI was retired. Use ./enabler-creds and ./enabler-mcp.\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
