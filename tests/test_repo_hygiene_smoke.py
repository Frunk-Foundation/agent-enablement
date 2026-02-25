from __future__ import annotations

import subprocess


def test_repo_contains_no_forbidden_tracked_artifacts() -> None:
    out = subprocess.check_output(["git", "ls-files"], text=True)
    tracked = [line.strip() for line in out.splitlines() if line.strip()]

    forbidden: list[str] = []
    for path in tracked:
        if path.endswith(".DS_Store"):
            forbidden.append(path)
            continue
        if "/__pycache__/" in f"/{path}" or path.startswith("__pycache__/"):
            forbidden.append(path)
            continue
        if path.endswith(".pyc"):
            forbidden.append(path)
            continue
        if path.startswith("cdk.out/"):
            forbidden.append(path)
            continue
        if path.startswith("Library/"):
            forbidden.append(path)
            continue

    assert forbidden == [], f"forbidden tracked artifacts: {forbidden}"
