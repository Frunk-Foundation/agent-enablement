from __future__ import annotations

from enabler_cli.agent_main import main


def test_agent_main_is_retired(capsys) -> None:
    rc = main([])
    captured = capsys.readouterr()

    assert rc == 1
    assert "retired" in captured.err
