from pathlib import Path


def test_project_does_not_use_forbidden_agent_frameworks():
    root = Path(__file__).resolve().parents[1]
    haystack = " ".join(
        path.read_text()
        for path in root.rglob("*.py")
        if ".venv" not in path.parts and path.name != "test_project_constraints.py"
    ).lower()

    forbidden = ["lang" + "chain", "crew" + "ai", "auto" + "gen"]
    assert all(name not in haystack for name in forbidden)
