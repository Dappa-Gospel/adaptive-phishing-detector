from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parent.parent / "app.py"


def _run(page):
    at = AppTest.from_file(str(APP), default_timeout=60)
    at.session_state["active_page"] = page
    at.run()
    return at


def test_all_pages_render_without_exception():
    for page in ["Chat", "History", "Statistics", "Settings", "About"]:
        at = _run(page)
        assert not at.exception, f"{page}: {[e.value for e in at.exception]}"


def test_statistics_shows_model_accuracy():
    at = _run("Statistics")
    labels = [m.label for m in at.metric]
    assert "Overall accuracy" in labels
    accuracy = [m for m in at.metric if m.label == "Overall accuracy"][0]
    assert accuracy.value.endswith("%")
