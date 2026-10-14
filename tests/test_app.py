from pathlib import Path

from streamlit.testing.v1 import AppTest

APP_PATH = Path(__file__).resolve().parents[1] / "app.py"


def test_sample_incident_supports_conversational_follow_up():
    app = AppTest.from_file(APP_PATH, default_timeout=20).run()
    next(button for button in app.button if button.label == "Investigate sample").click().run()
    assert not app.exception
    assert any("Leading hypothesis" in item.value for item in app.markdown)

    app.chat_input[0].set_value("Show the error lines").run()
    assert not app.exception
    assert any("error-level event(s)" in item.value for item in app.markdown)


def test_chat_composer_analyzes_pasted_logs():
    app = AppTest.from_file(APP_PATH, default_timeout=20).run()
    app.chat_input[0].set_value(
        "2026-10-14T10:00:00Z ERROR checkout-api database connection refused"
    ).run()
    assert not app.exception
    assert any("database connection refused" in item.value.lower() for item in app.markdown)
