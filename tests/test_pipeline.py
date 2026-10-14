from opspilot.pipeline import analyze_log_text


def test_pipeline_ranks_database_cause_and_recommends_safe_action():
    text = "\n".join([
        "2026-10-14T10:00:00Z INFO checkout-api request started",
        "2026-10-14T10:00:01Z ERROR checkout-api database connection refused",
        "2026-10-14T10:00:02Z ERROR checkout-api database connection refused",
        "2026-10-14T10:00:03Z ERROR checkout-api request failed with HTTP 503",
    ])
    result = analyze_log_text(text)
    assert len(result.events) == 4
    assert result.context is not None
    assert result.hypotheses
    assert "Database" in result.hypotheses[0].summary
    assert result.recommendations
    assert all("execute" not in step.lower() for action in result.recommendations for step in action.steps)


def test_pipeline_handles_empty_input():
    result = analyze_log_text("")
    assert result.events == []
    assert result.context is not None
    assert result.hypotheses == []
    assert result.recommendations == []
    assert "No non-empty log lines" in result.assessment


def test_pipeline_gives_a_cautious_answer_for_unfamiliar_logs():
    result = analyze_log_text("Exception: payment provider returned code XJ-73")
    assert result.events[0].is_error
    assert result.findings[0].pattern_id == "unclassified-error"
    assert "not classified" in result.hypotheses[0].summary
    assert "payment provider" in result.assessment.lower()
    assert result.recommendations


def test_pipeline_assesses_healthy_but_unfamiliar_logs():
    result = analyze_log_text("worker-7 completed task 42 in 18ms\nworker-8 completed task 43 in 22ms")
    assert "No explicit error" in result.assessment
    assert result.hypotheses == []

