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


def test_local_classifier_can_add_a_lead_for_an_unmatched_log_message():
    result = analyze_log_text(
        "2026-10-14T10:00:00Z ERROR api name lookup for payments.internal returned NXDOMAIN"
    )
    model_hypotheses = [hypothesis for hypothesis in result.hypotheses if hypothesis.method == "model"]
    assert model_hypotheses
    assert "DNS" in model_hypotheses[0].summary
    assert any("Line 1" in item and "NXDOMAIN" in item for item in model_hypotheses[0].evidence)
    assert any("name resolution" in action.title.lower() for action in result.recommendations)


def test_rules_still_work_when_joblib_is_not_installed(monkeypatch):
    import builtins

    from opspilot import ml_model

    original_import = builtins.__import__

    def import_without_joblib(name, *args, **kwargs):
        if name == "joblib":
            raise ModuleNotFoundError("No module named 'joblib'")
        return original_import(name, *args, **kwargs)

    ml_model._load_artifact.cache_clear()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(builtins, "__import__", import_without_joblib)
            ready, _, error = ml_model.classifier_status()
            result = analyze_log_text("2026-10-14T10:00:00Z ERROR api database connection refused")
        assert not ready
        assert "joblib is not installed" in error
        assert result.hypotheses
        assert "Database" in result.hypotheses[0].summary
    finally:
        ml_model._load_artifact.cache_clear()


def test_pipeline_assesses_healthy_but_unfamiliar_logs():
    result = analyze_log_text("worker-7 completed task 42 in 18ms\nworker-8 completed task 43 in 22ms")
    assert "No explicit error" in result.assessment
    assert result.hypotheses == []

