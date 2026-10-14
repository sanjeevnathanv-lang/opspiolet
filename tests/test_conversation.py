from opspilot.conversation import answer_follow_up, build_incident_answer, looks_like_log_input
from opspilot.pipeline import analyze_log_text


def test_log_detection_distinguishes_log_lines_from_chat_questions():
    assert looks_like_log_input("2026-10-14T10:00:00Z ERROR api database connection refused")
    assert looks_like_log_input("INFO api started\nERROR api request timed out")
    assert not looks_like_log_input("Why is the database error the leading cause?")


def test_opening_answer_summarizes_evidence_without_claiming_proof():
    result = analyze_log_text("2026-10-14T10:00:00Z ERROR api database connection refused")
    answer = build_incident_answer(result)
    assert "1 events" in answer
    assert "Leading lead" in answer
    assert "not proof" in answer


def test_follow_up_answers_actions_and_error_evidence():
    result = analyze_log_text(
        "2026-10-14T10:00:00Z ERROR api database connection refused\n"
        "2026-10-14T10:00:01Z ERROR api database connection refused"
    )
    action_answer = answer_follow_up("What should I check next?", result)
    error_answer = answer_follow_up("Show the error lines", result)
    assert "Safe next checks" in action_answer
    assert "Line 1" in error_answer
    assert "connection refused" in error_answer


def test_follow_up_explains_score_is_not_probability():
    result = analyze_log_text("2026-10-14T10:00:00Z ERROR api database connection refused")
    answer = answer_follow_up("How confident are you?", result)
    assert "not a statistical probability" in answer


def test_unmatched_question_retrieves_relevant_log_evidence():
    result = analyze_log_text("2026-10-14T10:00:00Z ERROR api database connection refused")
    answer = answer_follow_up("Is the database unavailable?", result)
    assert "match the wording" in answer
    assert "database connection refused" in answer


def test_follow_up_without_analysis_asks_for_logs():
    answer = answer_follow_up("What happened?", None)
    assert "Attach or paste a log first" in answer
