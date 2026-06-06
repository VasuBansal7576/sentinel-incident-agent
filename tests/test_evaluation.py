from sentinel.evaluation import EvaluationHarness


def test_evaluation_harness_scores_all_three_scenarios():
    results = EvaluationHarness().run_all()

    assert {result.scenario_name for result in results} == {
        "golden_path",
        "tool_degraded",
        "watch",
    }
    assert all(result.passed for result in results)
    assert all(result.score == 1.0 for result in results)

