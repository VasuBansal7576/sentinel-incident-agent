from sentinel.models import PermissionClass, ToolNamespace
from sentinel.scenarios import build_scenarios
from sentinel.simulated import TOOL_IMPLEMENTATIONS, SimulatedIncidentEnvironment
from sentinel.store import SQLiteInvestigationStore
from sentinel.tools import ToolExecutor, ToolFactory


def test_registry_declares_exact_52_tools_across_four_namespaces():
    registry = ToolFactory(
        SimulatedIncidentEnvironment(build_scenarios()["golden_path"])
    ).build_registry()

    assert len(registry) == 52
    assert len(registry.names_for_namespace(ToolNamespace.OBSERVE)) == 15
    assert len(registry.names_for_namespace(ToolNamespace.REPO)) == 13
    assert len(registry.names_for_namespace(ToolNamespace.INFRA)) == 12
    assert len(registry.names_for_namespace(ToolNamespace.COMMS)) == 12
    assert set(registry.contracts) == set(TOOL_IMPLEMENTATIONS)


def test_all_52_tools_execute_through_factory_and_typed_executor():
    registry = ToolFactory(
        SimulatedIncidentEnvironment(build_scenarios()["golden_path"])
    ).build_registry()
    store = SQLiteInvestigationStore()
    executor = ToolExecutor(registry, store)
    investigation_id = "inv-tool-unit"

    for contract in registry.list_contracts():
        result = executor.invoke(
            contract.name,
            {"service": "payment-service", "time_window": "02:30-03:30 UTC"},
            investigation_id=investigation_id,
            state=contract.phase_allowlist[0],
            approved=contract.permission == PermissionClass.HUMAN_APPROVED_REMEDIATION,
        )
        assert result.success, contract.name
        assert result.data["implementation"] == f"simulated::{contract.name}"
        assert result.data["stub"] is False
        implementation_keys = set(TOOL_IMPLEMENTATIONS[contract.name]["data"])
        assert implementation_keys
        assert implementation_keys.issubset(result.data)
        assert result.evidence, contract.name
        assert "returned simulated source material" not in result.evidence[0].claim
        assert result.attempt_count >= 1

    assert len(store.list_tool_calls(investigation_id)) == 52


def test_retry_backoff_records_attempts_for_transient_tool_failure():
    scenario = build_scenarios()["golden_path"]
    registry = ToolFactory(SimulatedIncidentEnvironment(scenario)).build_registry()
    store = SQLiteInvestigationStore()
    executor = ToolExecutor(registry, store)

    contract = registry.get_contract("observe.fetch_service_logs")
    result = executor.invoke(
        contract.name,
        {"service": "payment-service"},
        investigation_id="inv-retry",
        state=contract.phase_allowlist[0],
    )

    assert result.success
    assert result.attempt_count == 2


def test_tool_access_denial_is_audited_without_substitution():
    registry = ToolFactory(
        SimulatedIncidentEnvironment(build_scenarios()["golden_path"])
    ).build_registry()
    store = SQLiteInvestigationStore()
    executor = ToolExecutor(registry, store)

    result = executor.invoke(
        "infra.rollback_deployment",
        {"service": "payment-service", "target": "v2.3.1"},
        investigation_id="inv-denied",
        state=registry.get_contract("infra.rollback_deployment").phase_allowlist[0],
        approved=False,
    )
    scoped = executor.invoke(
        "observe.fetch_service_logs",
        {"service": "payment-service"},
        investigation_id="inv-denied",
        state=registry.get_contract("observe.fetch_service_logs").phase_allowlist[0],
        allowed_tool_names={"repo.get_deploy_history"},
    )

    assert not result.success
    assert result.error_kind == "permission_denied"
    assert not scoped.success
    assert scoped.error_kind == "permission_denied"
    assert [call.tool_name for call in store.list_tool_calls("inv-denied")] == [
        "infra.rollback_deployment",
        "observe.fetch_service_logs",
    ]
