DEVOPS AGENT — Full Detailed Explanation
The name: SENTINEL
One line: A persistent, self-hosted DevOps agent that lives on your infrastructure, watches your systems 24/7, investigates incidents autonomously, and talks to your team via Slack.
The real pain it solves
3am. PagerDuty fires. On-call engineer wakes up. Opens 6 tabs manually — Datadog, Grafana, CloudWatch, GitHub, Slack, Kubernetes dashboard. Spends 20-40 minutes just figuring out what's wrong, correlating information across systems in their head, half asleep, under pressure. Then spends another hour the next day writing the post-mortem from memory and scattered Slack threads.
This happens to every engineering team. Multiple times a month. It costs companies millions in engineer time and erodes on-call culture — people start dreading the pager because the investigation process itself is exhausting, not just the incident.
SENTINEL eliminates the investigation phase entirely. By the time the engineer picks up their phone, SENTINEL has already done the 40-minute investigation and is presenting a diagnosis with a proposed fix waiting for approval.
What it actually does — concrete flows
Flow 1: Incident Response
PagerDuty fires at 3:12am → SENTINEL receives webhook → immediately spawns parallel investigation:
Fetches last 30 mins of logs from affected service
Queries metrics for anomaly window
Pulls deploy history for last 6 hours
Checks recent PRs merged to main
Reads current pod health across cluster
Correlates all of it. Identifies: deploy at 2:58am, PR #847, missing index on orders table, query time 4ms → 2.3s.
Posts to Slack: "Payment service down. Root cause: PR #847 deployed at 2:58am added a query without an index on orders.user_id. Query time spiked 575x. Recommend: rollback to v2.3.1 OR add index (migration ready). Reply 'rollback' or 'add-index' to proceed."
Engineer replies "rollback." SENTINEL executes. Incident resolved in 4 minutes.
Flow 2: Post-Mortem Generation
Next morning engineer types: "Write last night's post-mortem"
SENTINEL already has everything. Reconstructs full timeline, identifies contributing factors, calculates blast radius (how many users affected, for how long), writes structured post-mortem with five sections — summary, timeline, root cause, contributing factors, action items — posts draft to Slack for review.
Flow 3: Proactive Anomaly Detection
No incident triggered. SENTINEL notices error rate on checkout service quietly climbing from 0.1% to 0.8% over 3 hours. Not enough to trigger PagerDuty. But SENTINEL recognizes the pattern from a previous incident. Posts to Slack: "Checkout error rate trending up. No alert triggered yet but pattern matches Nov 14 incident. Watching." Catches it before it becomes a 3am page.
The 50+ tools across 4 namespaces
observe.* — reading the world (15 tools)
fetch_service_logs
query_metrics_range
get_distributed_traces
check_pod_health
get_error_rate_timeseries
fetch_apm_data
read_queue_depth
check_db_slow_queries
get_network_latency
fetch_cdn_logs
read_flame_graph
check_uptime_history
get_memory_cpu_usage
fetch_alerting_rules
read_dashboard_snapshot
repo.* — understanding what changed (13 tools)
get_recent_commits
diff_pull_request
get_deploy_history
read_ci_pipeline_status
fetch_test_results
blame_file_line
get_rollback_targets
read_changelog
check_dependency_changes
get_feature_flags
fetch_pr_metadata
get_commit_author
read_deployment_config
infra.* — taking action (12 tools)
rollback_deployment
spawn_service_investigator
scale_replicas
toggle_feature_flag
add_database_index
flush_cache
update_rate_limit
drain_node
redeploy_service
modify_env_config
open_circuit_breaker
run_migration
comms.* — communicating and documenting (12 tools)
post_to_slack
create_incident_channel
page_oncall_engineer
update_status_page
write_post_mortem
notify_stakeholders
escalate_incident
close_incident
create_jira_ticket
send_executive_summary
schedule_retro_meeting
update_runbook
Total: 52 tools. All genuine. Zero padding.
The subagent architecture
When an incident spans multiple services simultaneously — which is the hardest and most common real scenario — the parent agent can't investigate everything sequentially. It would take too long and context would bleed between services.
Parent agent spawns one IncidentInvestigatorSubagent per affected service. Each one:
Gets its own isolated Claude context — completely separate API call, separate system prompt
Gets a scoped tool set — only observe.* and repo.. Cannot touch infra. or comms.*. Can read, cannot act.
Runs in parallel with other subagents
Returns a typed structured result:
Python
@dataclass
class ServiceIncidentReport:
    service_name: str
    root_cause: str
    confidence: float  # 0.0-1.0
    evidence: list[Evidence]
    contributing_factors: list[str]
    suggested_fix: str
    rollback_target: str | None
    estimated_user_impact: int
Parent agent receives all ServiceIncidentReport objects, synthesizes them, identifies the common thread across services, proposes a unified remediation. This is real subagent orchestration — isolated context, scoped tools, typed return, parallel execution.
The long-horizon task — 25+ tool calls, coherent plan
"Investigate last night's incident and write the full post-mortem"
comms.fetch_incident_timeline — get PagerDuty alert history
observe.fetch_service_logs — payment service, 2am-4am window
observe.fetch_service_logs — API gateway, same window
observe.query_metrics_range — error rate, latency, throughput
observe.get_distributed_traces — trace the failing requests
observe.check_db_slow_queries — identify the expensive query
repo.get_deploy_history — what went out in that window
repo.diff_pull_request — read the actual code change
repo.fetch_test_results — did tests catch this?
repo.blame_file_line — who owns the affected code
observe.get_error_rate_timeseries — when exactly did it start
repo.get_feature_flags — was this behind a flag
Spawn IncidentInvestigatorSubagent for payment service
Spawn IncidentInvestigatorSubagent for API gateway
Receive ServiceIncidentReport from payment subagent
Receive ServiceIncidentReport from API gateway subagent
Synthesize both reports — identify common root cause
observe.check_uptime_history — calculate blast radius
repo.get_rollback_targets — confirm safe rollback point
comms.search_past_incidents — has this happened before?
repo.read_deployment_config — understand the deploy pipeline
Construct post-mortem structure
comms.write_post_mortem — generate full document
comms.create_jira_ticket — action items as tickets
comms.update_runbook — add new learnings
comms.post_to_slack — share draft for review
That's a real 26-tool coherent investigation. The plan doesn't drift because context management is explicit — after each phase (observe, correlate, synthesize) the agent compresses what it learned into structured state before moving to the next phase. Not just a big context window — active state management in code.
Production scaffolding — what makes it deployment-ready
Every external call wrapped in exponential backoff with typed errors — DatadogRateLimitError, KubernetesTimeoutError, SlackWebhookError — not generic exceptions.
Every tool call logged: timestamp, duration, input hash, output hash, cost, success/failure. Full observability without bloat.
Rate limiting on all external APIs — Datadog, GitHub, PagerDuty all have rate limits that will bite you during a real incident when you're making 30 calls in 60 seconds.
The eval harness runs against known incident scenarios — given this log dump and this deploy history, did the agent identify the correct root cause? Did it propose the right fix? Did it complete without losing coherence? Crisp pass/fail metrics.
Test suite: unit tests per tool, integration tests for full incident flows against a deterministic harness, and one live proof against real local operational infrastructure.
The MEMO.md — writes itself honestly
What you built: a persistent DevOps agent that investigates incidents, proposes fixes, and writes post-mortems autonomously.
What you cut: real-time autonomous action without human approval. Every infra.* action requires explicit human confirmation in Slack. This is the right call — no agent should restart production pods without a human in the loop after 5 days of development.
What more time would address: learning from past incidents to get faster, runbook auto-generation from scratch, multi-cloud support beyond AWS.
Design decision to defend: spawning subagents per service rather than one sequential investigation. An engineer might argue sequential is simpler and more debuggable. The counter: in a real multi-service incident every minute of sequential investigation is a minute more of downtime. Parallel subagents with isolated contexts finish in the time of the slowest single investigation, not the sum of all of them. And isolation means a confused investigation of service A cannot pollute the reasoning about service B.
