# EDR System Requirements Document

**Version:** 1.0
**Status:** Draft
**Date:** 2026-08-16

---

## Table of Contents

1. [Overview](#1-overview)
2. [Goals](#2-goals)
3. [Architecture](#3-architecture)
4. [Agent Requirements](#4-agent-requirements)
5. [Server Requirements](#5-server-requirements)
6. [Detection Rule Schema](#6-detection-rule-schema)
7. [Dashboard Requirements](#7-dashboard-requirements)
8. [MCP Requirements](#8-mcp-requirements)
9. [CLI Requirements](#9-cli-requirements)
10. [Security Requirements](#10-security-requirements)
11. [Deployment](#11-deployment)
12. [Out of Scope / Future Work](#12-out-of-scope--future-work)

---

## 1. Overview

This document specifies the requirements for an Endpoint Detection and Response (EDR) system integrated into the existing `cc-toolkit` toolkit. The EDR system provides continuous host-level visibility across a heterogeneous fleet of devices connected via WireGuard VPN. It combines lightweight osquery-based telemetry collection, local YAML detection rule evaluation, a centralized alert ingestion pipeline, and OpenSearch-backed storage and correlation. The system is designed to operate under network constraints (intermittent VPN availability) and on resource-constrained hardware (e.g. Raspberry Pi Zero with 512MB RAM).

The EDR system is not a replacement for a commercial EDR product. It is a purpose-built, self-hosted telemetry and response framework tailored to a small-to-medium fleet with known topology and moderate threat-model requirements.

---

## 2. Goals

- Provide a single pane of glass for host-level security telemetry across all fleet devices.
- Minimize network overhead by transmitting compressed delta-alerts rather than raw logs.
- Maintain operational capability when the VPN tunnel or central server is unavailable.
- Run without performance degradation on ARM devices with as little as 512MB RAM.
- Integrate with the existing `cc-toolkit` ecosystem: Flask dashboard, MCP tools, CLI.
- Keep the dependency footprint small: Python 3.9+ and osquery, nothing else heavyweight.
- Enable AI-assisted investigation and response through MCP tooling.
- Ensure all communication is authenticated and encrypted (WireGuard or mTLS).

---

## 3. Architecture

### 3.1 High-Level Components

```
                          WireGuard VPN
                               |
  [Agent A] --+----------+----+----+----------+-- [Agent B]
  (laptop)    |          |         |          |   (Raspberry Pi)
              |     [Cloud Server] |          |
              |     +-----------+ |          |
              |     | Config API| |          |
              |     | Ingest API| |          |
              |     | Rule Eval | |          |
              |     | OpenSearch| |          |
              |     +-----------+ |          |
  [Agent C] --+-------------------+----------+-- [Agent D]
  (NAS)                         |           (PC)
                         Public :9443
                         (config only)
```

### 3.2 Data Flow

1. **Agent startup**: loads last-known-good config from local cache, initializes osquery scheduler, begins detection rule evaluation loop.
2. **Checkin cycle** (configurable, default 2x/day): agent connects to config API, pulls updated config + detection rules. If WireGuard tunnel is up, uses internal endpoint. If not, falls back to public endpoint on port 9443.
3. **Detection loop**: agent runs osquery packs defined in config, evaluates local detection rules against result sets, updates baseline if first run or if baseline was reset, generates alerts on deviations.
4. **Alert transmission**: on next checkin, agent sends compressed delta-alert batch to ingestion API. Only new/changed alerts are sent (not full log history).
5. **Server-side correlation**: server indexes results in OpenSearch, runs correlation rules across agents, surfaces cross-host patterns.
6. **Dashboard**: web UI displays agent status, alerts, investigation views, and response actions.
7. **MCP/CLI**: external tools query the server REST API for investigation and response.

### 3.3 Key Design Decisions

| Decision | Rationale |
|---|---|
| osquery as telemetry source | Battle-tested, cross-platform, low overhead, JSON output |
| Local rule evaluation | Enables offline operation, reduces server load, faster detection |
| Compressed delta-alerts | Minimizes bandwidth on metered or slow links |
| YAML detection rules (sigma-style) | Human-readable, version-controllable, easy to share |
| OpenSearch for storage | Full-text search, aggregation, alerting, open-source |
| UUID + HMAC auth | Simple, no PKI infrastructure required for agents, works offline |

---

## 4. Agent Requirements

### 4.1 Platform and Runtime

**EDR-AGT-001** The agent MUST run on the following platforms: Windows x86_64, Windows ARM64, Linux x86_64, Linux ARM (32-bit), and Linux ARM64.

**EDR-AGT-002** The agent MUST be implemented in Python 3.9 or later, with no compiled extensions required beyond what Python itself provides.

**EDR-AGT-003** The agent MUST NOT require any dependency beyond Python 3.9+ standard library, osquery, and the bundled YAML/zstd libraries. Specifically, it MUST NOT require gcc, Rust, or any build toolchain at install time.

**EDR-AGT-004** The agent MUST install and operate as a system service (systemd unit on Linux, Windows service or scheduled task on Windows) with configurable start-on-boot behavior.

**EDR-AGT-005** The agent MUST support graceful shutdown on SIGTERM (Linux) or service stop (Windows), flushing any pending alert queue before exit.

### 4.2 Resource Constraints

**EDR-AGT-006** The agent MUST operate within 50MB of RSS on Linux ARM devices (e.g. Raspberry Pi Zero) under normal load.

**EDR-AGT-007** The agent MUST NOT consume more than 5% average CPU on any supported device during steady-state operation.

**EDR-AGT-008** The agent MUST support a configurable osquery query interval (default: 300 seconds) to allow operators to tune resource usage on constrained devices.

**EDR-AGT-009** The agent MUST handle osquery process crashes and restarts without operator intervention, with exponential backoff on repeated failures (max interval: 60 seconds).

### 4.3 Osquery Integration

**EDR-AGT-010** The agent MUST manage an embedded or system-installed osqueryd process, restarting it if it exits unexpectedly.

**EDR-AGT-011** The agent MUST execute osquery scheduled queries defined in the loaded config, parsing JSON result sets and normalizing them into a common internal format.

**EDR-AGT-012** The agent MUST support osquery differential results (added/removed rows) to enable efficient change detection without re-scanning full result sets.

**EDR-AGT-013** The agent MUST tag each osquery result with: device UUID, query name, timestamp (UTC), and a monotonically increasing sequence number.

**EDR-AGT-014** The agent MUST support arbitrary osquery packs defined in YAML config, not just a hardcoded set of queries.

### 4.4 Detection Rule Evaluation

**EDR-AGT-015** The agent MUST evaluate detection rules locally against osquery result sets, without requiring server connectivity.

**EDR-AGT-016** Detection rules MUST be expressed in the YAML schema defined in Section 6.

**EDR-AGT-017** The agent MUST support the following rule condition types: exact match, regex, threshold (count > N within time window), absence (expected item missing), and presence (unexpected item appeared).

**EDR-AGT-018** Rule evaluation MUST be idempotent: running the same rule against the same result set twice MUST produce the same alert only once (deduplicated by rule ID + result fingerprint).

**EDR-AGT-019** The agent MUST log rule evaluation outcomes (match/no-match) at DEBUG level for troubleshooting, without flooding operational logs.

### 4.5 Integrity Monitoring via Baseline

**EDR-AGT-020** The agent MUST maintain a baseline snapshot of osquery result sets for configured queries (processes, listening ports, users, packages, scheduled tasks, firewall rules).

**EDR-AGT-021** The baseline MUST be computed by hashing the sorted, canonical representation of each osquery result set (e.g. SHA-256 of sorted JSON rows).

**EDR-AGT-022** On first run (no existing baseline), the agent MUST record the baseline and NOT generate alerts. This is the initialization period.

**EDR-AGT-023** On subsequent runs, the agent MUST compare current result set hashes against baseline hashes. Any deviation MUST trigger a baseline-change alert with the specific query and delta description.

**EDR-AGT-024** The agent MUST NOT hash raw files (e.g. `/etc/passwd`). Integrity monitoring is strictly at the osquery-result-set level.

**EDR-AGT-025** The baseline MUST be stored locally in a tamper-evident manner (e.g. signed with the agent's HMAC key) and MUST be reproducible from the same osquery results.

**EDR-AGT-026** The agent MUST support server-initiated baseline reset (see EDR-SRV-010), which clears the local baseline and forces re-initialization on next query cycle.

### 4.6 Alert Management

**EDR-AGT-027** The agent MUST maintain a local alert queue (SQLite database or append-only JSONL file) for alerts generated between checkin cycles.

**EDR-AGT-028** Each alert MUST contain: alert UUID (unique), rule ID, device UUID, timestamp (UTC), severity, rule name, description, matched data, and a fingerprint hash for deduplication.

**EDR-AGT-029** The agent MUST deduplicate identical alerts within a configurable window (default: 1 hour) to prevent alert storms from flapping conditions.

**EDR-AGT-030** On each checkin, the agent MUST transmit only NEW alerts since the last successful ingestion (delta-only transmission).

**EDR-AGT-031** The agent MUST compress the alert batch before transmission using zstd (preferred) or gzip (fallback).

**EDR-AGT-032** The agent MUST implement reliable delivery: alerts MUST NOT be discarded until the server confirms receipt via an acknowledgment. If the server does not acknowledge, alerts MUST be retried on the next checkin.

**EDR-AGT-033** The local alert queue MUST have a configurable maximum size (default: 10,000 alerts). When the limit is reached, the oldest alerts MUST be evicted with a warning log.

### 4.7 Configuration and Updates

**EDR-AGT-034** The agent MUST cache the last-known-good configuration locally (signed YAML file) and use it when the server is unreachable.

**EDR-AGT-035** The cached config MUST include: osquery queries, detection rules, checkin interval, public endpoint URL, and response action definitions.

**EDR-AGT-036** The agent MUST pull updated configuration from the server on each checkin cycle. If the server returns a newer config version (by integer version field), the agent MUST apply it.

**EDR-AGT-037** The agent MUST support auto-update of detection rules independent of full config updates, with a separate rule version counter.

**EDR-AGT-038** The agent MUST support self-update of its own code via a signed update package downloaded from the server, with version comparison and rollback capability.

**EDR-AGT-039** Config updates MUST be validated (signature check, schema validation) before application. Invalid configs MUST be rejected and logged.

**EDR-AGT-040** The agent MUST log all config changes (version transitions) with timestamps for audit purposes.

### 4.8 Network Awareness

**EDR-AGT-041** The agent MUST detect the presence of a WireGuard tunnel interface (e.g. `wg0`) and prefer the internal server endpoint when the tunnel is up.

**EDR-AGT-042** If the WireGuard tunnel is DOWN or the internal endpoint is unreachable, the agent MUST fall back to the public config endpoint (port 9443) for config delivery.

**EDR-AGT-043** The agent MUST NOT send alert data over the public endpoint. Alert ingestion is ONLY available over the WireGuard tunnel.

**EDR-AGT-044** The agent MUST implement connection timeouts (configurable, default: 10 seconds) and retry logic with exponential backoff for all network operations.

**EDR-AGT-045** The agent MUST be fully functional with no network connectivity: all detection and baseline operations continue locally; alerts are queued for later transmission.

---

## 5. Server Requirements

### 5.1 Core Server

**EDR-SRV-001** The server MUST be implemented in Python using FastAPI (preferred) or a lightweight Python HTTP framework with async support.

**EDR-SRV-002** The server MUST be deployable as a Podman container, running alongside the existing wg-easy and nginx containers on the cloud server.

**EDR-SRV-003** The server MUST expose the following internal API endpoints (accessible only via WireGuard nginx proxy):

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/cfg/{uuid}` | Deliver device-specific or default config |
| POST | `/api/v1/ingest/{uuid}` | Accept compressed alert batch from agent |
| GET | `/api/v1/agents` | List all registered agents |
| GET | `/api/v1/agents/{uuid}` | Get agent detail |
| GET | `/api/v1/alerts` | List alerts (filterable) |
| GET | `/api/v1/alerts/{alert_id}` | Get alert detail |
| POST | `/api/v1/response/quarantine` | Issue quarantine command to agent |
| POST | `/api/v1/response/isolate` | Issue network isolation command |
| POST | `/api/v1/response/config-push` | Force config push to agent |
| POST | `/api/v1/response/baseline-reset` | Reset baseline on agent |
| POST | `/api/v1/rules` | Add/update detection rule |
| DELETE | `/api/v1/rules/{rule_id}` | Remove detection rule |
| GET | `/api/v1/status` | Server health and stats |

**EDR-SRV-004** The server MUST expose a single public endpoint on port 9443 for config delivery only. This endpoint MUST NOT expose agent data, alerts, or any internal API.

### 5.2 Device Registry

**EDR-SRV-005** The server MUST maintain a device registry with the following fields per agent: UUID (primary key), hostname, OS, architecture, IP addresses, registration timestamp, last checkin timestamp, config version, agent version, tags (user-defined labels), and config overrides (device-specific rule/query overrides).

**EDR-SRV-006** New agents MUST be registered either via a pre-shared enrollment key or through a manual API call by an operator.

**EDR-SRV-007** The server MUST support device groups: agents can be assigned to groups, and groups can have shared config overrides and detection rule sets.

**EDR-SRV-008** The server MUST track agent health: agents that have not checked in within a configurable timeout (default: 48 hours) MUST be flagged as "stale" in the registry.

### 5.3 Config Delivery

**EDR-SRV-009** The config delivery endpoint MUST return a compressed (zstd) YAML configuration file signed with the device's HMAC key.

**EDR-SRV-010** The server MUST support per-device config overrides: device-specific rules, query intervals, or feature toggles that override the default config.

**EDR-SRV-011** The config delivery endpoint MUST include a version integer. Agents compare this to their cached version and skip application if equal or older.

### 5.4 Alert Ingestion

**EDR-SRV-012** The alert ingestion endpoint MUST accept compressed (zstd or gzip) JSON arrays of alerts.

**EDR-SRV-013** On successful ingestion, the server MUST return a JSON response containing a list of acknowledged alert UUIDs and a status code of 200.

**EDR-SRV-014** The server MUST index all ingested alerts into OpenSearch with the following fields: alert UUID, rule ID, device UUID, timestamp, severity, rule name, description, matched data, and source (local rule vs. server correlation).

**EDR-SRV-015** The server MUST reject alert batches from unknown or unregistered device UUIDs with a 403 response.

### 5.5 OpenSearch Integration

**EDR-SRV-016** The server MUST index the following document types in OpenSearch: agent checkin events, detection rule results (from agents), alerts (from agents), server-correlation alerts, baseline snapshots, and response actions.

**EDR-SRV-017** Index names MUST follow the pattern `edr-{type}-{YYYY.MM}` for monthly rotation.

**EDR-SRV-018** The server MUST implement index lifecycle management: indices older than the configurable retention period (default: 90 days) MUST be deleted or archived.

**EDR-SRV-019** The server MUST support OpenSearch queries for: alert aggregation by severity/device/rule, time-series alert trends, device activity timelines, and full-text search across alert descriptions.

### 5.6 Server-Side Correlation

**EDR-SRV-020** The server MUST run correlation rules across all agent data to detect cross-host patterns (e.g. same malicious process on multiple hosts, lateral movement indicators).

**EDR-SRV-021** Correlation rules MUST be defined in the same YAML schema as local detection rules (Section 6), with an additional `scope: global` field.

**EDR-SRV-022** Correlation rules MUST execute on a configurable interval (default: every 15 minutes) against OpenSearch data.

### 5.7 Response Actions

**EDR-SRV-023** The server MUST support issuing response commands to agents: quarantine (block network except C2 channel), force config update, and baseline reset.

**EDR-SRV-024** Response commands MUST be queued for delivery to the target agent on its next checkin. The server MUST track command status (pending, delivered, acknowledged, failed).

**EDR-SRV-025** All response actions MUST be logged with operator identity, timestamp, target agent, action type, and outcome.

---

## 6. Detection Rule Schema

### 6.1 Rule Format

Detection rules are YAML files following the schema below. Each rule is self-contained and describes what to detect, how to detect it, and what to do when a match occurs.

```yaml
id: EDR-RULE-001
name: "New Listening Port Detected"
description: "A new listening port was detected that was not present in the baseline."
severity: medium
platform: all
enabled: true
tags:
  - network
  - baseline

osquery:
  pack: "listening_ports"
  query: "SELECT port, protocol, process_name, pid FROM listening_ports;"
  differential: true

detection:
  method: presence
  field: port
  baseline_field: port
  condition: "new"

response:
  - type: alert
  - type: log
    level: warn
```

**EDR-RULE-001** Every rule MUST contain the following required fields: `id` (unique string), `name` (human-readable), `description`, `severity`, `platform`, `enabled`, and `osquery`.

**EDR-RULE-002** The `severity` field MUST be one of: `info`, `low`, `medium`, `high`, `critical`.

**EDR-RULE-003** The `platform` field MUST be one of: `linux`, `windows`, or `all`.

**EDR-RULE-004** The `osquery` block MUST contain `pack` (name of the osquery pack), `query` (the SQL statement), and optionally `differential` (boolean, default: false).

**EDR-RULE-005** The `detection` block MUST contain `method` (one of: `exact_match`, `regex`, `threshold`, `absence`, `presence`), the relevant field(s), and a `condition` specification appropriate to the method.

### 6.2 Detection Methods

**EDR-RULE-006** `presence`: Detects when a new item appears in the result set that was not in the baseline. Requires `field` (the field to compare) and `baseline_field`.

**EDR-RULE-007** `absence`: Detects when an expected item disappears from the result set. Requires `field` and `baseline_field`.

**EDR-RULE-008** `threshold`: Detects when a count of matching items exceeds a threshold within a time window. Requires `field`, `operator` (`gt`, `gte`, `lt`, `lte`, `eq`), `value` (the threshold), and `window` (e.g. `5m`, `1h`).

**EDR-RULE-009** `exact_match`: Detects when a field matches an exact value or set of values. Requires `field` and `match` (string or list of strings).

**EDR-RULE-010** `regex`: Detects when a field matches a regular expression pattern. Requires `field` and `pattern` (PCRE-compatible regex string).

### 6.3 Response Actions

**EDR-RULE-011** Rules MAY specify zero or more response actions in the `response` block. Supported action types: `alert` (generate alert), `log` (write to agent log at specified level), and `execute` (run a script or command, with operator approval required for high/critical severity).

**EDR-RULE-012** Response actions of type `execute` MUST require explicit operator approval via the dashboard or API before execution. They MUST NOT auto-execute on any severity level.

### 6.4 Rule Inheritance

**EDR-RULE-013** Rules are organized in a two-tier hierarchy: base rules (shipped with the agent, defined in the default config) and device-specific overrides (defined per device or device group in the server config).

**EDR-RULE-014** Device-specific overrides MAY disable a base rule (set `enabled: false`), modify detection parameters (e.g. change threshold value), or add new rules not present in the base set.

**EDR-RULE-015** When a base rule and an override share the same `id`, the override MUST take precedence. The agent MUST log when an override is applied.

### 6.5 Built-In Rules

**EDR-RULE-016** The agent MUST ship with the following built-in detection rules, enabled by default:

| Rule ID | Name | Platform | Detection Method |
|---|---|---|---|
| EDR-BUILTIN-001 | New Listening Port | all | presence |
| EDR-BUILTIN-002 | New Running Process | all | presence |
| EDR-BUILTIN-003 | New User Account | all | presence |
| EDR-BUILTIN-004 | SSH Key Added | linux | presence |
| EDR-BUILTIN-005 | Cron Job Added | linux | presence |
| EDR-BUILTIN-006 | Scheduled Task Added | windows | presence |
| EDR-BUILTIN-007 | Package Installed | all | presence |
| EDR-BUILTIN-008 | Firewall Rule Changed | all | presence |
| EDR-BUILTIN-009 | Sensitive File Modified | all | presence |
| EDR-BUILTIN-010 | High Process Count Threshold | all | threshold |

**EDR-RULE-017** Built-in rules MUST be overridable or disableable via device-specific config overrides, but MUST NOT be editable in place. Operators who want modified behavior MUST create a copy with a new ID.

### 6.6 Custom Rules

**EDR-RULE-018** Operators MUST be able to add custom rules via the dashboard UI, the REST API, or by placing YAML files in a designated rules directory.

**EDR-RULE-019** Custom rules MUST be validated against the schema (Section 6.1-6.2) before being accepted. Invalid rules MUST be rejected with a descriptive error message.

**EDR-RULE-020** Custom rules MUST be distributed to agents on next checkin via the config delivery mechanism.

---

## 7. Dashboard Requirements

### 7.1 EDR Tab

**EDR-DASH-001** The existing Flask web dashboard MUST include a new top-level "EDR" tab, accessible from the main navigation bar.

**EDR-DASH-002** The EDR tab MUST contain the following sub-pages: Agent List, Alert Browser, Investigation View, and Response Actions.

### 7.2 Agent List

**EDR-DASH-003** The Agent List sub-page MUST display a table of all registered agents with the following columns: hostname, OS, architecture, last checkin timestamp, status (online/stale/offline), active alert count, and agent version.

**EDR-DASH-004** The Agent List MUST support filtering by: status, OS, architecture, and tag. It MUST support sorting by any column.

**EDR-DASH-005** Clicking an agent row MUST navigate to the Investigation View for that agent.

### 7.3 Alert Browser

**EDR-DASH-006** The Alert Browser sub-page MUST display a filterable, searchable table of all ingested alerts with the following columns: timestamp, severity (color-coded), rule name, device hostname, and alert status (new/acknowledged/resolved).

**EDR-DASH-007** The Alert Browser MUST support filtering by: severity range, device, rule ID, time range, and alert status. It MUST support full-text search across rule names and alert descriptions.

**EDR-DASH-008** Clicking an alert row MUST expand an inline detail view showing: matched data, rule description, detection method used, and links to the source device.

**EDR-DASH-009** The Alert Browser MUST support bulk operations: acknowledge selected, resolve selected, and export selected as CSV.

### 7.4 Investigation View

**EDR-DASH-010** The Investigation View MUST display a per-agent detail page with the following sections: device metadata, baseline status, recent osquery results, active alerts, and response command history.

**EDR-DASH-011** The baseline status section MUST show: which queries are baselined, current baseline hash, time since last baseline update, and a "Reset Baseline" button.

**EDR-DASH-012** The recent osquery results section MUST display the last N (configurable, default: 100) osquery results from the agent in a filterable table.

### 7.5 Response Actions

**EDR-DASH-013** The Response Actions sub-page MUST provide UI controls for: issuing quarantine commands, issuing network isolation commands, forcing config updates, and resetting baselines on selected agents.

**EDR-DASH-014** All response actions MUST require explicit confirmation (dialog with action description and target agent list) before execution.

**EDR-DASH-015** The Response Actions sub-page MUST display a history of all response commands issued, with status (pending/delivered/acknowledged/failed) and timestamps.

### 7.6 Authentication

**EDR-DASH-016** The EDR tab MUST use the existing dashboard authentication mechanism (API key + CSRF token). No separate auth flow is required.

**EDR-DASH-017** All EDR dashboard API calls MUST include the CSRF token in the request header and be validated server-side.

### 7.7 REST API for External Access

**EDR-DASH-018** The EDR dashboard MUST expose a REST API (JSON) at `/api/v1/edr/` that mirrors the dashboard data, enabling MCP tools and CLI access.

**EDR-DASH-019** The REST API MUST be authenticated via API key (same mechanism as the dashboard) and MUST NOT require CSRF tokens for programmatic access.

---

## 8. MCP Requirements

### 8.1 Tool Definitions

**EDR-MCP-001** The system MUST expose the following MCP tools, each prefixed with `edr_`:

| Tool Name | Description | Parameters |
|---|---|---|
| `edr_agents_list` | List all registered agents with status | filter (optional): status, OS, tag |
| `edr_agent_detail` | Get full detail for a single agent | uuid (required) |
| `edr_alerts_list` | List alerts with filtering | severity, device_uuid, rule_id, time_range, status (all optional) |
| `edr_alert_detail` | Get full detail for a single alert | alert_id (required) |
| `edr_quarantine` | Issue quarantine command to agent(s) | agent_uuids (required), reason (optional) |
| `edr_threat_hunt` | Run a custom osquery hunt across agents | query (required), target_agents (optional, default: all) |
| `edr_config_push` | Force config update to agent(s) | agent_uuids (required) |
| `edr_baseline_reset` | Reset baseline on agent(s) | agent_uuids (required), queries (optional, default: all) |

**EDR-MCP-002** Each MCP tool MUST include a clear description string suitable for AI consumption, including: what the tool does, when to use it, and any safety implications.

### 8.2 Tool Behavior

**EDR-MCP-003** MCP tools MUST call the server REST API (Section 5.1) to retrieve data or issue commands. They MUST NOT access agent data directly.

**EDR-MCP-004** MCP tools MUST return structured JSON responses that can be parsed by the AI model. Error responses MUST include descriptive error messages.

**EDR-MCP-005** The `edr_quarantine` and `edr_baseline_reset` tools MUST include a confirmation mechanism: the tool returns a preview of the action, and a second call with `confirm: true` executes it. This prevents accidental response actions.

**EDR-MCP-006** The `edr_threat_hunt` tool MUST validate the osquery query syntax before sending it to agents. Invalid queries MUST be rejected with a descriptive error.

### 8.3 Documentation

**EDR-MCP-007** All EDR MCP tools MUST be documented in the `cc-toolkit` MCP tool registry with: name, description, parameter schema, return schema, and examples.

**EDR-MCP-008** The MCP tool descriptions MUST explicitly state that these tools are for security investigation and response, and that response actions (quarantine, baseline reset) are destructive operations.

---

## 9. CLI Requirements

### 9.1 Command Structure

**EDR-CLI-001** The system MUST provide a `cc-edr` CLI command with the following subcommands:

```
cc-edr agents list [--status STATUS] [--os OS] [--tag TAG]
cc-edr agents detail UUID
cc-edr alerts list [--severity SEV] [--device UUID] [--rule RULE] [--since TIME]
cc-edr alerts detail ALERT_ID
cc-edr hunt QUERY [--agents UUID1,UUID2]
cc-edr config push [--agents UUID1,UUID2]
cc-edr baseline reset [--agents UUID1,UUID2] [--queries Q1,Q2]
cc-edr status
```

**EDR-CLI-002** The CLI MUST support a `--server` flag to specify the server URL (default: read from local config or environment variable `EDR_SERVER_URL`).

**EDR-CLI-003** The CLI MUST support a `--local` flag to run commands against the local agent (e.g. `cc-edr agents detail --local` shows the local agent's state without contacting the server).

### 9.2 Output Formats

**EDR-CLI-004** The CLI MUST support `--output` flag with values: `table` (default, human-readable), `json` (machine-parseable), and `csv`.

**EDR-CLI-005** Table output MUST include column headers, aligned columns, and color-coded severity levels.

### 9.3 Authentication

**EDR-CLI-006** The CLI MUST authenticate to the server using the same API key mechanism as the dashboard. The API key MUST be configurable via environment variable (`EDR_API_KEY`), config file, or `--api-key` flag.

### 9.4 Offline Mode

**EDR-CLI-007** When `--local` is specified and the server is unreachable, the CLI MUST read directly from the local agent's data directory (alert queue, baseline, config).

**EDR-CLI-008** The CLI MUST clearly indicate when it is operating in offline mode (displaying cached/stale data) vs. live mode (connected to server).

---

## 10. Security Requirements

### 10.1 Agent Authentication

**EDR-SEC-001** Each agent MUST be identified by a unique UUID generated at first run and persisted locally.

**EDR-SEC-002** Each agent MUST possess a pre-shared HMAC key (derived from a master key at enrollment) used for signing config files, alert batches, and authenticating API requests.

**EDR-SEC-003** The HMAC key MUST be baked into the agent at build time or provisioned during first-run enrollment. It MUST NOT be transmitted in plaintext over the network after initial provisioning.

**EDR-SEC-004** The agent MUST sign all outgoing requests (config pulls, alert ingestion) with the HMAC key. The server MUST validate signatures before processing.

### 10.2 Config API Security

**EDR-SEC-005** The public config endpoint (port 9443) MUST authenticate requests using mTLS (preferred) or HMAC signature validation (fallback).

**EDR-SEC-006** The public config endpoint MUST NOT expose any agent data, alerts, internal APIs, or server metadata beyond the config response.

**EDR-SEC-007** The public config endpoint MUST reject requests with invalid or missing authentication with a 401 response and MUST NOT leak information about valid UUIDs.

### 10.3 Alert Ingestion Security

**EDR-SEC-008** The alert ingestion endpoint MUST validate that the UUID in the URL path matches the HMAC key used for request signing. Mismatches MUST be rejected with a 403 response.

**EDR-SEC-009** The alert ingestion endpoint MUST be accessible ONLY via the WireGuard tunnel (nginx proxy configuration). It MUST NOT be exposed on any public port.

### 10.4 Data Protection

**EDR-SEC-010** All data in transit between agents and the server MUST be encrypted: WireGuard tunnel for internal traffic, TLS for the public config endpoint.

**EDR-SEC-011** Alert data MUST NOT be stored in plaintext on disk. The agent's local alert queue MUST use encrypted storage (e.g. SQLite with SQLCipher or encrypted JSONL).

**EDR-SEC-012** Baseline data MUST be signed with the agent's HMAC key to detect tampering. If signature validation fails on load, the agent MUST discard the baseline and re-initialize.

### 10.5 Access Control

**EDR-SEC-013** All internal API endpoints (accessible via WireGuard) MUST require API key authentication. The API key MUST be validated on every request.

**EDR-SEC-014** Response actions (quarantine, isolation, config push, baseline reset) MUST require elevated permissions: the API key used MUST have the `admin` scope. Read-only API keys MUST NOT be able to execute response actions.

**EDR-SEC-015** All response actions MUST be logged with the authenticated operator identity (API key identifier), timestamp, target agent, action type, and outcome. Logs MUST be append-only and tamper-evident.

### 10.6 Network Isolation

**EDR-SEC-016** The nginx proxy configuration MUST ensure that only WireGuard-connected clients can access the internal API. Public-facing ports MUST be limited to port 9443 (config delivery) and any existing dashboard ports.

**EDR-SEC-017** The public config endpoint MUST be hardened: rate limiting (configurable, default: 100 requests/minute per source IP), request size limits, and connection timeouts.

**EDR-SEC-018** The agent's quarantine response action MUST block all outbound network traffic except the WireGuard tunnel to the server, ensuring the agent maintains its C2 channel while isolating the compromised host.

### 10.7 Secret Management

**EDR-SEC-019** API keys, HMAC keys, and mTLS certificates MUST NOT be hardcoded in source code or committed to version control.

**EDR-SEC-020** The server MUST store API keys and HMAC keys in a secure manner (environment variables, secrets manager, or encrypted config file with restricted permissions).

**EDR-SEC-021** The agent's HMAC key file on disk MUST have file permissions restricted to the agent's user account (0600 on Linux, restricted ACL on Windows).

---

## 11. Deployment

### 11.1 Server Deployment

**DEP-001** The server MUST be deployed as a Podman container with the following dependencies: Python 3.9+, OpenSearch (single-node or cluster), and nginx (for reverse proxy).

**DEP-002** The Podman container MUST be configured via environment variables or a mounted config file (no secrets in Dockerfile or image layers).

**DEP-003** The server container MUST expose port 9443 (public config endpoint) and the internal API port (default: 8000, proxied via nginx over WireGuard only).

**DEP-004** OpenSearch MUST be deployed as a separate container with persistent volume for data storage. The server container connects to OpenSearch via the WireGuard-internal network.

**DEP-005** The nginx container MUST be configured to proxy internal API requests from WireGuard clients to the server container, and to forward port 9443 for the public config endpoint.

### 11.2 Agent Deployment

**DEP-006** Agent installation MUST be a single-command process: `python install.py` (or platform-appropriate equivalent) that installs the agent as a system service and performs first-run enrollment.

**DEP-007** First-run enrollment MUST: generate a device UUID, provision the HMAC key (via enrollment key or manual operator action), download the initial config, and start the agent service.

**DEP-008** Agent updates MUST be delivered via the config update mechanism (EDR-AGT-038) and MUST NOT require manual intervention on each device.

**DEP-009** The agent MUST include a health check endpoint (local only, e.g. Unix socket or Windows named pipe) that returns current status, config version, and last checkin timestamp.

### 11.3 Fleet Management

**DEP-010** The server MUST support bulk operations: register multiple agents, push config to all agents in a group, and query alerts across all agents.

**DEP-011** The server MUST provide a fleet health dashboard showing: total agents, online/stale/offline counts, alert severity distribution, and OpenSearch storage utilization.

**DEP-012** The system MUST support rolling updates: new agent versions can be deployed incrementally across the fleet without downtime, with the server tracking which agents are on which version.

---

## 12. Out of Scope / Future Work

The following items are explicitly excluded from the initial release but may be addressed in future versions:

- **Full network traffic analysis**: The EDR system focuses on host-level telemetry, not network packet inspection.
- **File integrity monitoring via hashing**: Integrity monitoring is based on osquery result sets, not direct file hashing.
- **Automated response without operator approval**: All response actions require explicit operator confirmation.
- **Multi-tenant support**: The initial deployment assumes a single operator/team managing one fleet.
- **Compliance reporting**: No built-in compliance framework mapping (e.g. CIS, NIST) in v1.
- **Mobile device support**: iOS and Android are out of scope.
- **Cloud workload protection**: AWS/GCP/Azure instance integration is not included.
- **Machine learning-based detection**: All detection rules are deterministic YAML-based rules. ML-based anomaly detection may be added in a future version.
- **Agent-to-agent communication**: Agents communicate only with the server, not with each other.
- **Real-time streaming**: Alert transmission is batched on checkin intervals, not real-time push.
- **OpenSearch cluster mode**: Initial deployment assumes single-node OpenSearch. Cluster mode may be supported later for larger fleets.
- **Agent auto-enrollment**: First-run enrollment requires either a pre-shared enrollment key or manual operator registration. Zero-touch enrollment is a future goal.
- **Integration with external SIEM/SOAR**: No built-in forwarding to Splunk, Elastic, Sentinel, etc. in v1. This can be added via OpenSearch connectors.
