#!/usr/bin/env python3
"""Validate one read-only legacy Monitor owner snapshot and freeze transport payloads."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from pathlib import Path

EVIDENCE_SCHEMA = "H3_BRG_MONITOR_OWNER_SNAPSHOT_EVIDENCE_V1"
SNAPSHOT_SCHEMA = "H3_MONITOR_OBSERVER_SNAPSHOT_V1"
SOURCE_LEVEL = "3級"
RUNTIME_LEVEL = "3급"
COMPATIBILITY_RIDER = "H3-MONITOR-OWNER-LEVEL-TRANSPORT-20261004-V1"
SEMANTIC_SOURCE = "SEMANTIC_AUTHORING_QUEUE"
RS_SOURCE = "RS13_RS14_GATE"
SEMANTIC_REQUEST_SCHEMA = "H3_RUNTIME_SEMANTIC_AUTHORING_MONITOR_PROJECTION_WRITE_REQUEST_V1"
RS_REQUEST_SCHEMA = "H3_RUNTIME_RS13_RS14_MONITOR_PROJECTION_WRITE_REQUEST_V1"


def fail(code: str) -> None:
    raise SystemExit(code)


def require(condition: bool, code: str) -> None:
    if not condition:
        fail(code)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def source_by_id(snapshot: dict, source_id: str) -> dict:
    sources = snapshot.get("sources")
    require(isinstance(sources, list), "OWNER_SNAPSHOT_SOURCES_INVALID")
    matches = [
        value for value in sources
        if isinstance(value, dict) and value.get("source_id") == source_id
    ]
    require(
        len(matches) == 1,
        "OWNER_SNAPSHOT_SOURCE_CARDINALITY_INVALID:" + source_id,
    )
    return matches[0]


def validate_isolation(values: list[str]) -> None:
    require(
        values == ["NONE", "NONE", "NO", "NONE"],
        "OWNER_SNAPSHOT_MANUAL_ISOLATION_INVALID",
    )


def build_evidence(envelope: dict, source_sha: str, controls: list[str]) -> dict:
    require(
        re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None,
        "OWNER_SNAPSHOT_SOURCE_SHA_INVALID",
    )
    validate_isolation(controls)
    require(isinstance(envelope, dict), "OWNER_SNAPSHOT_CLASP_ENVELOPE_INVALID")
    require(envelope.get("error") is None, "OWNER_SNAPSHOT_CLASP_ERROR")
    snapshot = envelope.get("response")
    require(isinstance(snapshot, dict), "OWNER_SNAPSHOT_RESPONSE_INVALID")
    require(snapshot.get("schema") == SNAPSHOT_SCHEMA, "OWNER_SNAPSHOT_SCHEMA_INVALID")
    require(snapshot.get("level") == SOURCE_LEVEL, "OWNER_SNAPSHOT_SOURCE_LEVEL_INVALID")
    require(
        snapshot.get("write_performed") is False,
        "OWNER_SNAPSHOT_WRITE_PERFORMED_INVALID",
    )
    require(
        isinstance(snapshot.get("last_checked_at"), str)
        and bool(snapshot["last_checked_at"]),
        "OWNER_SNAPSHOT_TIME_INVALID",
    )
    require(
        re.fullmatch(r"[0-9a-f]{64}", str(snapshot.get("snapshot_sha256", "")))
        is not None,
        "OWNER_SNAPSHOT_HASH_INVALID",
    )

    ids = sorted(
        value.get("source_id")
        for value in snapshot.get("sources", [])
        if isinstance(value, dict) and isinstance(value.get("source_id"), str)
    )
    require(
        ids == [
            "ERROR_STATE",
            "RS13_RS14_GATE",
            "RUNTIME_AUTHORITY",
            "SEMANTIC_AUTHORING_QUEUE",
        ],
        "OWNER_SNAPSHOT_SOURCE_SET_INVALID",
    )

    semantic = source_by_id(snapshot, SEMANTIC_SOURCE)
    require(
        semantic.get("status") in {"OK", "WARNING"},
        "OWNER_SNAPSHOT_SEMANTIC_UNREADABLE",
    )
    semantic_data = semantic.get("data")
    require(isinstance(semantic_data, dict), "OWNER_SNAPSHOT_SEMANTIC_DATA_INVALID")
    require(
        semantic_data.get("schema") == "H3_MONITOR_SEMANTIC_AUTHORING_SOURCE_V1",
        "OWNER_SNAPSHOT_SEMANTIC_SCHEMA_INVALID",
    )
    require(
        semantic_data.get("monitor_contract") == "S4-R4-C",
        "OWNER_SNAPSHOT_SEMANTIC_CONTRACT_INVALID",
    )
    require(
        semantic_data.get("semantic_write_performed") is False,
        "OWNER_SNAPSHOT_SEMANTIC_WRITE_INVALID",
    )
    health = semantic_data.get("health")
    require(isinstance(health, dict), "OWNER_SNAPSHOT_SEMANTIC_HEALTH_INVALID")
    require(
        health.get("schema") == "H3_FAMILY_SCHEDULER_AUTHORING_OBSERVABILITY_V1",
        "OWNER_SNAPSHOT_HEALTH_SCHEMA_INVALID",
    )
    require(health.get("mode") == "READ_ONLY_HEALTH", "OWNER_SNAPSHOT_HEALTH_MODE_INVALID")
    require(health.get("level") == SOURCE_LEVEL, "OWNER_SNAPSHOT_HEALTH_LEVEL_INVALID")
    require(health.get("write_performed") is False, "OWNER_SNAPSHOT_HEALTH_WRITE_INVALID")
    policy = health.get("recovery_policy")
    require(isinstance(policy, dict), "OWNER_SNAPSHOT_RECOVERY_POLICY_INVALID")
    require(
        policy.get("policy_id") == "H3-SEMANTIC-AUTHORING-RECOVERY-20260924-V1",
        "OWNER_SNAPSHOT_RECOVERY_POLICY_ID_INVALID",
    )
    require(policy.get("claim_stale_minutes") == 120, "OWNER_SNAPSHOT_CLAIM_STALE_INVALID")
    require(policy.get("retry_backoff_minutes") == 60, "OWNER_SNAPSHOT_RETRY_BACKOFF_INVALID")
    require(policy.get("max_attempts") == 3, "OWNER_SNAPSHOT_MAX_ATTEMPTS_INVALID")

    rs = source_by_id(snapshot, RS_SOURCE)
    require(rs.get("status") in {"OK", "WARNING"}, "OWNER_SNAPSHOT_RS_UNREADABLE")
    rs_data = rs.get("data")
    require(isinstance(rs_data, dict), "OWNER_SNAPSHOT_RS_DATA_INVALID")
    require(
        rs_data.get("schema") == "H3_MONITOR_RS13_RS14_GATE_SOURCE_V1",
        "OWNER_SNAPSHOT_RS_SCHEMA_INVALID",
    )
    require(rs_data.get("monitor_contract") == "S4-R4-D", "OWNER_SNAPSHOT_RS_CONTRACT_INVALID")
    for key in [
        "observer_write_performed",
        "reconciliation_write_performed",
        "historical_backfill_performed",
        "rs13_close_performed",
        "rs14_activation_performed",
        "thresholds_changed",
    ]:
        require(rs_data.get(key) is False, "OWNER_SNAPSHOT_RS_WRITE_GUARD_INVALID:" + key)
    report = rs_data.get("report")
    k1 = rs_data.get("k1_authority")
    require(isinstance(report, dict), "OWNER_SNAPSHOT_REPORT_INVALID")
    require(report.get("schema") == "H3_RS13G_GATE_REPORT_V1", "OWNER_SNAPSHOT_REPORT_SCHEMA_INVALID")
    require(
        report.get("contract_id") == "H3-RS13G-GATE-REPORTER-20260922-V1",
        "OWNER_SNAPSHOT_REPORT_CONTRACT_INVALID",
    )
    require(
        report.get("read_only") is True and report.get("writes_performed") == 0,
        "OWNER_SNAPSHOT_REPORT_WRITE_INVALID",
    )
    require(isinstance(k1, dict), "OWNER_SNAPSHOT_K1_INVALID")
    require(
        k1.get("contract_id") == "H3-RS13K1-K1-SECONDARY-AUTHORITY-20260922-V1",
        "OWNER_SNAPSHOT_K1_CONTRACT_INVALID",
    )
    for key in ["skill_level_concept_inference", "historical_backfill", "state_transfer"]:
        require(k1.get(key) is False, "OWNER_SNAPSHOT_K1_GUARD_INVALID:" + key)

    runtime_health = copy.deepcopy(health)
    runtime_health["level"] = RUNTIME_LEVEL
    evidence = {
        "schema": EVIDENCE_SCHEMA,
        "status": "PASS_LIVE_READONLY",
        "source_repository": "bsi-fujimoto-akinari/hangul_legacy",
        "source_sha": source_sha,
        "snapshot_schema": SNAPSHOT_SCHEMA,
        "snapshot_sha256": snapshot["snapshot_sha256"],
        "observed_at": snapshot["last_checked_at"],
        "compatibility": {
            "contract": COMPATIBILITY_RIDER,
            "source_level": SOURCE_LEVEL,
            "runtime_projection_level": RUNTIME_LEVEL,
            "mapping_scope": "MONITOR_OWNER_PROJECTION_TRANSPORT_ONLY",
            "legacy_persistent_state_changed": False,
        },
        "source_owner_payloads": {
            "semantic_authoring_health": copy.deepcopy(health),
            "rs13_rs14_report": copy.deepcopy(report),
            "k1_authority_health": copy.deepcopy(k1),
        },
        "runtime_projection_requests": {
            "semantic_authoring": {
                "schema": SEMANTIC_REQUEST_SCHEMA,
                "health": runtime_health,
            },
            "rs13_rs14": {
                "schema": RS_REQUEST_SCHEMA,
                "level": RUNTIME_LEVEL,
                "observed_at": snapshot["last_checked_at"],
                "report": copy.deepcopy(report),
                "k1_health": copy.deepcopy(k1),
            },
        },
        "source_snapshot_write_performed": False,
        "runtime_population_performed": False,
    }
    evidence["evidence_sha256"] = hashlib.sha256(canonical_bytes(evidence)).hexdigest()
    return evidence


def self_test() -> None:
    health = {
        "schema": "H3_FAMILY_SCHEDULER_AUTHORING_OBSERVABILITY_V1",
        "mode": "READ_ONLY_HEALTH",
        "level": SOURCE_LEVEL,
        "write_performed": False,
        "recovery_policy": {
            "policy_id": "H3-SEMANTIC-AUTHORING-RECOVERY-20260924-V1",
            "claim_stale_minutes": 120,
            "retry_backoff_minutes": 60,
            "max_attempts": 3,
        },
    }
    report = {
        "schema": "H3_RS13G_GATE_REPORT_V1",
        "contract_id": "H3-RS13G-GATE-REPORTER-20260922-V1",
        "read_only": True,
        "writes_performed": 0,
    }
    k1 = {
        "contract_id": "H3-RS13K1-K1-SECONDARY-AUTHORITY-20260922-V1",
        "skill_level_concept_inference": False,
        "historical_backfill": False,
        "state_transfer": False,
    }
    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "level": SOURCE_LEVEL,
        "last_checked_at": "2026-10-04T00:00:00.000Z",
        "snapshot_sha256": "a" * 64,
        "write_performed": False,
        "sources": [
            {"source_id": "ERROR_STATE", "status": "OK", "data": {}},
            {"source_id": "RUNTIME_AUTHORITY", "status": "OK", "data": {}},
            {
                "source_id": SEMANTIC_SOURCE,
                "status": "OK",
                "data": {
                    "schema": "H3_MONITOR_SEMANTIC_AUTHORING_SOURCE_V1",
                    "monitor_contract": "S4-R4-C",
                    "health": health,
                    "semantic_write_performed": False,
                },
            },
            {
                "source_id": RS_SOURCE,
                "status": "OK",
                "data": {
                    "schema": "H3_MONITOR_RS13_RS14_GATE_SOURCE_V1",
                    "monitor_contract": "S4-R4-D",
                    "report": report,
                    "k1_authority": k1,
                    "observer_write_performed": False,
                    "reconciliation_write_performed": False,
                    "historical_backfill_performed": False,
                    "rs13_close_performed": False,
                    "rs14_activation_performed": False,
                    "thresholds_changed": False,
                },
            },
        ],
    }
    out = build_evidence(
        {"error": None, "response": snapshot},
        "b" * 40,
        ["NONE", "NONE", "NO", "NONE"],
    )
    require(
        out["source_owner_payloads"]["semantic_authoring_health"]["level"] == SOURCE_LEVEL,
        "SELFTEST_SOURCE_LEVEL_MUTATED",
    )
    require(
        out["runtime_projection_requests"]["semantic_authoring"]["health"]["level"] == RUNTIME_LEVEL,
        "SELFTEST_RUNTIME_LEVEL_NOT_MAPPED",
    )
    require(
        out["runtime_projection_requests"]["rs13_rs14"]["level"] == RUNTIME_LEVEL,
        "SELFTEST_RS_LEVEL_NOT_MAPPED",
    )
    require(out["runtime_population_performed"] is False, "SELFTEST_POPULATION_FLAG_INVALID")
    require(
        re.fullmatch(r"[0-9a-f]{64}", out["evidence_sha256"]) is not None,
        "SELFTEST_EVIDENCE_HASH_INVALID",
    )
    print("BRG Monitor owner snapshot validator self-test PASS")


def main(argv: list[str]) -> None:
    if argv == ["self-test"]:
        self_test()
        return
    if len(argv) != 8 or argv[0] != "validate":
        fail(
            "USAGE: validate INPUT OUTPUT SOURCE_SHA "
            "MIGRATION_CONTROL MIG_ASSET REM09_VALIDATION REM09_REPAIR"
        )
    envelope = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    evidence = build_evidence(envelope, argv[3], argv[4:8])
    Path(argv[2]).write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "schema": EVIDENCE_SCHEMA,
        "status": "PASS_LIVE_READONLY",
        "source_sha": argv[3],
        "evidence_sha256": evidence["evidence_sha256"],
        "source_level": SOURCE_LEVEL,
        "runtime_projection_level": RUNTIME_LEVEL,
        "runtime_population_performed": False,
    }, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main(sys.argv[1:])
