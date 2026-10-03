"""
T12 - Ansible Playbook Runner.

Execute Ansible playbooks against target hosts for automated
remediation, patching, and hardening during incident response.
"""

import hashlib
import json

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "playbook": {
            "type": "string",
            "description": "Name or path of the Ansible playbook to execute.",
        },
        "target_hosts": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of target hostnames or IPs.",
        },
        "params": {
            "type": "object",
            "description": "Extra variables passed to the playbook.",
        },
    },
    "required": ["playbook", "target_hosts", "params"],
}

# Deterministic task counts based on playbook name
_PLAYBOOK_TASKS = {
    "patch_os": {"total": 8, "fail_rate": 0},
    "harden_ssh": {"total": 5, "fail_rate": 0},
    "rotate_keys": {"total": 4, "fail_rate": 0},
    "isolate_host": {"total": 3, "fail_rate": 0},
    "deploy_agent": {"total": 6, "fail_rate": 0},
    "collect_forensics": {"total": 7, "fail_rate": 0},
}


async def handler(args: dict, state: dict) -> dict:
    playbook = args["playbook"]
    target_hosts = args["target_hosts"]
    params = args.get("params", {})

    if "executions" not in state:
        state["executions"] = []

    exec_seed = hashlib.sha256(
        json.dumps({"playbook": playbook, "hosts": sorted(target_hosts)},
                   sort_keys=True).encode()
    ).hexdigest()[:8]
    execution_id = f"ANS-{exec_seed}"

    playbook_key = playbook.replace(".yml", "").replace(".yaml", "").split("/")[-1]
    task_info = _PLAYBOOK_TASKS.get(playbook_key, {"total": 5, "fail_rate": 0})

    tasks_total = task_info["total"]
    tasks_failed = task_info["fail_rate"]
    tasks_completed = tasks_total - tasks_failed

    host_results = {}
    for host in target_hosts:
        host_results[host] = {
            "status": "ok" if tasks_failed == 0 else "failed",
            "tasks_ok": tasks_completed,
            "tasks_failed": tasks_failed,
            "tasks_skipped": 0,
        }

    execution_record = {
        "execution_id": execution_id,
        "playbook": playbook,
        "target_hosts": target_hosts,
        "params": params,
        "tasks_completed": tasks_completed,
        "tasks_failed": tasks_failed,
    }
    state["executions"].append(execution_record)
    state["actions_log"].append({
        "action": "run_playbook",
        "execution_id": execution_id,
        "playbook": playbook,
    })

    overall_status = "success" if tasks_failed == 0 else "partial_failure"

    return {
        "status": overall_status,
        "execution_id": execution_id,
        "playbook": playbook,
        "tasks_completed": tasks_completed,
        "tasks_failed": tasks_failed,
        "tasks_total": tasks_total,
        "host_results": host_results,
        "message": (
            f"Playbook '{playbook}' executed on {len(target_hosts)} host(s). "
            f"{tasks_completed}/{tasks_total} tasks completed successfully."
        ),
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="T12_ansible",
        tool_name="Ansible Playbook Runner",
        description="Execute Ansible playbooks for automated remediation and hardening.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
