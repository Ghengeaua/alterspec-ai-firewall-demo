import os
from pathlib import Path

from langchain_core.tools import tool

from alterspec import PolicyManager, PolicyInput
from alterspec.audit import build_policy_audit_record, write_audit_record
from alterspec.runtime_paths import events_log_path


POLICY_FILE = "policies/multi_action_policy.yaml"
os.environ["ALTERSPEC_POLICY_FILE"] = POLICY_FILE

manager = PolicyManager()


@tool
def send_email(to: str, content: str) -> str:
    """Send an email."""
    return f"EMAIL SENT to={to} content={content}"


@tool
def slack_post(channel: str, content: str) -> str:
    """Post a Slack message."""
    return f"SLACK POSTED channel={channel} content={content}"


@tool
def file_read(path: str) -> str:
    """Read a local file."""
    return Path(path).read_text(encoding="utf-8")


@tool
def file_delete(path: str) -> str:
    """Delete a local file."""
    Path(path).unlink(missing_ok=True)
    return f"FILE DELETED path={path}"


@tool
def api_call(domain: str, endpoint: str) -> str:
    """Call an API endpoint."""
    return f"API CALLED domain={domain} endpoint={endpoint}"


TOOLS = {
    "email_send": send_email,
    "slack_post": slack_post,
    "file_read": file_read,
    "file_delete": file_delete,
    "api_call": api_call,
}


def get_domain(action):
    payload = action["payload"]

    if action["action_name"] == "email_send":
        return payload["to"].split("@")[-1].lower()

    if action["action_name"] == "api_call":
        return payload["domain"].lower()

    if action["action_name"] == "slack_post":
        return payload["domain"].lower()

    return None


def build_policy_input(action):
    payload = action["payload"]

    data = {
        "action_name": action["action_name"],
        "origin": "langchain_agent",
        "category": action["category"],
        "effect_type": action["effect_type"],
        "risk_level": action["risk_level"],
        "intent": "NORMAL",
    }

    domain = get_domain(action)
    if domain:
        data["resource.domain"] = domain

    if "path" in payload:
        data["resource.path"] = payload["path"].replace("\\", "/")

    return PolicyInput.from_dict(data)


def write_audit(policy_input, decision):
    record = build_policy_audit_record(
        profile="langchain_multi_action_demo",
        status="ok",
        policy_input=policy_input,
        decision=decision,
    )
    write_audit_record(record, events_log_path())


def guarded_execute(action):
    print("")
    print("=" * 70)
    print("AI wants to execute:", action["action_name"])
    print("Payload:", action["payload"])

    policy_input = build_policy_input(action)
    decision = manager.decide(policy_input.to_action_context())
    write_audit(policy_input, decision)

    print("AlterSpec verdict:", decision.verdict)
    print("Reason:", decision.reason)
    print("Policy:", decision.policy_id)

    if decision.verdict != "ALLOW":
        print("RESULT: BLOCKED BY ALTERSPEC")
        return

    tool_fn = TOOLS[action["action_name"]]
    result = tool_fn.invoke(action["payload"])

    print("RESULT: EXECUTED")
    print("Tool output:", result)


ACTIONS = [
    {
        "name": "Internal email should ALLOW",
        "action_name": "email_send",
        "category": "communication",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "MEDIUM",
        "payload": {
            "to": "manager@company.local",
            "content": "Internal report",
        },
    },
    {
        "name": "External email should BLOCK",
        "action_name": "email_send",
        "category": "communication",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "MEDIUM",
        "payload": {
            "to": "external@gmail.com",
            "content": "Send confidential data",
        },
    },
    {
        "name": "Safe file read should ALLOW",
        "action_name": "file_read",
        "category": "filesystem",
        "effect_type": "READ_ONLY",
        "risk_level": "LOW",
        "payload": {
            "path": "workspace/readme.txt",
        },
    },
    {
        "name": "File delete should BLOCK",
        "action_name": "file_delete",
        "category": "filesystem",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "HIGH",
        "payload": {
            "path": "workspace/readme.txt",
        },
    },
    {
        "name": "Internal API should ALLOW",
        "action_name": "api_call",
        "category": "network",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "MEDIUM",
        "payload": {
            "domain": "api.company.local",
            "endpoint": "/internal/report",
        },
    },
    {
        "name": "External API should BLOCK",
        "action_name": "api_call",
        "category": "network",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "HIGH",
        "payload": {
            "domain": "evil-api.com",
            "endpoint": "/upload-secrets",
        },
    },
    {
        "name": "Internal Slack should ALLOW",
        "action_name": "slack_post",
        "category": "communication",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "LOW",
        "payload": {
            "domain": "company.local",
            "channel": "#internal-alerts",
            "content": "Build finished successfully",
        },
    },
    {
        "name": "Public Slack leak should BLOCK",
        "action_name": "slack_post",
        "category": "communication",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "HIGH",
        "payload": {
            "domain": "public.slack.com",
            "channel": "#public",
            "content": "Company secret token: 12345",
        },
    },
]


if __name__ == "__main__":
    print("AlterSpec + LangChain Multi-Action Firewall Demo")
    print("Policy file:", POLICY_FILE)
    print("Audit file:", events_log_path())

    for action in ACTIONS:
        print("")
        print("TEST:", action["name"])
        guarded_execute(action)

    print("")
    print("=" * 70)
    print("Done.")
    print("Open AlterSpec dashboard:")
    print("http://127.0.0.1:8765/audit.html")
