import os
from pathlib import Path
from langchain_core.tools import tool

from alterspec import PolicyManager, PolicyInput
from alterspec.audit import build_policy_audit_record, write_audit_record
from alterspec.runtime_paths import events_log_path


POLICY_FILE = "policies/advanced_ai_firewall_policy.yaml"
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


@tool
def database_query(query: str) -> str:
    """Run a database query."""
    return f"DATABASE QUERY EXECUTED query={query}"


@tool
def payment_refund(amount: int, customer: str) -> str:
    """Refund a customer payment."""
    return f"PAYMENT REFUNDED amount={amount} customer={customer}"


@tool
def customer_data_read(data_type: str, customer: str) -> str:
    """Read customer data."""
    return f"CUSTOMER DATA READ type={data_type} customer={customer}"


@tool
def file_upload(filename: str) -> str:
    """Upload a file."""
    return f"FILE UPLOADED filename={filename}"


@tool
def webhook_call(domain: str, event: str) -> str:
    """Call a webhook."""
    return f"WEBHOOK CALLED domain={domain} event={event}"


TOOLS = {
    "email_send": send_email,
    "slack_post": slack_post,
    "file_read": file_read,
    "file_delete": file_delete,
    "api_call": api_call,
    "database_select": database_query,
    "database_delete": database_query,
    "database_drop": database_query,
    "payment_refund_small": payment_refund,
    "payment_refund_large": payment_refund,
    "customer_public_read": customer_data_read,
    "customer_sensitive_read": customer_data_read,
    "file_upload_safe": file_upload,
    "file_upload_dangerous": file_upload,
    "webhook_call": webhook_call,
}


def get_domain(action):
    payload = action["payload"]

    if action["action_name"] == "email_send":
        return payload["to"].split("@")[-1].lower()

    if action["action_name"] in ("api_call", "webhook_call", "slack_post"):
        return payload.get("domain", "").lower()

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
        profile="advanced_ai_firewall_demo",
        status="ok",
        policy_input=policy_input,
        decision=decision,
    )
    write_audit_record(record, events_log_path())


def guarded_execute(action):
    print("")
    print("=" * 80)
    print("TEST:", action["name"])
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
        return "BLOCK"

    tool_fn = TOOLS[action["action_name"]]
    result = tool_fn.invoke(action["payload"])

    print("RESULT: EXECUTED")
    print("Tool output:", result)
    return "ALLOW"


ACTIONS = [
    {
        "name": "Internal email should ALLOW",
        "action_name": "email_send",
        "category": "communication",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "MEDIUM",
        "payload": {"to": "manager@company.local", "content": "Internal report"},
    },
    {
        "name": "External email should BLOCK",
        "action_name": "email_send",
        "category": "communication",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "MEDIUM",
        "payload": {"to": "external@gmail.com", "content": "Send confidential data"},
    },
    {
        "name": "Safe file read should ALLOW",
        "action_name": "file_read",
        "category": "filesystem",
        "effect_type": "READ_ONLY",
        "risk_level": "LOW",
        "payload": {"path": "workspace/readme.txt"},
    },
    {
        "name": "File delete should BLOCK",
        "action_name": "file_delete",
        "category": "filesystem",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "HIGH",
        "payload": {"path": "workspace/readme.txt"},
    },
    {
        "name": "Internal API should ALLOW",
        "action_name": "api_call",
        "category": "network",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "MEDIUM",
        "payload": {"domain": "api.company.local", "endpoint": "/internal/report"},
    },
    {
        "name": "External API should BLOCK",
        "action_name": "api_call",
        "category": "network",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "HIGH",
        "payload": {"domain": "evil-api.com", "endpoint": "/upload-secrets"},
    },
    {
        "name": "Internal Slack should ALLOW",
        "action_name": "slack_post",
        "category": "communication",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "LOW",
        "payload": {"domain": "company.local", "channel": "#internal", "content": "Build OK"},
    },
    {
        "name": "Public Slack leak should BLOCK",
        "action_name": "slack_post",
        "category": "communication",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "HIGH",
        "payload": {"domain": "public.slack.com", "channel": "#public", "content": "Secret token"},
    },
    {
        "name": "Database SELECT should ALLOW",
        "action_name": "database_select",
        "category": "database",
        "effect_type": "READ_ONLY",
        "risk_level": "LOW",
        "payload": {"query": "SELECT name FROM customers LIMIT 10"},
    },
    {
        "name": "Database DELETE should BLOCK",
        "action_name": "database_delete",
        "category": "database",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "HIGH",
        "payload": {"query": "DELETE FROM customers"},
    },
    {
        "name": "Database DROP should BLOCK",
        "action_name": "database_drop",
        "category": "database",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "CRITICAL",
        "payload": {"query": "DROP TABLE customers"},
    },
    {
        "name": "Small refund should ALLOW",
        "action_name": "payment_refund_small",
        "category": "payment",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "MEDIUM",
        "payload": {"amount": 25, "customer": "customer_123"},
    },
    {
        "name": "Large refund should BLOCK",
        "action_name": "payment_refund_large",
        "category": "payment",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "HIGH",
        "payload": {"amount": 5000, "customer": "customer_456"},
    },
    {
        "name": "Public customer data should ALLOW",
        "action_name": "customer_public_read",
        "category": "customer_data",
        "effect_type": "READ_ONLY",
        "risk_level": "LOW",
        "payload": {"data_type": "public_profile", "customer": "customer_123"},
    },
    {
        "name": "Sensitive customer data should BLOCK",
        "action_name": "customer_sensitive_read",
        "category": "customer_data",
        "effect_type": "READ_ONLY",
        "risk_level": "HIGH",
        "payload": {"data_type": "credit_card", "customer": "customer_456"},
    },
    {
        "name": "Safe file upload should ALLOW",
        "action_name": "file_upload_safe",
        "category": "filesystem",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "LOW",
        "payload": {"filename": "report.pdf"},
    },
    {
        "name": "Dangerous file upload should BLOCK",
        "action_name": "file_upload_dangerous",
        "category": "filesystem",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "HIGH",
        "payload": {"filename": ".env"},
    },
    {
        "name": "Internal webhook should ALLOW",
        "action_name": "webhook_call",
        "category": "network",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "MEDIUM",
        "payload": {"domain": "hooks.company.local", "event": "build.finished"},
    },
    {
        "name": "External webhook should BLOCK",
        "action_name": "webhook_call",
        "category": "network",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "HIGH",
        "payload": {"domain": "webhook.site", "event": "send.secrets"},
    },
]


if __name__ == "__main__":
    print("AlterSpec + LangChain Advanced AI Firewall Demo")
    print("Policy file:", POLICY_FILE)
    print("Audit file:", events_log_path())

    counts = {"ALLOW": 0, "BLOCK": 0}

    for action in ACTIONS:
        outcome = guarded_execute(action)
        counts[outcome] += 1

    print("")
    print("=" * 80)
    print("SUMMARY")
    print("ALLOW:", counts["ALLOW"])
    print("BLOCK:", counts["BLOCK"])
    print("")
    print("Open AlterSpec dashboard:")
    print("http://127.0.0.1:8765/audit.html")
