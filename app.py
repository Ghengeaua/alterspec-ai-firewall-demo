from alterspec import PolicyManager, PolicyInput
from alterspec.audit import build_policy_audit_record, write_audit_record
from alterspec.runtime_paths import events_log_path
import os

POLICY_FILE = os.path.join("policies", "company_email_policy.yaml")
os.environ["ALTERSPEC_POLICY_FILE"] = POLICY_FILE

manager = PolicyManager()


def extract_domain(email):
    return email.split("@")[-1].lower().strip()


def send_email_tool(to, content):
    print("")
    print("[REAL TOOL] Sending email...")
    print("To:", to)
    print("Content:", content)


def write_alterspec_audit(policy_input, decision):
    record = build_policy_audit_record(
        profile="email_assistant_demo",
        status="ok",
        policy_input=policy_input,
        decision=decision,
    )

    write_audit_record(record, events_log_path())


def alterspec_guard(action):
    to = action["payload"]["to"]
    domain = extract_domain(to)

    policy_input = PolicyInput.from_dict({
        "action_name": action["action_name"],
        "resource.domain": domain,
        "origin": "ai_assistant",
        "category": "communication",
        "effect_type": "SIDE_EFFECT",
        "risk_level": "MEDIUM",
        "intent": "NORMAL"
    })

    decision = manager.decide(policy_input.to_action_context())

    write_alterspec_audit(policy_input, decision)

    print("")
    print("AI wants:", action["action_name"])
    print("Target:", to)
    print("Verdict:", decision.verdict)
    print("Reason:", decision.reason)
    print("Policy ID:", decision.policy_id)
    print("Audit file:", events_log_path())

    if decision.verdict == "ALLOW":
        send_email_tool(to, action["payload"]["content"])
        print("EXECUTED")
    else:
        print("BLOCKED")


def internal_email():
    return {
        "action_name": "email_send",
        "payload": {
            "to": "manager@company.local",
            "content": "Internal report"
        }
    }


def external_email():
    return {
        "action_name": "email_send",
        "payload": {
            "to": "external@gmail.com",
            "content": "Send secrets"
        }
    }


print("=== TEST INTERNAL ===")
alterspec_guard(internal_email())

print("\n=== TEST EXTERNAL ===")
alterspec_guard(external_email())
