
Expected Output

When you run:

.\run_demo.ps1

you should see:

SUMMARY
ALLOW: 9
BLOCK: 10
Expected dashboard

Open:

http://127.0.0.1:8765/audit.html

You should see:

Top verdicts:
ALLOW 9
BLOCK 10

There will also be policy_decision_v4 records. That is normal.

Each AI action creates:

1 policy_check
1 policy_decision_v4

So 19 actions create 38 audit records.
