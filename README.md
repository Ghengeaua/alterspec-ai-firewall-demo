# AlterSpec AI Firewall Demo

This project demonstrates AlterSpec as an AI Action Firewall.

It shows how an AI agent can be allowed or blocked before executing tools such as email, Slack, file access, API calls, database operations, payments, customer data access, file uploads, and webhooks.

## Run

```powershell
py -m pip install -r requirements.txt
.\run_demo.ps1
Expected result
SUMMARY
ALLOW: 9
BLOCK: 10
Dashboard

Start the AlterSpec dashboard from the private AlterSpec repo:

cd "C:\Users\AequitaS\Desktop\Proiecte\AlterSpec\alterspec"
py tools\alterspec_dashboard\dev_server.py

Open:

http://127.0.0.1:8765/audit.html

Expected dashboard result:

Top verdicts:
ALLOW 9
BLOCK 10
Architecture
AI Agent
   ↓
AlterSpec Policy Check
   ↓
ALLOW / BLOCK
   ↓
Tool Execution or Block
   ↓
Audit Log
   ↓
AlterSpec Dashboard

AlterSpec itself stays private. This repo is only the demo application.

## Dashboard preview

![AlterSpec dashboard audit summary](screenshots/dashboard-audit-summary.png)

