
Architecture

This demo shows AlterSpec used as a guard layer before AI tool execution.

LangChain-style AI Agent
        ↓
Generated Action
        ↓
AlterSpec Guard
        ↓
PolicyManager.decide()
        ↓
ALLOW / BLOCK
        ↓
Real Tool or Block
        ↓
AlterSpec Audit Log
        ↓
AlterSpec Dashboard

The AI does not execute tools directly. Every tool call first becomes a policy input. AlterSpec decides whether the action is allowed. Only ALLOW reaches the real tool. BLOCK stops execution before anything dangerous happens.
