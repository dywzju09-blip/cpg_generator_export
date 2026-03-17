---
name: agent-handoff-prompter
description: Generate copy-ready implementation prompts for other coding agents instead of editing code directly. Use when the user wants to hand off coding work to another agent and needs clear target files, technical rationale, expected runtime behavior, verification criteria, and optional diagrams for complex logic.
---

# Agent Handoff Prompter

## Objective

Produce two artifacts for every request:
1. A copy-ready prompt for another coding agent.
2. A human-readable brief that explains what will change, why it works, and what should happen after the change.

Never edit project files while this skill is active. Only produce structured prompts and explanations.

## Workflow

1. Read the user goal and infer the likely code area.
2. Identify concrete file targets using exact paths whenever available.
3. Explain the implementation principle in plain language and technical language.
4. Define expected runtime behavior before and after the change.
5. Define verification commands and acceptance criteria.
6. Add a Mermaid diagram when flow, state, or component interactions are non-trivial.
7. Return the response in the required output contract.

## Output Contract

Always output the following sections in order.

### 1) Handoff Prompt (for agent)

Write a fenced markdown block that can be copied directly into another coding agent.
Include:
- Goal and scope
- Project context
- Files to modify (absolute or repo-relative paths)
- Detailed implementation steps
- Technical constraints and non-goals
- Verification commands
- Acceptance criteria
- Expected output format from the target agent

### 2) Human Brief

Summarize for humans:
- Which files are expected to change and why
- Core principle behind the fix
- Expected behavior after rollout
- Main risks and rollback idea

### 3) Diagram (Optional but Preferred for Complexity)

Add Mermaid only when helpful, especially for:
- Multi-component request/response flows
- State transitions
- Async pipelines
- Error handling branches

## Quality Gates

Before returning the final prompt, verify:
- Mention specific files instead of vague modules.
- Explain both "what to change" and "why this change is correct."
- State measurable expected behavior (logs, output, API response, UI state, performance bound, or test result).
- Include executable validation commands.
- Avoid direct code patches in this skill output.

## Template Reference

Use [references/prompt-template.md](references/prompt-template.md) as the primary structure.

## Missing Context Policy

If key details are missing, do not stop.

Apply this rule:
1. State assumptions explicitly.
2. Produce a best-effort prompt under those assumptions.
3. Add a short "Need Confirmation" list at the end.
