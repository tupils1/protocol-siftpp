# Protocol SIFT++ — design

Working spec for our FIND EVIL! 2026 submission. This doc is the north star; it also seeds the required *written description* and *architecture* deliverables.

## 1. Goal

Make Protocol SIFT a *fully autonomous* incident-response agent that a senior analyst would trust — one that investigates real forensic case data, **catches its own mistakes**, and shows its work, with no human in the decision loop.

## 2. The wedge (why we win)

FIND EVIL! judging, in weight order:

| # | Criterion | Baseline (Protocol SIFT) | Reference (Valhuntir) | Protocol SIFT++ |
|---|-----------|--------------------------|-----------------------|-----------------|
| 1 | Autonomous execution + real-time self-correction *(tiebreaker)* | autonomous, no self-correction | human-gated (not autonomous) | **adversarial self-correction loop** |
| 2 | IR accuracy / catches hallucinations | no accuracy check | admits it hallucinates; relies on human | **Verifier refutes every finding; confirmed vs inferred** |
| 3 | Depth > breadth | broad | broad / heavy | **one scenario, deep** |
| 4 | Architectural (not prompt) guardrails | permission/prompt-based | infra-based | **read-only MCP server: destructive tools don't exist** |
| 5 | Audit trail to specific tool executions | session log | extensive | **per-finding citation: command + output hash** |
| 6 | Usability / docs | good | heavy setup | **one-command try-it-out** |

## 3. Architecture

```
evidence (read-only)  ─►  read-only MCP server (SIFT tools)  ◄─►  Investigator agent
                                                               │
                                                               ▼
                                                    Skeptic / Verifier agent
                                                               │
                                       confirmed / refuted / inferred  (+ confidence)
                                                               │
                                                               ▼
                                            structured audit log  +  IR report
```

- **Read-only MCP server** wraps a curated set of SIFT tools (e.g. Volatility 3, Sleuth Kit, Plaso, EZ Tools, YARA, Hayabusa) as MCP tools that *only read*. No write/delete/network-exfil tool is exposed → spoliation is impossible by construction.
- **Investigator** (Claude via Protocol SIFT / Claude Agent SDK): plans the investigation, calls tools, drafts findings.
- **Skeptic / Verifier** (separate agent/role): for each draft finding, re-examines the cited evidence and tries to *refute* it. Per-finding verdict: `confirmed` (evidence directly supports), `inferred` (plausible but not directly evidenced), or `refuted` (drop / flag as hallucination), each with a confidence score.
- **Self-correction loop**: `refuted` or low-confidence findings re-enter the Investigator with the Skeptic's objection attached, forcing a new approach — bounded by a max-iteration budget.

## 4. Finding schema (every finding)

`claim` · `severity` · `confidence` (0–1) · `status` (confirmed/inferred/refuted) · `evidence[]` { tool, exact command, output excerpt, sha256 of full output } · `mitre_attack[]` · `verifier_notes`

## 5. Audit log

Append-only JSONL: every tool call (ts, agent, command, args, output hash, tokens), every inter-agent message, every self-correction iteration. This *is* deliverable #8 and backs criterion #5.

## 6. Scope (depth > breadth)

Pick ONE scenario after reviewing the provided sample images:
- **Option A — Memory forensics** (Volatility 3 on a provided memory capture): rogue processes, injected code, persistence.
- **Option B — Windows triage** (EZ Tools + Hayabusa/Sigma on a disk image / EVTX): execution evidence, lateral movement, timeline.

Build the verification loop *deep* on one. Do NOT chase all 200 SIFT tools.

## 7. Compliance

Building on Protocol SIFT + open-source forensic tools is explicitly allowed; FIND EVIL! requires the *novel contribution* to be substantially new work created in the Apr 15 – Jun 15 window and clearly documented. Our novel contribution = the adversarial self-verification loop, the read-only MCP guardrail layer, and the cited / confidence-scored finding + audit system. License: MIT.

## 8. Plan (6/6 → 6/15)

D1–2 env + register + repo + baseline + samples · D3–5 MCP server + Investigator e2e · D5–7 Skeptic + self-correction + confidence/citation/audit · D7–8 accuracy testing + report · D8–9 demo (≥1 self-correction) + arch diagram + docs + submit.

## 9. Open questions

- Which provided sample image / scenario gives the cleanest 5-min self-correction demo?
- Single multi-role agent vs. two separate agent processes for Investigator / Skeptic (MCP makes either viable).
- Does stock Protocol SIFT already expose any MCP, or is it pure Claude Code + CLI? (confirm hands-on on the box)
