# Protocol SIFT++ — a self-verifying, autonomous DFIR analyst

*A submission for [SANS FIND EVIL! 2026](https://findevil.devpost.com/) — the first hackathon for autonomous incident response.*
*Built on top of [Protocol SIFT](https://github.com/teamdfir/protocol-sift) and the SANS SIFT Workstation.*

## The gap we close

AI-assisted attackers breach in minutes. The two strongest existing autonomous-IR prototypes each leave half the problem open:

- **Protocol SIFT** (the official baseline) runs autonomously but has **no built-in accuracy check** — it can assert a finding the evidence doesn't actually support.
- **Valhuntir** (the official reference) is rigorous but **gates every finding behind a human approval** — it is *assisted*, not autonomous, and its own docs warn it "will more than likely hallucinate" if simply told to *find evil*.

FIND EVIL!'s top two judging criteria are exactly this pair: **autonomous execution with real-time self-correction**, and **IR accuracy / catching its own hallucinations**. Protocol SIFT++ targets both head-on.

## How it works

An adversarial, self-verifying multi-agent loop layered onto Protocol SIFT:

- **Investigator** — reasons like a senior DFIR analyst: sequences forensic tools, forms findings.
- **Skeptic (Verifier)** — independently tries to *refute* each finding against the raw tool output, separating **confirmed** findings from **inferences**, and flagging or dropping hallucinations.
- **Self-correction loop** — a refuted finding sends the Investigator back to re-investigate and adjust its approach (the behaviour the rubric weights highest).
- **Read-only MCP server** — every forensic tool is exposed through a custom MCP server that contains *only* read-only operations, so the agent is *architecturally* incapable of altering evidence. No spoliation is possible — a guardrail enforced by design, not by prompt.
- **Cited, confidence-scored findings** — each finding carries a confidence level and a citation to the exact tool execution (command + output hash) that supports it, written to a structured, append-only audit log.

## Status

🚧 Under active development for the **June 15, 2026** deadline. See [DESIGN.md](DESIGN.md) for the architecture, the verification protocol, and how each component maps to the judging criteria.

## License

[MIT](LICENSE).
