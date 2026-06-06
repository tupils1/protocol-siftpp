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

## Local smoke demo

Run the deterministic self-correction demo without API keys or a forensic image:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run siftpp-demo
```

It writes `analysis/demo/report.md`, `analysis/demo/report.json`, and
`analysis/demo/audit.jsonl`. The demo intentionally starts with an over-claimed
injection finding, has the Skeptic refute it, then re-investigates and replaces
it with a narrower evidence-backed finding. This is only a development replay;
the final submission still needs a run on the SANS sample case data.

## Selected SANS case

Primary target case: `SRL-2018 Compromised Enterprise Network /
base-file-memory.7z` from the official FIND EVIL! starter case folder. Download
and extract it with:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run siftpp-download-case
```

The real investigation path supports Anthropic or DeepSeek. For DeepSeek:

```powershell
$env:DEEPSEEK_API_KEY = "<your key>"
C:\Users\Administrator\.local\bin\uv.exe run siftpp-investigate `
  --provider deepseek `
  --evidence evidence\srl-2018-base-file-memory\extracted\base-file-memory.img `
  --out analysis\srl-2018-base-file-memory `
  --case-id srl-2018-base-file-memory `
  --offline
```

## Deliverable drafts

- [Try-it-out instructions](docs/TRY_IT_OUT.md)
- [Architecture and security boundary](docs/ARCHITECTURE.md)
- [Dataset documentation template](docs/DATASET.md)
- [Accuracy and integrity report template](docs/ACCURACY_REPORT.md)
- [5-minute demo script](docs/DEMO_SCRIPT.md)

## License

[MIT](LICENSE).
