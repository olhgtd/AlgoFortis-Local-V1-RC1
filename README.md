# AlgoFortis Public CI Mirror

This repository is a disposable, sanitized CI snapshot used only to execute qualification workflows on public GitHub-hosted runners.

The authoritative product source remains the private repository `olhgtd/ALGOFORTISGPT`. This public mirror is not a development source of truth and must not contain credentials, private keys, broker secrets, real account/user data, local databases/runtime state, unrestricted trade logs, bulk market datasets, or private Git history.

The exact private source commit and allowed snapshot surface are recorded in `CI_MIRROR_MANIFEST.json`.

Phase 8 safety invariants for this snapshot:

- AI authority: `RESEARCH_SHADOW_ONLY`
- ApprovedOrder authority: `RISK_GATE_V2_ONLY`
- Live state: `READ_ONLY/DISARMED`
- Real-money trading enabled: `NO`
