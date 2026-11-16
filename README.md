# zkv-gatekeeper-runner

Standalone, isolated runner for **zkVerify Agent Games — Event 01: Proof Gatekeeper**.

## Features

- **Bidirectional raw-body HMAC-SHA256**: verifies `x-agent-games-signature` against raw request bytes before `JSON.parse` (with `AGENT_GAMES_HMAC_SECRET_PREVIOUS` rotation support) and signs every outbound JSON response (including `agent-games.preflight.v1`).
- **Fast preflight**: responds to `agent-games.preflight.v1` with signed `{ ok: true, protocolVersion: "v1" }` in `<50ms`.
- **Official circuit proving**: generates and locally verifies real `Groth16` (`bn128`) proofs using the official `circuits/gatekeeper.wasm` and `circuits/gatekeeper_final.zkey` (`vkHash`: `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`).
- **Idempotency & mode-isolated replay protection**: backed by `node:sqlite` (`DatabaseSync`, WAL mode) checking `(task_id, raw_body_sha256)` cache inside `BEGIN IMMEDIATE` before `(mode, proof_tx)` so network retries never self-trigger `PROOF_REUSED`, and `practice` tasks never contaminate `competition`.
- **Fail-closed trap & deadline enforcement**: rejects `VK_SUBSTITUTION`, `THRESHOLD_MISMATCH`, `EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW`, `PROOF_REUSED`, and malformed/overflow inputs under a 45-second soft deadline.
- **Configurable reason-code profile**: switch between `event_page` (default) and `canonical_rules` via `REASON_CODE_PROFILE` with zero code changes.

## Requirements

- Node.js `v24+` (uses built-in `node:sqlite` and `--experimental-strip-types`)

## Setup

```bash
npm install
cp .env.example .env
# Set AGENT_GAMES_HMAC_SECRET in .env
npm start
```

## Endpoints

- `GET /healthz` — health check and registered `vk_hash`
- `POST /gatekeeper/agent` (and alias `POST /agent`) — signed preflight and task handler

## Verification

```bash
npm run typecheck
npm test
```

## License

MIT — see [LICENSE](LICENSE).
