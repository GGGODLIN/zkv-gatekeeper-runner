# zkv-gatekeeper-runner

Standalone `Event 01: Proof Gatekeeper` HTTP agent runner for `zkVerify Agent Games`, strictly isolated from [`GGGODLIN/reserverail`](https://github.com/GGGODLIN/reserverail) so `Event 01` qualification tasks never share HMAC keys, routes, or SQLite replay state with the `Wildcard` treasury rail.

## Capabilities

- **Pre-JSON Raw-Body `HMAC-SHA256`**: Verifies inbound `x-agent-games-signature` over exact raw request bytes before parsing JSON and signs all outbound JSON responses (including `<50ms` `agent-games.preflight.v1` handshakes).
- **7-Rule Deterministic Gatekeeper Engine + Real `Groth16` Proving**: Evaluates `VK_SUBSTITUTION`, `THRESHOLD_MISMATCH`, `(mode, proof_tx)` scoped `PROOF_REUSED`, strict `current_block < expiry_block`, `RECIPIENT_MISMATCH`, and `AMOUNT_OVERFLOW`, then generates and locally verifies real `Groth16` proofs against the official `gatekeeper.wasm` (`vkHash = 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`).
- **Practice vs. Competition Replay Isolation**: Keys replay tracking by `(mode, proof_tx)` in `node:sqlite` (`BEGIN IMMEDIATE`) and checks `(task_id, raw_body_sha256)` idempotency before replay rejection so platform network retries replay cached signed responses cleanly.

## Run & Test

Requires **Node.js `>= 24.0.0`**.

```bash
npm ci
npm test
AGENT_GAMES_HMAC_SECRET="<per-agent-secret>" PORT=3411 npm start
```

## License

MIT — see [/LICENSE](/LICENSE).
