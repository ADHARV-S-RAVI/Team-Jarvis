# Q-SHIELD — Known Limitations

1. **Local Key Storage (No HSM/KMS):** `master_kek.key` and `key_versions.json` are stored on the local filesystem (`.qshield_keys/` or `QSHIELD_KEY_STORE_DIR`). Host root/disk compromise exposes the KEK.
2. **Simulated Distributed Nodes:** The 3–7 node cluster (`sim-node-1`..`sim-node-7`) is an **in-process simulator** backed by SQLite tables (`simulated_nodes`, `node_acknowledgements`), not physical distributed servers or real network sockets.
3. **ML-DSA Not Implemented:** Post-quantum digital signatures (ML-DSA) are **NOT IMPLEMENTED**. Integrity and authentication rely on HMAC-SHA-256 and AES-256-GCM.
4. **Forward Secrecy Not Established:** Messaging uses AEAD with session/KEK-derived keys without a per-message ephemeral DH/KEM ratchet; therefore `/api/v1/messages/security-status` truthfully reports `NOT_ESTABLISHED`.
5. **Detector Dataset Scope:** Deterministic rules achieved `F1=1.0` (`TP=5, FP=0, FN=0`) on the `22`-event labelled practice dataset (`tools/Track-4-Toolkit/practice/`). This validates deterministic rule logic on synthetic fixtures and **does not** establish production detection accuracy.
6. **Code Coverage Not Measured:** `pytest-cov` was not run; test completeness is evidenced by `46/46` backend tests, `9/9` adapter tests, `4/4` frontend tests, and `21/21` official validator checks.
7. **Single-Process / SQLite Concurrency:** SQLite WAL mode supports local concurrency, but multi-host high-throughput deployment is outside current scope.
