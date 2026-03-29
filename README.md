# ⚡ zk-Smart-Meter: Privacy-Preserving Energy Grid Verification

A production-simulated Zero-Knowledge proof protocol built in Rust using the Arkworks ecosystem. This system allows a Smart Meter to mathematically prove to an Energy Grid operator that its monthly power usage is below a policy threshold, **without ever revealing the actual energy consumption.**

## 🧠 Protocol Architecture & Mathematics

This system utilizes **Groth16** SNARKs over the **BLS12-381** pairing-friendly elliptic curve, combined with embedded **Jubjub** curve Pedersen Commitments.

### 1. Identity & Data Hiding (Native Execution)

Upon boot, the Smart Meter generates a random private key ($pk$) and a random blinder ($r$). It creates a cryptographic Pedersen Commitment of its true measurement ($M$):

$$C = [pk]G + [M]H + [r]F$$

_(Where $G, H, F$ are orthogonal generator points on the Jubjub curve)._

### 2. Circuit Constraints (R1CS Matrix)

The SNARK circuit enforces the following arithmetic logic:

- **Commitment Integrity:** Computes the elliptic curve scalar multiplication inside the circuit to ensure the private inputs natively hash to the public $C_{data}$ input.
- **Range Proof:** Enforces $M < T$ (where $T$ is the Grid's public policy threshold).

### 3. The API Boundary (Network Transit)

The generated proof is serialized into a highly compressed, 192-byte array and transmitted to the Grid, simulating a real-world microservice architecture.

### 4. Verification & Cryptographic Firewall

The Verifier checks that $C_{data}$ is a valid Jubjub curve point and resides in the correct prime subgroup (preventing Small Subgroup Attacks) _before_ executing the Groth16 pairing check.

---

## 🚀 Key Features

- **Network Serialization:** Full serialization/deserialization pipeline simulating an API transit layer.
- **Man-in-the-Middle (MITM) Demo:** Built-in attack simulation that dynamically intercepts and mutates network payloads to demonstrate cryptographic soundness.
- **Pre-Flight Ghost Matrix:** Debuggable constraint generation that catches invalid logic _before_ expensive proof generation.
- **Cryptographic Firewall:** Active public input validation against malicious curve geometries.
- **Custom Error Routing:** Idiomatic Rust `Result` handling with a custom `SmartMeterError` enum (zero `.unwrap()` panics in the execution flow).
- **Property-Based Testing:** An 8-part cryptographic gauntlet testing honest setups, fraudulent setups, boundary conditions ($M = T$), field overflows ($M = \text{u64::MAX}$), blinder forgeries, and serialization roundtrips.

---

## ⚠️ Security Assumptions & Limitations (Not for Production)

**1. Trusted Setup (Toxic Waste)**
This repository utilizes a **Single-Party Setup** (`Groth16::circuit_specific_setup`). This generates "toxic waste" parameters ($\tau, \alpha, \beta, \gamma, \delta$). If this were deployed to production, the party who ran the setup could forge proofs.
_Fix for Prod:_ Implement a multi-party computation (MPC) setup like the _Perpetual Powers of Tau_, or migrate to a transparent/universal SNARK like Halo2 or Plonk.

**2. Network Replay Attacks**
Currently, the protocol does not implement a cryptographic `nonce` or timestamp. A malicious user could capture a valid proof payload and resend it the next month.
_Fix for Prod:_ Inject the current month/year epoch as a public input constraint.

---

## 📊 Benchmarks & Gas Estimations

_Tested on standard consumer hardware._

| Metric          | Value             |
| --------------- | ----------------- |
| **Constraints** | ~14,500 R1CS Rows |
| **Prove Time**  | ~1.5 - 3.5s       |
| **Proof Size**  | 192 bytes         |
| **Verify Time** | < 15ms            |

**Ethereum On-Chain Verification Cost:**

- Groth16 Verify (3 Pairings): ~250,000 Gas
- Public Input Calldata: ~2,000 Gas
- **Total Estimate:** ~252,000 Gas per proof verification (~$50 at 200 gwei).
- _Note: Production deployments should utilize L2 rollups (Arbitrum/Optimism) or proof batching to reduce verification costs to <$0.50._

---

## 💻 Usage

**1. Standard Run (Honest & Fraudulent Meters):**
Executes the standard Prover-to-Verifier pipeline.

```bash
cargo run --release
```
