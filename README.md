# FedCloud — Formal Verification Gateway for Federal Cloud Authorizations

[![CI](https://github.com/j-arndt/fedcloud/actions/workflows/ci.yml/badge.svg)](https://github.com/j-arndt/fedcloud/actions/workflows/ci.yml)
[![Lean 4](https://img.shields.io/badge/Lean-4.28.0-blue)](https://lean-lang.org/)
[![OSCAL](https://img.shields.io/badge/OSCAL-1.1.2-green)](https://pages.nist.gov/OSCAL/)
[![Python](https://img.shields.io/badge/Python-3.10+-yellow)](https://python.org/)

**Replace compliance narratives with mathematical proofs.**

FedCloud automates continuous compliance verification by converting live infrastructure state into mathematical types and evaluating them against formal invariant theorems using the [Lean 4](https://lean-lang.org/) interactive theorem prover. Instead of periodic manual assessments, the system provides deterministic, cryptographically signed proof artifacts in [OSCAL](https://pages.nist.gov/OSCAL/) format.

---

## Architecture

```
┌────────────────────────┐      ┌────────────────────────┐      ┌────────────────────────┐
│  1. State Ingestion    │      │    2. Translation      │      │    3. Lean 4 Kernel    │
│  AWS CloudTrail/Config │ ───> │  Python AST Parser     │ ───> │   Verification Engine  │
│  App Schemas           │      │  (JSON → Lean Types)   │      │  (Invariant Proofs)    │
└────────────────────────┘      └────────────────────────┘      └───────────┬────────────┘
                                                                            │
                                                                            ▼
┌────────────────────────┐      ┌────────────────────────┐      ┌────────────────────────┐
│  6. Federal Gateway    │      │  5. Trust Center API   │      │ 4. Verification Output │
│  Continuous            │ <─── │   OSCAL Repository     │ <─── │ Cryptographic Signed   │
│  Authorization (ConMon)│      │   (SSP + AR)           │      │ JSON Receipt Artifact  │
└────────────────────────┘      └────────────────────────┘      └────────────────────────┘
```

## Security Clusters

The gateway enforces four deterministic invariant theorems:

| Cluster | Invariant | Controls |
|---------|-----------|----------|
| **Identity & Access** | Privileged sessions require phishing-resistant MFA; tokens ≤ 60 min | AC-2, AC-3, AC-6, IA-2, IA-5 |
| **Cryptographic Protection** | Federal data encrypted at rest with FIPS-140-3 modules | SC-8, SC-12, SC-13, SC-28 |
| **Architecture Immutability** | Signed images only; no shell access; no open ingress | CM-2, CM-6, CM-7, SC-7, SI-7 |
| **Continuous Monitoring** | Active logging to tamper-evident targets; ≥ 365-day retention | AU-2, AU-6, AU-9, AU-11, SI-4 |

Each invariant is expressed as a formal Lean 4 theorem with a corresponding decision procedure that produces concrete verification results.

## Quick Start

### Prerequisites

- Python 3.10+
- [Lean 4](https://lean-lang.org/lean4/doc/setup.html) (for proof compilation)

### Run the Pipeline (Mock Mode)

```bash
# Clone the repository
git clone https://github.com/j-arndt/fedcloud.git
cd fedcloud

# Run all tests
python -m pytest translator/tests/ oscal/tests/ -v

# Execute the full pipeline against mock fixtures
python -m scripts.run_pipeline --mode mock --state fixtures/mock_aws_topology.json

# View output artifacts
ls output/
# → SystemState.lean  verification_receipt.json  fedcloud_ssp.json  assessment_results.json
```

### Build the Lean 4 Verification Engine

```bash
cd lean

# Install Lean via elan
curl https://elan.lean-lang.org/install/linux -sSf | sh

# Build the verification library
lake build

# Run proof checker against sample states
lean FedCloud/Verify.lean
```

### Docker

```bash
docker build -t fedcloud-gateway .
docker run -v $(pwd)/fixtures:/data fedcloud-gateway /data/mock_aws_topology.json
```

## Project Structure

```
fedcloud/
├── lean/                          # Lean 4 formal verification engine
│   ├── lakefile.lean              # Lake build configuration
│   ├── lean-toolchain             # Lean version pin (v4.28.0)
│   └── FedCloud/
│       ├── BaseModel.lean         # Core type definitions
│       ├── Verify.lean            # Orchestrator + sample states
│       └── Invariants/
│           ├── Identity.lean      # IAM cluster invariant
│           ├── Crypto.lean        # Cryptographic protection invariant
│           ├── Architecture.lean  # Immutability invariant
│           └── Monitoring.lean    # Continuous monitoring invariant
├── translator/                    # JSON → Lean translation layer
│   ├── json_to_lean.py            # Multi-format state translator
│   ├── state_ingestion.py         # State collection service
│   └── tests/
│       └── test_translator.py     # Translator unit tests
├── oscal/                         # OSCAL synthesis pipeline
│   ├── receipt_generator.py       # Signed verification receipts
│   ├── ssp_updater.py             # SSP component injection
│   ├── assessment_results.py      # OSCAL Assessment Results
│   ├── templates/
│   │   └── fedramp_moderate_ssp.json  # Baseline SSP template
│   └── tests/
│       └── test_pipeline.py       # Pipeline integration tests
├── fixtures/                      # Mock telemetry data
│   ├── mock_aws_topology.json     # Sample AWS infrastructure state
│   ├── mock_terraform_plan.json   # Sample Terraform plan
│   └── mock_tyler_app_schema.json # Sample application metadata
├── scripts/
│   └── run_pipeline.py            # Pipeline orchestrator
├── docs/                          # HTML documentation
├── .github/workflows/ci.yml       # GitHub Actions CI
├── Dockerfile                     # Container build
└── README.md
```

## How It Works

### 1. State Ingestion

Infrastructure state is collected from AWS Config, CloudTrail, EventBridge, and application APIs. In PoC mode, mock fixtures simulate these sources.

### 2. Translation

The `json_to_lean.py` translator converts JSON payloads into typed Lean 4 definitions. It handles multiple input formats (raw state, Terraform plans, application schemas) and normalizes them into the `SystemState` structure.

### 3. Formal Verification

The Lean 4 kernel compiles the translated state alongside the invariant theorem library. If all proofs hold, the system is mathematically verified. If any invariant fails, the specific violation is identified.

### 4. Receipt Generation

A cryptographically signed (HMAC-SHA256) JSON receipt captures the verification result, input state hash, timestamp, and per-cluster status.

### 5. OSCAL Synthesis

The receipt is injected into an OSCAL SSP, updating component definitions with verification metadata. A separate OSCAL Assessment Results document is generated with findings mapped to control families.

## Verification Guarantees

Unlike scan-based compliance tools, this system provides:

- **Determinism**: Same input always produces same verification result
- **Completeness**: Every in-scope resource is checked against every applicable invariant
- **Tamper Evidence**: Receipts are cryptographically signed with input state hashes
- **Auditability**: The Lean 4 proof logic is inspectable and verifiable by third parties

## License

MIT
