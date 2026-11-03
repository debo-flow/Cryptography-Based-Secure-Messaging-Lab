# Project Architecture (M30)

## Overview
The `Cryptography-Based-Secure-Messaging-Lab` employs a strict modular separation of concerns. Cryptographic logic is strictly isolated in the `core/` directory, while presentation layers exist exclusively in `app.py` and `ui_components.py`.

## Directory Structure
```text
├── .github/workflows/   # CI/CD pipelines (M28)
├── .streamlit/          # Theming configurations (M29)
├── core/                # Cryptographic Business Logic
│   ├── aes_gcm.py       # AEAD Engines
│   ├── ake.py           # Authenticated Key Exchange
│   ├── benchmark.py     # Statistical Profiling
│   ├── database.py      # SQLite Metadata Store
│   ├── e2ee.py          # Session Management
│   ├── kme.py           # Key Management System (Encrypted at Rest)
│   ├── qr_exchange.py   # Out-of-band Identity Trust
│   ├── security_audit.py# Blue-Team Configuration Auditor
│   ├── testing_engine.py# Subprocess Test Runners
│   └── transmission.py  # Replay-protected Messaging
├── tests/               # Pytest, Hypothesis, and Coverage specs
├── app.py               # Application Entry Point
├── config.py            # Global Roadmap & Nav config
├── requirements.txt     # Locked Dependency Tree
└── README.md
