# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] - 2024-05-30
### Added
- **Final Integration (M35):** Consolidated all 34 prior milestones into a single, cohesive architecture.
- **Continuous Integration (CI):** Added GitHub Actions workflows enforcing Pytest coverage, `ruff` linting, `bandit` static analysis, and `pip-audit` dependency checks.
- **Automated Validation:** New `test_integration_v1.py` proves unbroken End-to-End flow spanning KMS, Lifecycles, E2EE, Ratchets, and Auditing.
- **Security Documentation:** Introduced `SECURITY.md` to explicitly define the educational scope and limitations of the project.
- **Performance Optimization:** Implemented `st.cache_resource` in the UI to prevent expensive SQLite re-instantiations.

### Changed
- Configured all dependencies to strictly pinned versions in `requirements.txt` to prevent future upstream supply chain breaks.

### Security
- Verified that all cryptographic operations rely exclusively on the vetted `cryptography` library primitives.
- Confirmed SQLite schemas never store plaintext session keys, message keys, or chain keys.
