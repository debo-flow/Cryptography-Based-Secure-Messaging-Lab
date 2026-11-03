# Testing & Validation Strategy

This project employs a comprehensive, multi-layered testing strategy (implemented in Milestone 28) to mathematically prove the integrity and stability of the entire cryptographic laboratory.

## 1. Testing Categories

### Known-Answer Tests (KAT)
Found in `tests/test_kat.py`. These tests validate our cryptographic wrapper implementations against strict NIST and RFC specifications. 
- Verifies exact output matches for algorithms like SHA-256 and HMAC-SHA256 using official test vectors.

### Property-Based Fuzzing
Found in `tests/test_properties.py`. We utilize the `Hypothesis` library to generate massive, randomized permutations of inputs.
- Tests dynamic bounds, malicious JSON rejection, and unicode AEAD round-trip guarantees.
- Ensures the system handles malformed data gracefully without crashing or exposing secrets.

### Integration & End-to-End (E2E) Testing
Found across the `tests/` directory (e.g., `test_integration.py`).
- Validates the end-to-end flow: `Identity Generation -> AKE -> Transmission -> Analysis`.
- Ensures all Milestones (M1-M30) interact with each other seamlessly and maintain backward compatibility.

### UI & Subprocess Testing
Found in `tests/test_ui.py`. 
- Validates Streamlit component rendering, status badge color mapping, and headless application startup to ensure no UI-level regressions occur.

## 2. Test Execution

### Running Tests Locally (CLI)
To run the full test suite with coverage analysis, execute the following command in your terminal:

```bash
pytest tests/ -v --cov=core
