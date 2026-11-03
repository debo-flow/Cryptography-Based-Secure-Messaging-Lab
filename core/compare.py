"""
Advanced Cryptographic Algorithm Comparison Engine (M25).
Evaluates security properties, benchmarks performance (latency, throughput),
and provides architectural recommendations based on standard best practices.
"""

import time
import json
import io
import csv
import platform
import statistics
from typing import Dict, Any, List

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False

from .randomness import generate_random_bytes
from .encoding import bytes_to_b64
from .aes_gcm import encrypt_aes_gcm, decrypt_aes_gcm
from .chacha20_poly1305 import encrypt_chacha20_poly1305, decrypt_chacha20_poly1305
from .rsa import generate_rsa_key_pair, encrypt_rsa_oaep, decrypt_rsa_oaep
from .ecc import generate_ecc_key_pair
from .ed25519 import generate_ed25519_key_pair, sign_message as sign_ed25519, verify_signature as verify_ed25519
from .signatures import create_advanced_signature_package, validate_advanced_signature_package
from .integrity import calculate_hash
from .hmac_engine import calculate_hmac
from .kdf_engine import derive_key, generate_kdf_salt, KDF_REGISTRY

# =====================================================================
# SECURITY PROPERTIES REGISTRY
# =====================================================================

SECURITY_PROPERTIES = {
    "AES-256-GCM": {
        "Type": "Symmetric AEAD",
        "Confidentiality": "Yes",
        "Integrity": "Yes (GMAC)",
        "Authentication": "Symmetric",
        "Key Size": "256-bit",
        "Nonce/IV": "96-bit (MUST NOT REUSE)",
        "Overhead": "28 bytes (12b Nonce + 16b Tag)",
        "Use Case": "High-speed secure messaging, file encryption, TLS.",
        "Limitations": "Catastrophic failure if nonce is reused under same key."
    },
    "ChaCha20-Poly1305": {
        "Type": "Symmetric AEAD",
        "Confidentiality": "Yes",
        "Integrity": "Yes (Poly1305)",
        "Authentication": "Symmetric",
        "Key Size": "256-bit",
        "Nonce/IV": "96-bit (MUST NOT REUSE)",
        "Overhead": "28 bytes (12b Nonce + 16b Tag)",
        "Use Case": "Mobile/IoT devices lacking AES hardware acceleration.",
        "Limitations": "Nonce reuse completely breaks Poly1305 authenticator."
    },
    "RSA-OAEP-3072": {
        "Type": "Asymmetric KEM/Encryption",
        "Confidentiality": "Yes",
        "Integrity": "Yes (via OAEP Hash)",
        "Authentication": "None (Anyone can encrypt to public key)",
        "Key Size": "3072-bit",
        "Nonce/IV": "N/A (OAEP handles randomness)",
        "Overhead": "Large (Ciphertext = Key Size)",
        "Use Case": "Encrypting small symmetric keys (Key Encapsulation).",
        "Limitations": "Very slow. Cannot encrypt data larger than key size minus padding."
    },
    "Ed25519": {
        "Type": "Digital Signature",
        "Confidentiality": "No",
        "Integrity": "Yes",
        "Authentication": "Asymmetric (Non-Repudiation)",
        "Key Size": "256-bit (32 bytes)",
        "Nonce/IV": "Deterministic (No external RNG needed)",
        "Overhead": "64 bytes (Signature size)",
        "Use Case": "Identity verification, document signing, TLS certificates.",
        "Limitations": "Does not provide confidentiality (encryption)."
    },
    "X25519": {
        "Type": "Key Exchange",
        "Confidentiality": "Facilitates (Yields Shared Secret)",
        "Integrity": "No",
        "Authentication": "No (Requires external signatures like Ed25519)",
        "Key Size": "256-bit (32 bytes)",
        "Nonce/IV": "N/A",
        "Overhead": "32 bytes (Public Share)",
        "Use Case": "Establishing ephemeral session keys (E2EE/TLS 1.3).",
        "Limitations": "Vulnerable to MITM attacks if public keys aren't authenticated."
    },
    "Argon2id": {
        "Type": "Key Derivation Function (KDF)",
        "Confidentiality": "N/A",
        "Integrity": "N/A",
        "Authentication": "N/A",
        "Key Size": "Configurable Output",
        "Nonce/IV": "Requires Salt (16+ bytes)",
        "Overhead": "Memory & CPU constraints",
        "Use Case": "Password hashing, deriving keys from human passwords.",
        "Limitations": "Requires significant RAM to resist GPU/ASIC attacks."
    },
    "HMAC-SHA256": {
        "Type": "Message Authentication Code",
        "Confidentiality": "No",
        "Integrity": "Yes",
        "Authentication": "Symmetric",
        "Key Size": "Variable (256-bit recommended)",
        "Nonce/IV": "N/A",
        "Overhead": "32 bytes (Tag size)",
        "Use Case": "API authentication, payload integrity where keys are shared.",
        "Limitations": "Lacks non-repudiation. Either party can forge tags."
    }
}

# =====================================================================
# RECOMMENDATION ENGINE
# =====================================================================

def get_algorithm_recommendations(use_case: str) -> Dict[str, str]:
    """Provides cryptographic architectural recommendations based on use cases."""
    recommendations = {
        "Secure Messaging (E2EE)": {
            "Recommendation": "X25519 (Key Exchange) + Ed25519 (Identity Auth) + HKDF-SHA256 (KDF) + AES-256-GCM / ChaCha20-Poly1305 (Bulk Enc)",
            "Reasoning": "Provides Perfect Forward Secrecy (PFS), strong identity binding preventing MITM, and high-speed authenticated bulk encryption.",
            "Limitations": "Requires complex state management for message sequencing and key rotation."
        },
        "File Encryption (At Rest)": {
            "Recommendation": "AES-256-GCM or ChaCha20-Poly1305 with random 256-bit DEK.",
            "Reasoning": "AEAD ensures the file isn't tampered with. Symmetric encryption handles large payloads instantly.",
            "Limitations": "In-memory AEAD is constrained by available RAM. Massive files require specialized chunked AEAD constructions."
        },
        "Password-Based Encryption": {
            "Recommendation": "Argon2id (Memory-Hard KDF) -> AES-256-GCM",
            "Reasoning": "Argon2id defeats GPU/ASIC offline brute-force attacks by requiring massive RAM allocation.",
            "Limitations": "Slow derivation impacts user experience if tuned too high."
        },
        "Digital Document Signing": {
            "Recommendation": "Ed25519 or RSA-PSS (SHA-256/384/512)",
            "Reasoning": "Provides mathematically undeniable non-repudiation. Ed25519 is preferred for small size and speed.",
            "Limitations": "Signatures prove key possession, not real-world identity without a trusted PKI/OOB fingerprint check."
        },
        "Data Integrity (No Secrets)": {
            "Recommendation": "SHA-256, SHA-384, or SHA3-256",
            "Reasoning": "Provides strict collision resistance to detect accidental file corruption.",
            "Limitations": "Easily bypassed by malicious actors unless the hash itself is distributed over a trusted channel."
        }
    }
    return recommendations.get(use_case, {"Recommendation": "Unknown", "Reasoning": "N/A", "Limitations": "N/A"})

# =====================================================================
# BENCHMARK ENGINE
# =====================================================================

def get_environment_info() -> Dict[str, str]:
    """Collects safe, non-sensitive environment metadata for benchmark context."""
    info = {
        "OS": platform.system() + " " + platform.release(),
        "Architecture": platform.machine(),
        "Python Version": platform.python_version(),
        "Timestamp": datetime.now(timezone.utc).isoformat()
    }
    if PSUTIL_AVAILABLE:
        info["CPU Cores (Logical)"] = str(psutil.cpu_count(logical=True))
        info["Total Memory (GB)"] = f"{psutil.virtual_memory().total / (1024**3):.2f}"
    return info

def benchmark_symmetric(algo: str, payload_sizes_kb: List[int], iterations: int = 10) -> List[Dict[str, Any]]:
    """Benchmarks AES-GCM and ChaCha20-Poly1305 across different payload sizes."""
    key = generate_random_bytes(32)
    results = []
    
    for size_kb in payload_sizes_kb:
        payload = generate_random_bytes(size_kb * 1024)
        enc_times, dec_times = [], []
        
        # Warm-up
        for _ in range(2):
            if algo == "AES-256-GCM": encrypt_aes_gcm(key, payload)
            else: encrypt_chacha20_poly1305(key, payload)
            
        for _ in range(iterations):
            # Encrypt
            t0 = time.perf_counter()
            if algo == "AES-256-GCM": 
                pkg = encrypt_aes_gcm(key, payload)
            else: 
                pkg = encrypt_chacha20_poly1305(key, payload)
            t1 = time.perf_counter()
            enc_times.append(t1 - t0)
            
            # Decrypt
            t2 = time.perf_counter()
            if algo == "AES-256-GCM": 
                decrypt_aes_gcm(key, json.dumps(pkg))
            else: 
                decrypt_chacha20_poly1305(key, json.dumps(pkg))
            t3 = time.perf_counter()
            dec_times.append(t3 - t2)
            
        enc_mean = statistics.mean(enc_times)
        dec_mean = statistics.mean(dec_times)
        throughput_mb_s = (size_kb / 1024) / enc_mean
        
        results.append({
            "Algorithm": algo,
            "Payload Size (KB)": size_kb,
            "Mean Encrypt (ms)": round(enc_mean * 1000, 3),
            "Mean Decrypt (ms)": round(dec_mean * 1000, 3),
            "Throughput (MB/s)": round(throughput_mb_s, 2)
        })
        
    return results

def benchmark_signatures(iterations: int = 10) -> List[Dict[str, Any]]:
    """Benchmarks Signature generation and verification (RSA vs ECC)."""
    results = []
    msg = "Standard benchmark payload for digital signatures."
    
    algos = [
        ("RSA-PSS 2048", lambda: generate_rsa_key_pair(2048), "RSA-PSS", "SHA-256"),
        ("RSA-PSS 3072", lambda: generate_rsa_key_pair(3072), "RSA-PSS", "SHA-256"),
        ("ECDSA P-256", lambda: generate_ecc_key_pair("SECP256R1"), "ECDSA", "SHA-256"),
        ("Ed25519", generate_ed25519_key_pair, "Ed25519", "SHA-256")
    ]
    
    for label, gen_func, algo, hash_alg in algos:
        # KeyGen Benchmark
        kg_times, sign_times, ver_times = [], [], []
        
        for _ in range(iterations):
            t0 = time.perf_counter()
            priv, pub = gen_func()
            t1 = time.perf_counter()
            kg_times.append(t1 - t0)
            
            t2 = time.perf_counter()
            pkg = create_advanced_signature_package(priv, msg, algo, hash_alg)
            t3 = time.perf_counter()
            sign_times.append(t3 - t2)
            
            t4 = time.perf_counter()
            validate_advanced_signature_package(pub, json.dumps(pkg))
            t5 = time.perf_counter()
            ver_times.append(t5 - t4)
            
        results.append({
            "Algorithm": label,
            "Mean KeyGen (ms)": round(statistics.mean(kg_times) * 1000, 3),
            "Mean Sign (ms)": round(statistics.mean(sign_times) * 1000, 3),
            "Mean Verify (ms)": round(statistics.mean(ver_times) * 1000, 3)
        })
        
    return results

# =====================================================================
# REPORT GENERATORS
# =====================================================================

def generate_csv_report(env_info: dict, sym_results: list, sig_results: list) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(["### ENVIRONMENT METADATA ###"])
    for k, v in env_info.items():
        writer.writerow([k, v])
        
    writer.writerow([])
    writer.writerow(["### SYMMETRIC BENCHMARKS ###"])
    if sym_results:
        writer.writerow(list(sym_results[0].keys()))
        for r in sym_results: writer.writerow(list(r.values()))
        
    writer.writerow([])
    writer.writerow(["### ASYMMETRIC SIGNATURE BENCHMARKS ###"])
    if sig_results:
        writer.writerow(list(sig_results[0].keys()))
        for r in sig_results: writer.writerow(list(r.values()))
        
    return output.getvalue()

def generate_pdf_report(env_info: dict, sym_results: list, sig_results: list) -> bytes:
    if not FPDF_AVAILABLE:
        raise CryptographicOperationError("fpdf2 library not installed. PDF generation unavailable.")
        
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    pdf.cell(200, 10, txt="Cryptographic Algorithm Comparison Report (M25)", ln=True, align='C')
    pdf.ln(10)
    
    pdf.set_font("Arial", style='B', size=10)
    pdf.cell(200, 10, txt="Environment Metadata:", ln=True)
    pdf.set_font("Arial", size=10)
    for k, v in env_info.items():
        pdf.cell(200, 8, txt=f"{k}: {v}", ln=True)
        
    pdf.ln(5)
    pdf.set_font("Arial", style='B', size=10)
    pdf.cell(200, 10, txt="Symmetric AEAD Benchmarks:", ln=True)
    pdf.set_font("Arial", size=9)
    for r in sym_results:
        pdf.cell(200, 6, txt=str(r), ln=True)
        
    pdf.ln(5)
    pdf.set_font("Arial", style='B', size=10)
    pdf.cell(200, 10, txt="Signature Benchmarks:", ln=True)
    pdf.set_font("Arial", size=9)
    for r in sig_results:
        pdf.cell(200, 6, txt=str(r), ln=True)
        
    pdf.ln(10)
    pdf.set_font("Arial", style='I', size=8)
    pdf.cell(200, 10, txt="Generated by Cryptography-Based-Secure-Messaging-Lab (M25)", ln=True)
    
    return bytes(pdf.output(dest='S'))
