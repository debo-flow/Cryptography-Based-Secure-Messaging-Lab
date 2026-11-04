"""
Configuration Data Layer for the Cryptography-Based Secure Messaging Laboratory.
Final Release Version (v1.0.0).
"""
from typing import Dict, List, Any

PROJECT_INFO = {
    "name": "Cryptography-Based Secure Messaging Laboratory",
    "version": "1.0.0-RELEASE",
    "description": "A professional, extensible, educational Cryptography & Secure Messaging Laboratory.",
    "status": "Production Release - All 35 Milestones Completed",
    "identity": "Cybersecurity Research Lab"
}

ROADMAP: List[Dict[str, Any]] = [
    {"id": "M01-M17", "title": "Cryptographic Primitives & Core Algorithms", "status": "Completed"},
    {"id": "M18-M21", "title": "Secure Messaging & File Encryption", "status": "Completed"},
    {"id": "M22-M23", "title": "Key Management & Identity Exchange", "status": "Completed"},
    {"id": "M24-M28", "title": "Integrity, Benchmarking & Testing", "status": "Completed"},
    {"id": "M29-M30", "title": "UI/UX & Final Integration Architecture", "status": "Completed"},
    {"id": "M31", "title": "Advanced E2EE Architecture (V2.0)", "status": "Completed"},
    {"id": "M32", "title": "Forward Secrecy & Cryptographic Ratchet", "status": "Completed"},
    {"id": "M33", "title": "Key Rotation & Lifecycle Management", "status": "Completed"},
    {"id": "M34", "title": "Advanced Cryptographic Security Auditing", "status": "Completed"},
    {"id": "M35", "title": "System Integration & V1.0.0 Release", "status": "Completed"}
]

NAVIGATION_CATEGORIES = {
    "PROJECT": [
        "Dashboard", "Project Roadmap", "Application Settings"
    ],
    "CORE CRYPTOGRAPHY": [
        "Cryptographic Core Engine", "AES Encryption", "AES-GCM Encryption", 
        "Advanced RSA-OAEP", "ChaCha20 Encryption", "ChaCha20-Poly1305", 
        "Fernet Encryption", "Hybrid Encryption"
    ],
    "KEY MANAGEMENT": [
        "Public-Key Cryptography", "X25519 Key Exchange", "Password-Based Encryption", 
        "Advanced KDF Laboratory", "Key Management (M22)", "QR Identity Exchange (M23)",
        "Advanced Key Lifecycle (M33)"
    ],
    "AUTHENTICATION": [
        "Advanced Signatures (M16)", "Message Authentication (HMAC)", "Integrity Analyzer (M24)"
    ],
    "SECURE MESSAGING": [
        "Authenticated E2EE (M19)", "Secure Transmission (M20)", "Secure File Encryption (M21)",
        "Advanced E2EE Architecture (M31)", "Ratchet & Forward Secrecy (M32)"
    ],
    "ANALYSIS & BENCHMARKING": [
        "Algorithm Comparison (M25)", "Advanced Benchmark Lab (M26)", 
        "Test & Validation Lab (M28)", "Adv. Security Audit Center (M34)"
    ]
}

TOTAL_MILESTONES = len(ROADMAP)
COMPLETED_MILESTONES = len([m for m in ROADMAP if m["status"] == "Completed"])
REMAINING_MILESTONES = TOTAL_MILESTONES - COMPLETED_MILESTONES
