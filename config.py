"""
Configuration Data Layer for the Cryptography-Based Secure Messaging Laboratory.
Final Release Version (M30).
"""
from typing import Dict, List, Any

PROJECT_INFO = {
    "name": "Cryptography-Based Secure Messaging Laboratory",
    "version": "1.30.0-RELEASE",
    "description": "A professional, extensible, research-oriented Cryptography & Secure Messaging Laboratory.",
    "status": "Production Release - Milestone 30 Completed",
    "identity": "Cybersecurity Research Lab"
}

ROADMAP: List[Dict[str, Any]] = [
    {"id": "M01", "title": "Project Foundation & Core Architecture", "status": "Completed"},
    {"id": "M02", "title": "Cryptographic Core Engine", "status": "Completed"},
    {"id": "M03", "title": "AES Encryption", "status": "Completed"},
    {"id": "M04", "title": "AES-256-GCM", "status": "Completed"},
    {"id": "M05", "title": "RSA Encryption", "status": "Completed"},
    {"id": "M06", "title": "RSA-OAEP", "status": "Completed"},
    {"id": "M07", "title": "ChaCha20 Encryption", "status": "Completed"},
    {"id": "M08", "title": "ChaCha20-Poly1305", "status": "Completed"},
    {"id": "M09", "title": "Fernet Encryption", "status": "Completed"},
    {"id": "M10", "title": "Hybrid Encryption", "status": "Completed"},
    {"id": "M11", "title": "Public-Key Cryptography", "status": "Completed"},
    {"id": "M12", "title": "X25519 Key Exchange", "status": "Completed"},
    {"id": "M13", "title": "Password-Based Encryption", "status": "Completed"},
    {"id": "M14", "title": "PBKDF2, Scrypt & Argon2id", "status": "Completed"},
    {"id": "M15", "title": "Digital Signature System", "status": "Completed"},
    {"id": "M16", "title": "RSA-PSS & Ed25519", "status": "Completed"},
    {"id": "M17", "title": "Message Authentication", "status": "Completed"},
    {"id": "M18", "title": "End-to-End Messaging Foundation", "status": "Completed"},
    {"id": "M19", "title": "Secure Key Exchange & Identity Auth", "status": "Completed"},
    {"id": "M20", "title": "Secure Message Transmission", "status": "Completed"},
    {"id": "M21", "title": "Advanced Secure File Encryption", "status": "Completed"},
    {"id": "M22", "title": "Cryptographic Key Management", "status": "Completed"},
    {"id": "M23", "title": "QR-Based Public-Key Exchange", "status": "Completed"},
    {"id": "M24", "title": "Message Integrity Analyzer", "status": "Completed"},
    {"id": "M25", "title": "Algorithm Comparison Laboratory", "status": "Completed"},
    {"id": "M26", "title": "Cryptographic Benchmarking", "status": "Completed"},
    {"id": "M27", "title": "Security Analysis Dashboard", "status": "Completed"},
    {"id": "M28", "title": "Automated Testing & Validation", "status": "Completed"},
    {"id": "M29", "title": "UI/UX Optimization & Design System", "status": "Completed"},
    {"id": "M30", "title": "Final Integration & Documentation", "status": "Completed"}
]

# Advanced Categorized Navigation System
NAVIGATION_CATEGORIES = {
    "PROJECT": [
        "Dashboard", "Application Settings", "Project Roadmap"
    ],
    "CORE CRYPTOGRAPHY": [
        "Cryptographic Core Engine", "AES Encryption", "AES-GCM Encryption", 
        "Advanced RSA-OAEP", "ChaCha20 Encryption", "ChaCha20-Poly1305", 
        "Fernet Encryption", "Hybrid Encryption"
    ],
    "KEY MANAGEMENT": [
        "Public-Key Cryptography", "X25519 Key Exchange", "Password-Based Encryption", 
        "Advanced KDF Laboratory", "Key Management (M22)", "QR Identity Exchange (M23)"
    ],
    "AUTHENTICATION": [
        "Advanced Signatures (M16)", "Message Authentication (HMAC)", "Integrity Analyzer (M24)"
    ],
    "SECURE MESSAGING": [
        "Authenticated E2EE (M19)", "Secure Transmission (M20)", "Secure File Encryption (M21)"
    ],
    "ANALYSIS & BENCHMARKING": [
        "Algorithm Comparison (M25)", "Advanced Benchmark Lab (M26)", 
        "Security Dashboard (M27)", "Test & Validation Lab (M28)"
    ]
}

TOTAL_MILESTONES = len(ROADMAP)
COMPLETED_MILESTONES = len([m for m in ROADMAP if m["status"] == "Completed"])
REMAINING_MILESTONES = TOTAL_MILESTONES - COMPLETED_MILESTONES
