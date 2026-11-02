"""
Configuration Data Layer for the Cryptography-Based Secure Messaging Laboratory.
Contains milestone definitions, navigation state, and project metadata.
"""

from typing import Dict, List, Any

# Project Header & Metadata
PROJECT_INFO = {
    "name": "Cryptography-Based Secure Messaging Laboratory",
    "version": "1.0.0-M01",
    "description": "A professional, extensible, research-oriented Cryptography & Secure Messaging Laboratory.",
    "status": "Development - Milestone 1",
    "identity": "Cybersecurity Research Lab"
}

# 35-Milestone Development Plan
ROADMAP: List[Dict[str, Any]] = [
    {"id": "M01", "title": "Project Foundation & Core Architecture", "status": "Completed"},
    {"id": "M02", "title": "Cryptographic Core Engine", "status": "Pending"},
    {"id": "M03", "title": "AES Encryption", "status": "Pending"},
    {"id": "M04", "title": "AES-256-GCM", "status": "Pending"},
    {"id": "M05", "title": "RSA Encryption", "status": "Pending"},
    {"id": "M06", "title": "RSA-OAEP", "status": "Pending"},
    {"id": "M07", "title": "ChaCha20 Encryption", "status": "Pending"},
    {"id": "M08", "title": "ChaCha20-Poly1305", "status": "Pending"},
    {"id": "M09", "title": "Fernet Encryption", "status": "Pending"},
    {"id": "M10", "title": "Hybrid Encryption", "status": "Pending"},
    {"id": "M11", "title": "Public-Key Cryptography", "status": "Pending"},
    {"id": "M12", "title": "X25519 Key Exchange", "status": "Pending"},
    {"id": "M13", "title": "Password-Based Encryption", "status": "Pending"},
    {"id": "M14", "title": "PBKDF2, Scrypt & Argon2id", "status": "Pending"},
    {"id": "M15", "title": "Digital Signature System", "status": "Pending"},
    {"id": "M16", "title": "RSA-PSS & Ed25519", "status": "Pending"},
    {"id": "M17", "title": "Message Authentication", "status": "Pending"},
    {"id": "M18", "title": "End-to-End Messaging Foundation", "status": "Pending"},
    {"id": "M19", "title": "Secure Key Exchange", "status": "Pending"},
    {"id": "M20", "title": "Secure Message Transmission", "status": "Pending"},
    {"id": "M21", "title": "Secure File Encryption", "status": "Pending"},
    {"id": "M22", "title": "Cryptographic Key Manager", "status": "Pending"},
    {"id": "M23", "title": "QR-Based Public-Key Exchange", "status": "Pending"},
    {"id": "M24", "title": "Message Integrity Analyzer", "status": "Pending"},
    {"id": "M25", "title": "Algorithm Comparison Laboratory", "status": "Pending"},
    {"id": "M26", "title": "Cryptographic Benchmarking", "status": "Pending"},
    {"id": "M27", "title": "Security Analysis Dashboard", "status": "Pending"},
    {"id": "M28", "title": "Automated Testing & Validation", "status": "Pending"},
    {"id": "M29", "title": "UI/UX Optimization", "status": "Pending"},
    {"id": "M30", "title": "Final Integration & Documentation", "status": "Pending"},
    {"id": "M31", "title": "Advanced E2EE Architecture", "status": "Pending"},
    {"id": "M32", "title": "Forward Secrecy", "status": "Pending"},
    {"id": "M33", "title": "Key Rotation & Lifecycle Management", "status": "Pending"},
    {"id": "M34", "title": "Security Auditing", "status": "Pending"},
    {"id": "M35", "title": "Final System Integration & Release", "status": "Pending"}
]

# Navigation System
NAVIGATION = [
    "Dashboard",
    "Encryption Laboratory",
    "AES Encryption",
    "RSA Encryption",
    "ChaCha20 Encryption",
    "Fernet Encryption",
    "Hybrid Encryption",
    "Public-Key Cryptography",
    "Password-Based Encryption",
    "End-to-End Messaging",
    "Digital Signatures",
    "Secure File Encryption",
    "Key Management",
    "Message Authentication",
    "Algorithm Comparison",
    "Performance Benchmark",
    "Security Analysis",
    "Project Roadmap",
    "About Project"
]

# Computed Statistics
TOTAL_MILESTONES = len(ROADMAP)
COMPLETED_MILESTONES = len([m for m in ROADMAP if m["status"] == "Completed"])
REMAINING_MILESTONES = TOTAL_MILESTONES - COMPLETED_MILESTONES
