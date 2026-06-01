# HAEPD Forensic Suite Pro (V8.16)

An advanced, multi-modal Digital Forensics application engineered to intercept email phishing and social engineering threat vectors through parallel multi-engine triage.

## 🚀 Key Features
* **Anurag Engine (Contextual AI):** Cognitive semantic analysis using Google's production-grade Gemini API framework to detect psychological manipulation.
* **Sweeti Engine (Structural ML):** Empirical Random Forest binary pipeline analyzing 8 core metadata characteristics.
* **Sunil Engine (Live Intel & IMAP):** Secure `IMAP4_SSL` email extraction synced with live VirusTotal V3 API scanning (70+ threat feeds).

---

## 🛠️ Installation & Setup Instructions

### 1. Prerequisites
Ensure you have **Python 3.10** or a newer compatible version installed on your host system architecture (macOS, Windows, or Linux).

### 2. Extract and Initialize Environment
Extract the submission zip archive, open your system terminal/command prompt, navigate to the root directory, and build a localized virtual environment:

```bash
# Navigate to project folder
cd HAEPD-Forensic-Suite

# Build localized virtual environment space
python -m venv venv

# Activate the environment
# For macOS / Linux:
source venv/bin/activate
# For Windows (Command Prompt):
venv\Scripts\activate
# For Windows (PowerShell):
.\venv\Scripts\Activate.ps1