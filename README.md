# HAEPD Forensic Suite Pro (V8.16)

The **High-Accuracy Email Phishing Detection (HAEPD) Forensic Suite** is a production-grade digital forensics web application built to intercept sophisticated phishing attempts, identity forgery, and zero-day credential harvesting schemes. 

By employing a decoupled, multi-tier **DevSecOps** architecture within an **Agile lifecycle**, the suite bridges the "context deficit" of traditional signature-based gateway filters. It runs parallel diagnostic engines to evaluate both the semantic psychological indicators and the structural metadata signatures of an email payload simultaneously.

---

## ⚙️ Core Architecture & Subsystem Engines

The platform processes unstructured email data through three decoupled analytical nodes before feeding the outputs into a centralized decision core:

* **Anurag Engine (Contextual AI):** Orchestrates secure API connection loops with Google’s production-grade `gemini-2.5-flash` model namespace. It utilizes a highly tuned prompt constraint matrix to detect cognitive social engineering and brand-impersonation cues while cleanly ignoring legitimate retail marketing urgency.
* **Sweeti Engine (Structural ML):** An empirical machine learning pipeline driven by a serialized Random Forest classifier (`.pkl`). It extracts and analyzes an 8-feature vector containing server authentication status (`dkim_pass`, `dmarc_pass`, `spf_pass`) and hyperlink structural layouts.
* **Sunil Engine (Live Threat Intel & IMAP Ingestion):** Uses `imaplib` over `IMAP4_SSL` (secure port 993) to pull live forensic email samples directly from active enterprise inboxes. It extracts embedded domains via regex patterns and queries them asynchronously against the **VirusTotal V3 API** across 70+ global blocklist networks.
* **Unified Aggregator Core:** Automatically adjusts its analytical weights (e.g., dynamic 60/40 context/structure splits) depending on data completeness. It features an automated global kill-switch that overrides baseline calculations and forces a critical risk score of `0.99` if a domain hits an explicit malicious blocklist flag.

---

## 🛡️ Security & Privacy Engineering

* **Zero-Persistence Storage Layout:** To satisfy enterprise data privacy mandates and enforce strict data minimization, the suite operates entirely within local volatile memory. Scanned payloads, credential variables, and session keys are never written to the host disk and are purged completely upon session termination.
* **Null Token Calibration:** Features a specialized preprocessing module built using `BeautifulSoup4` that sanitizes messy HTML/CSS formatting and automatically assigns neutral fallback markers (`0.5`) to missing header data in manual copy-pasted payloads, stabilizing false-positive spikes.

---

## 🛠️ Technology Stack & Dependencies

* **Language:** Python 3.10+
* **Frontend UI:** Streamlit (Reactive data web dashboard)
* **Machine Learning:** Scikit-Learn, Joblib, Pandas
* **AI Integration:** Google GenAI SDK (Gemini API)
* **Forensic Parsing:** BeautifulSoup4, Regular Expressions (`re`)
* **Reporting Subsystem:** FPDF, Matplotlib (On-the-fly binary rendering)

---

## 🚀 Quick Start Guide

### 1. Local Environment Initialization
Clone the repository and spin up a localized virtual environment:
```bash
git clone [https://github.com/your-username/HAEPD-Forensic-Suite.git](https://github.com/your-username/HAEPD-Forensic-Suite.git)
cd HAEPD-Forensic-Suite
python -m venv venv

# Activate on Windows:
.\venv\Scripts\activate
# Activate on macOS/Linux:
source venv/bin/activate
