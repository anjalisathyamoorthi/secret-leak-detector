# 🛡️ Secret Leak Detector

A high-performance security tool that scans source code for leaked secrets (API keys, passwords, cloud tokens, database URIs), prevents accidental Git commits via pre-commit protection, and tracks team security compliance on an interactive dashboard.

---

## 🏗️ Tech Stack

- **CLI Scanner**: Python 3.11+ with regex pattern matching engine & Shannon entropy analysis
- **Backend API**: FastAPI (high-async performance)
- **Database**: SQLite with SQLAlchemy ORM
- **Dashboard**: Streamlit interactive compliance dashboard
- **Git Hook**: Custom Python pre-commit hook script & `.pre-commit-config.yaml` framework support
- **Reports**: Automated CSV report exporter & trend analysis

---

## 📂 Project Structure

```
secret-leak-detector/
├── scanner/
│   ├── __init__.py
│   ├── rules.yaml              # 12+ Regex rules (AWS, GitHub, Stripe, DB, JWT, RSA)
│   ├── detector.py             # Pattern matching & entropy analysis engine
│   ├── entropy.py              # Shannon entropy computation & context filters
│   ├── cli.py                  # CLI scanner interface (scan, init, --staged, --history)
│   └── masker.py               # Secret masking & SHA-256 fingerprint hashing
├── hooks/
│   └── pre_commit_hook.py      # Git hook blocking HIGH/CRITICAL secret commits
├── backend/
│   ├── main.py                 # FastAPI application
│   ├── models.py               # SQLAlchemy database models
│   ├── database.py             # SQLite database connection & session setup
│   ├── routes/
│   │   ├── auth.py             # Authentication endpoints
│   │   ├── scans.py            # Scan ingestion & retrieval
│   │   ├── findings.py         # Finding lifecycle & status updates
│   │   ├── metrics.py          # Compliance metrics computation
│   │   └── bypasses.py         # Audit log for commit bypasses
│   └── schemas.py              # Pydantic validation models
├── dashboard/
│   └── app.py                  # Streamlit compliance dashboard (Overview, Findings, Repos, Reports)
├── tests/
│   ├── fake_secrets/           # Synthetic test files (FAKE credentials only)
│   └── clean_code/              # Clean test benchmark files
├── reports/
│   └── export.py               # CSV report generation module
├── eval.py                     # Precision, Recall, F1 score accuracy benchmark
├── requirements.txt
├── README.md
└── .pre-commit-config.yaml
```

---

## 🚀 Quickstart & Setup

### 1. Installation
Clone the repository and install dependencies:

```bash
cd secret-leak-detector
pip install -r requirements.txt
```

### 2. Initialize Git Pre-Commit Hook
Install the Secret Leak Detector pre-commit hook into your repository:

```bash
python scanner/cli.py init
```

### 3. Start Backend API & Dashboard

Start the FastAPI backend server:
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

In a second terminal window, launch the Streamlit dashboard:
```bash
streamlit run dashboard/app.py
```

Open your browser at `http://localhost:8501`.

---

## 🖥️ CLI Usage Commands

- **Scan a directory or file**:
  ```bash
  python scanner/cli.py scan .
  python scanner/cli.py scan src/config.py
  ```

- **Scan staged Git files only**:
  ```bash
  python scanner/cli.py scan --staged
  ```

- **Scan Git commit history**:
  ```bash
  python scanner/cli.py scan --history
  ```

- **Output Format**:
  ```
  [HIGH] Stripe API Key detected
  File: config.py
  Line: 14
  Rule: stripe-key
  Masked value: sk_l****...**91ab
  Action: Roll Stripe API key immediately in Stripe Dashboard.
  ```

---

## 🎬 Live Demo Script Walkthrough

Follow these steps to demonstrate the complete prevention & compliance workflow live:

1. **Create a fake secret file**:
   ```bash
   echo "DEMO_KEY = 'sk_live_1234567890abcdefghijklmnopqrst'" > tests/fake_secrets/demo.py
   ```

2. **Stage the file with Git**:
   ```bash
   git add tests/fake_secrets/demo.py
   ```

3. **Attempt to commit**:
   ```bash
   git commit -m "add demo credentials"
   ```
   *Result*: Pre-commit hook triggers, displays `[SECURITY ALERT]`, shows masked value `sk_l****...**qrst`, and **BLOCKS** the commit (exit code 1).

4. **Remediate the file**:
   ```bash
   git rm -f tests/fake_secrets/demo.py
   ```

5. **Commit clean code**:
   ```bash
   git commit -m "commit clean code"
   ```
   *Result*: Commit succeeds cleanly!

6. **View & Manage Findings on Dashboard**:
   - Open Streamlit dashboard (`http://localhost:8501`).
   - Navigate to the **Findings** tab to view the blocked finding recorded in real-time.
   - Click **Mark as Resolved** to resolve the issue.
   - Return to the **Overview** tab to see updated team compliance percentage!

---

## 📊 Evaluation & Accuracy Benchmarking

Run the built-in precision & recall evaluation benchmark:

```bash
python eval.py
```

Example Output:
```
============================================================
 SECRET LEAK DETECTOR ACCURACY & PERFORMANCE EVALUATION
============================================================
Files Scanned:             6 (5 positive, 1 clean)
Total Detections:          12
True Positives (TP):       10
False Positives (FP):      0
False Negatives (FN):      2
------------------------------------------------------------
Precision:                 100.00%
Recall:                    83.33%
F1 Score:                  90.91%
Average Scan Time:         0.64 ms / file
============================================================
```

---

## 🔒 Security Requirements & Plaintext Isolation Guarantee

> [!IMPORTANT]
> **Plaintext Secret Guarantee**:
> - Full plaintext secret values are **never** logged, saved to disk, or stored in backend database tables.
> - Secrets are masked using the format `sk_l****...**91ab` (showing only first 4 and last 4 characters).
> - One-way **SHA-256 fingerprints** are computed for secret deduplication without exposing secret values.

---

## ⚠️ Security Disclaimer Note

> [!CAUTION]
> This is a prototype layered secret detector using pattern matching, entropy analysis, and Git pre-commit protection. It does not guarantee detection of all secrets and may produce false positives. This is not a substitute for centralized secrets management.
