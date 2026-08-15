# LLM08 Vector & Embedding Security Scanner

An automated penetration-testing and monitoring framework that detects **OWASP LLM08: Vector & Embedding Weaknesses** in RAG (Retrieval-Augmented Generation) pipelines. 

Modern AI systems store knowledge as numerical vectors in a vector database. This scanner automatically audits a live Qdrant vector store across multiple attack classes to identify the risk that these embeddings can be exploited—leaking private data, being poisoned to manipulate AI outputs, or exposing tenant information across security boundaries.

## Features
- **High-Performance Scanning Engine**: A modular backend built with Python, rigorously testing the vector database across 9 unique attack classes.
- **Interactive Dashboard**: A beautiful, real-time React/Vite dashboard to track live scans, explore findings, and view an aggregated risk gauge.
- **Automated Reporting**: Generates detailed JSON datasets and OWASP-mapped PDF reports.

---

## How It Tests RAG Models

The scanner evaluates the security of your embeddings using 5 Core Modules (which contribute to the overall 0-100 Risk Score) and 4 Unique Tech Modules (for advanced contextual telemetry).

### Core Modules
1. **ACL Fuzzer (Cross-Tenant Leakage)**: Fuzzes vector isolation by presenting Tenant A's token when querying Tenant B's collection. If the database returns records instead of an AuthorizationError, a leakage is flagged.
2. **Inversion Tester (Data Reconstruction)**: Takes raw vectors from the database and runs nearest-neighbor searches against a massive corpus of known embeddings to prove if raw, plaintext PII or vocabulary words can be perfectly reconstructed from the float arrays.
3. **Poisoning Simulator (Adversarial Injection)**: Injects targeted adversarial vectors into the database, then simulates thousands of user RAG queries. It flags a finding if the adversarial vector is disproportionately over-retrieved, successfully hijacking the LLM's context window.
4. **Drift Detector (Distribution Shift)**: Analyzes the mathematical distribution of your entire embedding namespace using Mahalanobis distance and DBSCAN clustering. Outliers that fall far outside the normal variance are flagged as potential tampering or injection attacks.
5. **Probe Generator (Similarity Manipulation)**: Generates highly paraphrased and semantically adjacent attack queries to test if an attacker can steer the RAG retrieval boundaries to pull isolated data.

### Unique Tech Modules
- **DP Noise Injector**: Simulates differential privacy by injecting calibrated Laplace noise into vectors, measuring how much privacy is gained versus how much utility/accuracy is lost.
- **Collision Scorer**: Scans across distinct tenant namespaces for identical vectors (mathematical collisions), which can reveal identical data uploads across boundaries.
- **ACL Simulator**: Audits row-level metadata filtering rules before execution to proactively catch misconfigurations.
- **Poison Classifier**: An IsolationForest-based machine learning model that acts as a secondary defense layer to classify anomalous vectors.

---

## E2E Setup & Demo Guide

If you want to evaluate this scanner locally, we have provided an automated seeder script (`seed_final_demo.py`) that instantly generates a vulnerable, multi-tenant Qdrant database specifically designed to trigger all the alarms.

### Prerequisites
- **Python 3.11+**
- **Node.js 18+** (for the frontend UI)
- **PowerShell 5.1+** (Windows)

### Step 1: Start Qdrant
The scanner requires a running instance of Qdrant. You can start one using either Docker or the Windows standalone binary.

**Option A: Docker (Recommended)**
```bash
docker run -p 6333:6333 -p 6334:6334 -d qdrant/qdrant
```

**Option B: Windows Standalone Binary**
1. Download the latest `qdrant-x86_64-pc-windows-msvc.zip` from [Qdrant Releases](https://github.com/qdrant/qdrant/releases).
2. Extract it and place `qdrant.exe` into a new folder named `qdrant_bin/` in the project root.
3. Run the provided start script:
   ```powershell
   .\scripts\start_qdrant.ps1
   ```
   *(Keep this terminal open, or let it run in the background. It will bind to `127.0.0.1:6333`)*

### Step 2: Seed the Vulnerable Dataset
We need a dataset to test against. Open a new terminal and run:
```bash
# Install dependencies if you haven't already
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# Run the seeder
python seed_final_demo.py
```
**What this script does:**
- Injects 60 "normal" baseline HR documents.
- Injects 1 highly malicious, off-distribution outlier vector (Triggers **Drift Detector**).
- Injects exact float representations of common English words (Triggers **Inversion Tester** to hit a 100% reconstruction rate).
- Injects duplicate outlier vectors across isolated namespaces (Triggers **Collision Scorer**).
- Automatically generates a `config_final.yaml` file that intentionally configures `tenant_a` and `tenant_b` to share a collection without authorization tokens (Triggers **ACL Fuzzer**).

### Step 3: Launch the Backend API
The frontend relies on a FastAPI backend to coordinate the scanning engine.
```bash
uvicorn api.main:app --host 127.0.0.1 --port 8000
```
*(Keep this terminal open)*

### Step 4: Launch the Dashboard
In a third terminal, start the Vite development server:
```bash
cd frontend
npm install
npm run dev
```

### Step 5: Run the Live Scan
1. Open `http://localhost:5173/` in your browser.
2. Toggle **Demo Mode** to `OFF`.
3. Click **Choose File** and select the `config_final.yaml` file from your file system.
4. Click **▶ Run Live Scan**.

Watch the stepper progress through the 9 modules in real-time. Once the scan completes, you will see a high-severity **CRITICAL** or **HIGH** overall risk score, and you can explore the exact vulnerabilities the scanner discovered in the interactive **Findings Explorer** table.

---

## Output Artifacts
Every successful scan automatically generates persistent reports in the root directory:
- `llm08_scan_report_<timestamp>.json`: Full machine-readable telemetry.
- `llm08_scan_report_<timestamp>.pdf`: Human-readable, OWASP-mapped risk report.
- `llm08_scan_report_<timestamp>.heatmap.json`: Structured UMAP 2D projection data for rendering the interactive vector space heatmap in the dashboard.
- `findings_<timestamp>.csv`: Complete dataset of all flagged vectors (generated if findings exceed the PDF table limits).

---

## License
MIT
