---
title: FortifyAI Prompt Injection Security Engine
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: gradio
sdk_version: 4.44.0
app_file: hf_app.py
pinned: false
---

# 🛡️ FortifyAI — Enterprise Prompt Injection & Document Security Engine

Enterprise-grade multi-layer Prompt Injection Guardrail, Document & Web Scanner, and Continuous Re-Training Engine.

---

## 📋 Table of Contents
- [Architecture & Overview](#-architecture--overview)
- [Prerequisites](#-prerequisites)
- [Local Setup Guide (Full Stack)](#-local-setup-guide-full-stack)
  - [1. Clone Repository](#1-clone-repository)
  - [2. Backend Setup (FastAPI & ML Engine)](#2-backend-setup-fastapi--ml-engine)
  - [3. Frontend Setup (React + Vite Dashboard)](#3-frontend-setup-react--vite-dashboard)
- [Alternative Quick-Start Options](#-alternative-quick-start-options)
  - [Option A: Gradio Standalone UI](#option-a-gradio-standalone-ui)
  - [Option B: Docker Setup](#option-b-docker-setup)
- [Environment Configuration](#-environment-configuration)
- [Running Automated Tests](#-running-automated-tests)
- [API Reference](#-api-reference)
- [Project Structure](#-project-structure)

---

## 🏛️ Architecture & Overview

FortifyAI protects LLM applications against direct prompt injections, jailbreaks, indirect injection vectors, and invisible adversarial payloads hidden inside documents or websites.

- **Layer 1: Heuristics & Obfuscation Detection** — Scans for Unicode homoglyphs, Base64/Hex encoding, leetspeak, markdown injection, and prompt override patterns (<5ms).
- **Layer 2: ModernBERT ML Classifier** — Fine-tuned transformer-based prompt injection detection running within an SLA latency budget (<100ms).
- **Layer 3: Document & Web Invisible Content Scanner** — Detects hidden text (`display: none`, `font-size: 0`, matching background colors, metadata injection in PDF/DOCX/HTML).
- **Layer 4: Continuous Re-Training Loop** — Captures novel edge cases and queued telemetry for active fine-tuning.

---

## ⚙️ Prerequisites

Before getting started, make sure you have the following installed on your machine:

- **Python**: `3.10` or `3.11` ([Download Python](https://www.python.org/downloads/))
- **Node.js**: `v18.0.0` or higher & **npm** ([Download Node.js](https://nodejs.org/))
- **Git**: ([Download Git](https://git-scm.com/))
- *(Optional)* **MongoDB**: Local MongoDB instance (`mongodb://localhost:27017`) or a free [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) cluster.
- *(Optional)* **Docker**: If you wish to run the containerized backend.

---

## 🚀 Local Setup Guide (Full Stack)

Follow these steps to run both the FastAPI backend and the React frontend on your local machine.

### 1. Clone Repository

```bash
git clone https://github.com/IqraS-gif/FortifyAI-Final.git
cd FortifyAI-Final
```

---

### 2. Backend Setup (FastAPI & ML Engine)

#### Step 2.1 — Create and Activate a Python Virtual Environment

- **On Windows (PowerShell):**
  ```powershell
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  ```
  *(If script execution is restricted on Windows PowerShell, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first)*

- **On macOS / Linux:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

#### Step 2.2 — Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

> **Note on PyTorch (CPU acceleration):**
> If you want a lightweight CPU-only PyTorch installation, you can install it using:
> ```bash
> pip install torch --index-url https://download.pytorch.org/whl/cpu
> ```

#### Step 2.3 — Configure Environment Variables

Create a `.env` file in the `backend/` directory (or copy from `backend/.env.example`):

```bash
# Windows
copy backend\.env.example backend\.env

# macOS / Linux
cp backend/.env.example backend/.env
```

Example `backend/.env` contents:
```env
MONGODB_URI=mongodb://localhost:27017
DB_NAME=fortify_ai
```
*(You can also use a MongoDB Atlas connection string: `mongodb+srv://<user>:<password>@cluster.mongodb.net/fortify_ai`)*

#### Step 2.4 — Start the Backend Server

Run the backend from the root directory:

```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

Or from inside the `backend/` directory:

```bash
cd backend
python main.py
```

The backend will start at:
- **API Base URL**: `http://localhost:8000`
- **Interactive Swagger Docs**: `http://localhost:8000/docs`
- **ReDoc Documentation**: `http://localhost:8000/redoc`

---

### 3. Frontend Setup (React + Vite Dashboard)

Open a **new terminal window/tab** (leaving the backend running).

#### Step 3.1 — Navigate to the Frontend Directory

```bash
cd frontend
```

#### Step 3.2 — Install Node Dependencies

```bash
npm install
```

#### Step 3.3 — (Optional) Configure Frontend Environment

By default, Vite is configured with a proxy in `vite.config.js` forwarding `/api` to `http://127.0.0.1:8000`. If you wish to specify an explicit backend URL, create a `.env` file inside `frontend/`:

```env
VITE_API_BASE_URL=http://localhost:8000/api
```

#### Step 3.4 — Start the Frontend Development Server

```bash
npm run dev
```

The frontend will be available at:
- **Dashboard URL**: `http://localhost:3000` (or `http://localhost:5173` depending on port availability)

---

## ⚡ Alternative Quick-Start Options

### Option A: Gradio Standalone UI

If you want a lightweight single-page UI for quick testing without running the React frontend:

1. Ensure your Python virtual environment is activated and dependencies are installed (`pip install -r requirements.txt`).
2. Run:
   ```bash
   python hf_app.py
   ```
3. Open `http://localhost:7860` in your browser.

---

### Option B: Docker Setup

You can build and run the containerized backend using Docker:

```bash
# Build the Docker image
docker build -t fortifyai .

# Run the container
docker run -d -p 8000:8080 -e PORT=8080 --name fortifyai-container fortifyai
```

Access the API at `http://localhost:8000/docs`.

---

## 🔧 Environment Configuration

| Variable | Scope | Default | Description |
|---|---|---|---|
| `MONGODB_URI` | Backend | `mongodb://localhost:27017` | MongoDB connection URI string |
| `DB_NAME` | Backend | `fortify_ai` | Target MongoDB database name |
| `PORT` | Backend / Docker | `8000` / `8080` | Port for the backend service |
| `VITE_API_BASE_URL` | Frontend | `http://localhost:8000/api` | Base API route for frontend requests |
| `BACKEND_URL` | Gradio App | `http://localhost:8000` | Backend API URL used by `hf_app.py` |

---

## 🧪 Running Automated Tests

To run the end-to-end security pipeline test suite (validating heuristic filters, ModernBERT classifier, document scanner, indirect attack vectors, and latency SLAs):

```bash
# Run pipeline test suite
python backend/test_pipeline.py
```

Or using `pytest`:

```bash
pytest
```

---

## 📡 API Reference

Here are the primary endpoints exposed by the backend:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Service health status & latency budget info |
| `POST` | `/api/scan/prompt` | Scan prompt text for injection & jailbreak attacks |
| `POST` | `/api/scan/document` | Upload & scan PDF/DOCX files for hidden prompt vectors |
| `POST` | `/api/scan/url` | Scan live web pages for indirect injection payloads |
| `GET` | `/api/projects` | List active projects & sensitivity configurations |
| `GET` | `/api/analytics` | Retrieve security telemetry & threat analytics |
| `POST` | `/api/retrain/trigger`| Trigger the continuous retraining pipeline |
| `GET` | `/api/retrain/samples`| View queued edge-case feedback samples |

Interactive testing is available at `http://localhost:8000/docs`.

---

## 📁 Project Structure

```
fortifyAI/
├── backend/
│   ├── app/
│   │   ├── config.py             # App settings & sensitivity profiles
│   │   ├── db/                   # MongoDB connection & schemas
│   │   ├── ml/                   # Model loaders & tokenizer pipelines
│   │   ├── routers/              # API endpoints (scan, retrain, projects, etc.)
│   │   └── services/             # Core security scanners (heuristic, ModernBERT, doc)
│   ├── main.py                   # FastAPI server entry point
│   ├── requirements.txt          # Backend dependencies
│   ├── test_pipeline.py          # Automated verification test suite
│   └── .env.example              # Environment variables template
├── frontend/
│   ├── src/                      # React UI components, 3D views & dashboards
│   ├── package.json              # Frontend dependencies
│   └── vite.config.js            # Vite configuration & API proxy
├── Dockerfile                    # Containerization setup
├── hf_app.py                     # Hugging Face Gradio interface
├── requirements.txt              # Root dependencies
└── README.md                     # Project documentation & setup instructions
```

---

## 📄 License

This project is licensed under the MIT License.