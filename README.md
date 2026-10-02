![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![React](https://img.shields.io/badge/React-Vite-cyan?logo=react&logoColor=black)
![FastAPI](https://img.shields.io/badge/FastAPI-Celery-009688?logo=fastapi&logoColor=white)

# PiQuaChu 🛡️

> **Enterprise-grade Post-Quantum Cryptography (PQC) DevSecOps Pipeline.** Decentralized local scanning meets asynchronous AI threat analysis.

---

## What Is PiQuaChu?

PiQuaChu is an automated, AI-driven security analysis tool designed to bridge the gap between legacy cryptographic standards (RSA, ECC) and the impending threat of quantum computing. 

Instead of forcing developers to upload sensitive source code to a centralized server, PiQuaChu utilizes a lightweight, zero-trust local CLI agent. This agent parses Abstract Syntax Trees (ASTs) directly on the developer's machine to find vulnerable cryptographic implementations, and securely transmits only the necessary telemetry to our central AI engine to generate FIPS-203 compliant migration plans.

---

## Features

### 🔒 Zero-Trust Local CLI Agent
Developers can install the `cipher_cli.py` tool locally or integrate it directly into their CI/CD pipelines (like GitHub Actions). It finds vulnerabilities at the source and communicates securely with the Core Engine using long-lived API keys, ensuring proprietary code never leaves the local environment.

### 🧠 Asynchronous AI Remediation Engine
PiQuaChu doesn't just flag deprecated algorithms; it tells you how to fix them. Using a concurrent LLM-powered engine (via Groq), it generates exact code replacements and architectural warnings. To handle high-volume enterprise traffic without blocking the main event loop, all AI analysis is offloaded to a **Celery** task queue backed by **Redis**.

### 🛂 Dual-Auth API Gateway
A true SOC tool separates human operators from machine agents:
* **Humans (CISOs/Analysts):** Log into the Fleet Command Dashboard using secure Google Firebase JWTs.
* **Machines (CLI/Pipelines):** Authenticate using locally generated, database-backed API Keys (`cs_live_...`).

### 📊 Fleet Command Dashboard
A dark-mode React interface featuring real-time PQC readiness scoring, a Time Machine Archive for historical audit logs, interactive threat metrics, and one-click PDF Executive Report generation.

---

## Architecture



```text
┌───────────────────────────────────────┐
│        Local Agent / CI Pipeline      │
│  Python CLI · Local AST · API Tokens  │
└───────────────────┬───────────────────┘
                    │ REST / JSON (Metadata Only)
┌───────────────────▼───────────────────┐
│           FastAPI Gateway             │
│  Dual-Auth Bouncer · SQLite (Keys)    │
└───────────────────┬───────────────────┘
                    │ Task Delegation
┌───────────────────▼───────────────────┐
│         Celery Worker Queue           │
│    Redis Broker · Groq LLM Engine     │
└───────────────────┬───────────────────┘
                    │ HTTP Polling      
┌───────────────────▼───────────────────┐
│      Fleet Command Dashboard          │
│ React · Framer Motion · Firebase Auth │
└───────────────────────────────────────┘

```

---

## Quickstart

### Prerequisites

* Python 3.10+
* Node.js 18+
* Redis Server (running on `localhost:6379`)

### 1. Boot the Core Engine & Message Broker

Start your local Redis server. Then, initialize the FastAPI backend and Celery workers:

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Terminal A: Start the API Gateway
uvicorn api.main:app --reload

# Terminal B: Start the Asynchronous Workers
celery -A worker.celery_app worker --loglevel=info

```

### 2. Launch the Fleet Command (Frontend)

In a new terminal:

```bash
cd frontend
npm install
npm run dev

```

Access the dashboard at `http://localhost:5173`.

### 3. Run a Zero-Trust CLI Scan

Log into the web dashboard and generate an API Key from the "API KEYS" tab. Then, run the terminal agent:

```bash
cd backend
python cipher_cli.py path/to/your/code.java --token "cs_live_YOUR_GENERATED_KEY"

```

---

## API Reference

### `POST /api/v1/keys/generate` — Provision Machine Token

Generates a long-lived API key for CI/CD integration.

* **Auth:** Requires a valid human Firebase JWT.

### `POST /api/v1/scan` — Submit Telemetry

Accepts vulnerability metadata from the local CLI and dispatches an asynchronous Celery task.

* **Auth:** `Bearer cs_live_<key>` OR `Bearer <firebase_jwt>`

### `GET /api/v1/scan/{task_id}` — Poll Engine Status

Retrieves the real-time status of the LLM analysis queue (PENDING, SUCCESS, FAILED).

### `GET /api/v1/history` — Fetch Audit Trail

Returns the encrypted session's complete historical scan log for the Archive tab.

---

## Contributing

Pull requests are welcome. For significant changes, open an issue first to discuss your proposal. Ensure all new API routes or architectural shifts are reflected in this README.

---

## License

[MIT](https://www.google.com/search?q=LICENSE)


```

