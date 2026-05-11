# Specialised Security Partner — IDS Prototype

A fully local, privacy-preserving Intrusion Detection System that combines a machine learning classifier with a natural language analyst interface. Built as a solo honours dissertation project at Edinburgh Napier University (2025–2026).

**No data leaves your machine.** The ML classifier and LLM both run entirely on-device.

---

## Key Results

| Metric | Value |
|---|---|
| Dataset | CICIDS2017 — 2.1M network flow records, 12 attack classes |
| Classifier | Random Forest (100 trees, scikit-learn) |
| Weighted Accuracy | **98%** |
| False Positive Rate | **0.012%** at 0.89 confidence threshold |
| Baseline Comparison | Outperforms Linear SVM under identical conditions |

---

## Features

- **3-Tier Confidence System** — automatically alerts on high-confidence threats, routes uncertain detections to human review, and clears low-confidence benign traffic
- **Natural Language Interface** — type commands in plain English ("scan network", "what is DoS Hulk?", "isolate")
- **LLM Analyst Assistant** — Mistral 7B (via Ollama) explains uncertain detections and answers security questions without sending data to the cloud
- **Automated Incident Reports** — generates compliance-ready security reports exported as `.docx`
- **12 Attack Classes Covered** — DoS variants, brute force (SSH/FTP), web attacks (XSS, SQL injection, brute force), Heartbleed, Infiltration

---

## Architecture

```
CICIDS2017 Dataset
      ↓
 train_ids.py  →  Random Forest Model (.joblib)
                        ↓
               Flask Backend (app.py)
               ├── /run_scan       → ML inference + 3-tier routing
               ├── /chat           → NLI keyword router + Mistral fallback
               ├── /analyse_packet → LLM analysis of uncertain detections
               ├── /generate_report → LLM incident report generation
               └── /export_report  → .docx download
                        ↓
              Web Dashboard (HTML5 + Tailwind CSS + JavaScript)
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.9+ | Tested on Python 3.13 |
| [Ollama](https://ollama.com) | Required for the LLM features |
| Mistral 7B model | Pulled via Ollama (see step 4 below) |

The ML classifier works without Ollama — the app falls back gracefully if Ollama is not running.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/AhmedMKA99/0.Updated-ID-IDS.git
cd 0.Updated-ID-IDS
```

### 2. Create and activate a virtual environment

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Ollama and pull Mistral

Download Ollama from [https://ollama.com](https://ollama.com) and install it, then run:

```bash
ollama pull mistral
```

This downloads the Mistral 7B model (~4GB). Only needed once.

---

## Running the App

```bash
cd Code
python app.py
```

Then open your browser and go to:

```
http://localhost:5000
```

> **Note:** The app must be started from inside the `Code/` directory so the relative paths to `../models/` and `../data/` resolve correctly.

---

## Using the Dashboard

Once the app is running you will see the analyst dashboard. Here is what each part does:

### Scanning
- Click **Scan** or type `scan network` in the chat to classify the next network flow
- The result will be one of three outcomes:

| Result | What it means |
|---|---|
| **ALERT** (red) | Confidence ≥ 89% — automatic threat detected |
| **UNCERTAIN** (amber) | Confidence 50–89% — scan pauses, operator review required |
| **BENIGN** (green) | Confidence < 50% or classified as normal traffic |

### Uncertain Detections
When an uncertain packet is flagged:
1. Click **Analyse with AI** to get Mistral's explanation of why it was flagged
2. Review the top-3 prediction split shown on screen
3. Click **Mark as Threat** or **Dismiss** to resolve it and continue scanning

### Chat Commands
Type natural language commands in the chat box:

| Command | Action |
|---|---|
| `scan network` | Classify next packet |
| `what is DoS Hulk?` | Get attack explanation |
| `show stats` | View session summary |
| `isolate` | Simulate firewall isolation of last threat |
| Any other question | Forwarded to Mistral for a general security answer |

### Reports
- Click **Generate Report** after scanning to produce an LLM-written incident report
- Click **Export** to download it as a formatted `.docx` file

### Data Streams
Use the stream selector to switch between:
- **Demo** — small curated dataset, good for a quick walkthrough
- **Uncertain** — dataset weighted towards the 50–89% confidence band, useful for testing human-review flow
- **Production** — full hold-out test set (requires local training, see below)

---

## Retrain the Model (Optional)

The pre-trained model is included in the repo (`models/ids_model.joblib`). If you want to retrain from scratch:

1. Download the CICIDS2017 dataset from [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)
2. Place the 5 CSV files in `data/raw/`
3. Run:

```bash
cd Code
python train_ids.py
```

Training takes approximately 5–15 minutes depending on hardware. The script will print a full classification report when complete.

---

## Project Structure

```
0.Updated-ID-IDS/
├── Code/
│   ├── app.py              # Flask backend — inference, chat, report generation
│   ├── train_ids.py        # ML training pipeline
│   ├── map_test_data.py    # Data mapping utilities
│   └── templates/
│       └── index.html      # Single-page analyst dashboard
├── models/
│   ├── ids_model.joblib    # Pre-trained Random Forest classifier (61MB)
│   ├── label_encoder.joblib
│   └── feature_names.joblib
├── data/
│   ├── processed/
│   │   ├── viva_demo_data.csv      # Small demo dataset (included)
│   │   └── uncertain_demo_data.csv # Uncertain-band demo data (included)
│   └── raw/                        # Place CICIDS2017 CSVs here (not included — too large)
├── requirements.txt
└── README.md
```

---

## Academic Context

This project was submitted as a 40-credit solo honours dissertation at Edinburgh Napier University (module SOC10101). The dissertation explores the design and evaluation of a human-in-the-loop IDS that pairs a statistical ML classifier with a locally deployed LLM, addressing alert fatigue through confidence-based triage rather than binary detection.

Supervisor: Dr Pavlos Papadopoulos | Second Marker: Robert Ludwiniak

---

## License

MIT
