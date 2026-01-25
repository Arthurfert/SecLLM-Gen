# SecLLM-Gen

**Applied Research Project (PRAPP) - Télécom Saint-Etienne**

##  Overview

This project explores the application of **Generative Artificial Intelligence** in both **Offensive and Defensive Cybersecurity**. It facilitates the automated generation of vulnerability exploitation scripts (CVEs) and corresponding Intrusion Detection System (IDS) rules, leveraging local Large Language Models (LLMs) via Ollama and Retrieval-Augmented Generation (RAG).

### Core Modules

| Module | Description | Status |
| :--- | :--- | :--- |
|  **Attaque_LLM** | Automated CVE exploit generation with RAG support |  Functional |
|  **IDS_LLM** | Automated creation of Suricata detection rules |  Functional |
|  **Interface_web** | Centralized orchestration via React + FastAPI |  Functional |

 **Disclaimer**: This project is strictly for **educational and research purposes** within the framework of PRAPP 2025.

---

##  Table of Contents

1. [Project Objectives](#-project-objectives)
2. [System Architecture](#-system-architecture)
3. [Prerequisites](#-prerequisites)
4. [Quick Installation](#-quick-installation)
5. [Tutorial: Getting Started](#-tutorial-getting-started)
6. [Module Details](#-module-details)
7. [Technology Stack](#-technology-stack)
8. [Troubleshooting](#-troubleshooting)
9. [Ethical Considerations](#-ethical-considerations)
10. [Resources](#-resources)

---

##  Project Objectives

### 1. Demonstrate AI Capabilities in Cybersecurity
- Automate exploit generation using LLMs.
- Automate request-based defense generation (IDS rules).
- Enhance vulnerability analysis with RAG (Retrieval-Augmented Generation).

### 2. Compare Offensive vs. Defensive Strategies
- Measure the efficacy of generated exploits.
- Evaluate the quality and accuracy of generated IDS rules.
- Identify the limitations of AI in both domains.

### 3. Centralized Orchestration
- Unified web interface to manage both offensive and defensive modules.
- Feedback loop integration to refine generated scripts.
- Automated code quality evaluation.

---

##  System Architecture

```
52/
├──  Attaque_LLM/              # Offensive Module
│   ├── main.py                  # Main entry point
│   ├── llm_generator.py         # Ollama Interface (Standard)
│   ├── llm_generator_rag.py     # Ollama Interface with RAG
│   ├── rag_engine.py            # RAG Engine (ChromaDB + HuggingFace)
│   ├── nmap_scanner.py          # Vulnerability Scanner
│   ├── cve_database.py          # Local CVE Database
│   ├── api_server.py            # REST API for Orchestrator
│   ├── requirements.txt         # Python Dependencies
│   ├──  CVE_info_rag/         # NVD Data for RAG - unable to push to github
│   ├──  chroma_db/            # Vector Database
│   └──  scripts/              # Generated Exploit Scripts
│
├──  IDS_LLM/                  # Defensive Module
│   ├── main.py                  # Main Entry Point
│   ├── llm_generator.py         # Ollama Interface
│   └──  scripts/              # Generated IDS Rules
│
├──  Interface_web/            # Centralized Interface
│   ├──  orchestrator/         # FastAPI Backend
│   │   ├── app/
│   │   │   ├── main.py          # REST API
│   │   │   ├── models.py        # Pydantic/SQLAlchemy Models
│   │   │   ├── db.py            # Database Management
│   │   │   └──  services/     # Business Logic
│   │   └── requirements.txt
│   └──  frontend/             # React Frontend
│       ├── src/App.js           # Main Application
│       └── package.json
│
└── README.md                    # This file
```

---

##  Prerequisites

### Required Software

| Software | Version | Description |
| :--- | :--- | :--- |
| **Python** | 3.10+ | Primary programming language |
| **Node.js** | 18+ | Required for React frontend |
| **Ollama** | Latest | Local LLM server |
| **Nmap** | 7.0+ | Vulnerability scanner (optional) |

### Optional Tools

- **Suricata**: To test generated IDS rules.
- **NVIDIA GPU**: For accelerated generation.

---

##  Quick Installation

### Step 1: Clone the Repository

```powershell
git clone https://github.com/Arthurfert/SecLLM-Gen
cd SecLLM-Gen
```

### Step 2: Install Ollama

Install Ollama and then pull models :

```powershell
# Pull models (examples below)
ollama pull mistral
ollama pull codestral  # Recommended for code generation
```

### Step 3: Install Nmap

```powershell
winget install Insecure.Nmap #windows
# Verify installation
nmap --version
```

### Step 4: Install Python Dependencies

```powershell
# Install project-wide dependencies
pip install -r requirements.txt
```

### Step 5: Install Frontend Dependencies

```powershell
cd ..\frontend
npm install
```

---

##  Tutorial: Getting Started

This guide provides step-by-step instructions for using each module of the project.

###  Scenario 1: Generate an Exploit (CLI Mode)

**Goal**: Generate an exploitation script for the Heartbleed vulnerability (CVE-2014-0160).

#### 1. Start Ollama
```powershell
# In a separate terminal
ollama serve
```

#### 2. Launch Exploit Generator
```powershell
cd Attaque_LLM
.\venv\Scripts\Activate.ps1
python main.py
```

#### 3. Follow the Interactive Workflow
```text
============================================================
 CVE Exploit Script Generator
  Educational and Ethical Use Only
============================================================

Target CVE (e.g., CVE-2014-0160): CVE-2014-0160

Target IP Address (e.g., 192.168.1.10): 192.168.56.101

 Mode: Direct Heartbleed Detection with Nmap

Scan Options:
  1. Auto-detect SSL/TLS ports (Recommended)
  2. Manually specify ports

Selection (1/2, Enter=1): 1
```

#### 4. Select LLM Model
```text
 Available Models (2):
   1. mistral:latest
   2. codestral:latest

Select a model (number or name, Enter for 1st): 2
```

#### 5. Retrieve Generated Script
The script is automatically saved in `Attaque_LLM/scripts/`:
```text
 Script saved: scripts/exploit_CVE_2014_0160_20251127_143022.py
```

---

###  Scenario 2: Generate IDS Rules (CLI Mode)

**Goal**: Create Suricata rules to detect Heartbleed exploitation attempts.

#### 1. Launch IDS Generator
```powershell
cd IDS_LLM
python main.py
```

#### 2. Follow the Workflow
```text
============================================================
 IDS Rule Script Generator
============================================================

CVE to defend (e.g., CVE-2014-0160): CVE-2014-0160

 Available Models (2):
   1. mistral:latest
   2. codestral:latest

Select a model: 1

 Generating IDS rules for CVE-2014-0160...

 Script saved: ./IDS_LLM/scripts/ids_CVE_2014_0160_20251127_144500.txt
```

#### 3. Integrate with Suricata (Optional)
```bash
sudo cp scripts/ids_CVE_*.txt /etc/suricata/rules/custom.rules
sudo suricatasc -c reload-rules
```

---

###  Scenario 3: Using the Web Interface (Orchestrated Mode)

**Goal**: Manage offensive and defensive generation via the graphical interface.

#### 1. Start Backend (Orchestrator)
```powershell
cd Interface_web\orchestrator
uvicorn app.main:app --reload --port 8000
```
*Wait for: `INFO: Application startup complete.`*

#### 2. Start React Frontend
```powershell
# In a new terminal
cd Interface_web\frontend
npm start
```
The application will open automatically at `http://localhost:3000`.

#### 3. Create a Scenario
1. **Enter CVE**: Input `CVE-2021-44228` (Log4Shell).
2. **Enable RAG**: Check " Use RAG" for context enrichment.
3. **Generate**: Click "Generate Script & IDS Rules".

#### 4. Refine with LLM Feedback
If the generated scripts require adjustment:
1. Go to the "Request LLM Refinement" section.
2. Describe the desired changes:
   ```text
   Add error handling for connection timeouts.
   IDS rules must also detect obfuscated variants.
   ```
3. Click "Send Feedback to LLM".

#### 5. Validate and Execute
1. Check the human validation boxes for the script and rules.
2. Click "Evaluate Code Quality" to get a score.
3. Click "Execute Simulation on Lab".

---

###  Scenario 4: Using RAG (Contextual Enrichment)

**Goal**: Improve exploit quality using NVD data.

#### 1. Initialize RAG Database
The RAG system uses NVD (National Vulnerability Database) JSON files. The vector database is created automatically on first run:

```powershell
cd Attaque_LLM
python -c "from rag_engine import initialize_knowledge_base; initialize_knowledge_base()"
```
```text
 Initializing RAG (Data Ingestion)...
 Reading and ingesting CVE_info_rag/nvdcve-2.0-2025.json...
 15,234 CVEs found
 Vectorizing 45,000 documents (this may take time)...
 Knowledge base created and saved.
```

#### 2. Test Retrieval
```python
from rag_engine import get_cve_context

context = get_cve_context("CVE-2021-44228")
print(context)
```

#### 3. Automatic Enrichment
When using `llm_generator_rag.py`, NVD context is automatically injected into the LLM prompt, enhancing the accuracy of generated scripts.

---

##  Module Details

###  Attaque_LLM - Exploit Generation

**Features:**
-  Python exploit generation via LLM (Ollama).
-  Automatic Nmap scanning for vulnerable ports.
-  Auto-detection of SSL/TLS ports.
-  Support for 8+ major CVEs with NSE scripts.
-  RAG for contextual enrichment (ChromaDB).
-  REST API for orchestrator integration.

**Supported CVEs:**

| CVE | Vulnerability | Ports | NSE Script |
| :--- | :--- | :--- | :--- |
| CVE-2014-0160 | Heartbleed | SSL/TLS auto | ssl-heartbleed  |
| CVE-2017-0144 | EternalBlue | 445, 139 | smb-vuln-ms17-010  |
| CVE-2021-44228 | Log4Shell | 8080, 443 | - |
| CVE-2017-5638 | Apache Struts | 8080, 80 | http-vuln-cve2017-5638  |
| CVE-2019-0708 | BlueKeep | 3389 | rdp-vuln-ms12-020  |
| CVE-2014-6271 | Shellshock | 80, 443 | http-shellshock  |

 [Full Documentation](./Attaque_LLM/README.md)

---

###  IDS_LLM - IDS Rule Generation

**Features:**
-  Suricata rule generation via LLM.
-  Multi-model Ollama support.
-  Generic rules covering exploitation variants.
-  Automatic explanatory comments.
-  Compatible with any CVE.

**Output Format:**
```suricata
# IDS Rules for CVE-2014-0160 (Heartbleed)
alert tls any any -> any any (
    msg:"HEARTBLEED Exploitation Attempt";
    flow:established,to_server;
    content:"|18 03|"; depth:2;
    sid:1000001; rev:1;
    reference:cve,2014-0160;
)
```

 [Full Documentation](./IDS_LLM/README.md)

---

###  Interface_web - Orchestrator

**Features:**
-  Modern React interface (Dark Mode).
-  FastAPI Backend with REST API.
-  Scenario creation and management.
-  Coupled attack/defense generation.
-  Feedback loop for LLM refinement.
-  Automated code quality evaluation.
-  Execution simulation (Mock).
-  Integrated RAG option.

**API Endpoints:**

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| POST | `/scenarios` | Create a scenario |
| GET | `/scenarios` | List scenarios |
| POST | `/scenarios/{id}/generate` | Generate script + IDS |
| POST | `/scenarios/{id}/refine` | Refine with feedback |
| POST | `/scenarios/{id}/evaluate` | Evaluate quality |
| PUT | `/scenarios/{id}/override` | Manual override |
| POST | `/runs/{id}/execute` | Execute simulation |

 [Full Documentation](./Interface_web/README.md)

---

##  Technology Stack

| Category | Technologies |
| :--- | :--- |
| **AI / LLM** | Ollama, Mistral, Codestral, LangChain |
| **RAG** | ChromaDB, HuggingFace Embeddings (all-MiniLM-L6-v2) |
| **Security** | Nmap, NSE Scripts, Suricata |
| **Backend** | Python 3.10+, FastAPI, SQLAlchemy, Pydantic |
| **Frontend** | React 19, JavaScript |
| **Database** | SQLite (Orchestrator), ChromaDB (RAG) |

---

##  Troubleshooting

### Common Issues

####  "Unable to connect to Ollama"
```powershell
# Verify Ollama is running
ollama serve

# Check installed models
ollama list
```

####  "Model not found"
```powershell
ollama pull mistral
ollama pull codestral
```

####  "Nmap not found"
```powershell
# Install Nmap
winget install Insecure.Nmap

# Verify PATH
nmap --version
```

####  "RAG Error: module not found"
```powershell
pip install langchain-huggingface langchain-chroma langchain-core
```

####  "Frontend does not start"
```powershell
cd Interface_web\frontend
npm install
npm start
```

####  "CORS error on API"
Ensure the backend is running on port 8000:
```powershell
uvicorn app.main:app --reload --port 8000
```

---

##  Ethical Considerations

###  Important Warning

This project was developed strictly for **educational purposes** to understand attack and defense mechanisms in cybersecurity.

### Usage Guidelines

 **AUTHORIZED**:
- Controlled environments (VMs, isolated labs).
- Academic research.
- Security training.
- Testing on systems with explicit written permission.

 **PROHIBITED**:
- Attacks on systems without authorization.
- Malicious use.
- Distribution for illegal purposes.
- Testing on production systems.

---

##  Resources

### Artificial Intelligence
- [Ollama](https://ollama.ai/) - Local LLM Server
- [Mistral AI](https://mistral.ai/) - LLM Models
- [LangChain](https://python.langchain.com/) - RAG Framework
- [ChromaDB](https://www.trychroma.com/) - Vector Database

### Cybersecurity
- [CVE Database (MITRE)](https://cve.mitre.org/)
- [NVD (NIST)](https://nvd.nist.gov/) - CVE Data for RAG
- [Nmap](https://nmap.org/)
- [Suricata](https://suricata.io/)

### Module Documentation
- [ Attaque_LLM](./Attaque_LLM/README.md)
- [ IDS_LLM](./IDS_LLM/README.md)
- [ Interface_web](./Interface_web/README.md)

---

##  Team

**Group 52** - Class of 2025  
Applied Research Project (PRAPP)

---

*Last Updated: November 2025*
