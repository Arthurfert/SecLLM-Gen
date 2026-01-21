# SecLLM-Gen

**Projet de Recherche Appliquée (PRAPP)**

## 📋 Vue d'Ensemble

Ce projet explore l'utilisation de l'**intelligence artificielle générative** appliquée à la **cybersécurité offensive et défensive**. Il permet de générer automatiquement des scripts d'exploitation de vulnérabilités (CVE) ainsi que des règles de détection IDS correspondantes, le tout piloté par des modèles de langage (LLM) locaux via Ollama.

### Trois Modules Complémentaires

| Module | Description | Statut |
|--------|-------------|--------|
| 🔴 **Attaque_LLM** | Génération automatique d'exploits CVE avec RAG | ✅ Fonctionnel |
| 🛡️ **IDS_LLM** | Création de règles de détection Suricata | ✅ Fonctionnel |
| 🌐 **Interface_web** | Orchestration avec interface React + FastAPI | ✅ Fonctionnel |

⚠️ **Avertissement** : Projet à usage **strictement éducatif** dans le cadre du PRAPP 2025.

---

## 📚 Table des Matières

1. [Objectifs du Projet](#-objectifs-du-projet)
2. [Architecture](#-architecture)
3. [Prérequis](#-prérequis)
4. [Installation Rapide](#-installation-rapide)
5. [Tutoriel : Prise en Main](#-tutoriel--prise-en-main)
6. [Modules Détaillés](#-modules-détaillés)
7. [Technologies](#-technologies)
8. [Dépannage](#-dépannage)
9. [Considérations Éthiques](#-considérations-éthiques)
10. [Ressources](#-ressources)

---

## 🎯 Objectifs du Projet

### 1. Démontrer les capacités de l'IA en cybersécurité
- Automatisation de la génération d'exploits via LLM
- Automatisation de la défense avec règles IDS générées
- Analyse de vulnérabilités enrichie par RAG (Retrieval-Augmented Generation)

### 2. Comparer offensive vs défensive
- Mesurer l'efficacité des exploits générés
- Évaluer la qualité des règles IDS créées
- Identifier les limites de chaque approche

### 3. Orchestration centralisée
- Interface web unifiée pour piloter les deux modules
- Boucle de feedback pour affiner les scripts générés
- Évaluation automatique de la qualité du code

---

## 🏗️ Architecture

```
52/
├── 📁 Attaque_LLM/              # Module offensif
│   ├── main.py                  # Point d'entrée principal
│   ├── llm_generator.py         # Interface Ollama (base)
│   ├── llm_generator_rag.py     # Interface Ollama avec RAG
│   ├── rag_engine.py            # Moteur RAG (ChromaDB + HuggingFace)
│   ├── nmap_scanner.py          # Détection de vulnérabilités
│   ├── cve_database.py          # Base CVE locale
│   ├── api_server.py            # API REST pour l'orchestrateur
│   ├── requirements.txt         # Dépendances Python
│   ├── 📁 CVE_info_rag/         # Données NVD pour le RAG
│   ├── 📁 chroma_db/            # Base vectorielle ChromaDB
│   └── 📁 scripts/              # Scripts d'exploits générés
│
├── 📁 IDS_LLM/                  # Module défensif
│   ├── main.py                  # Point d'entrée principal
│   ├── llm_generator.py         # Interface Ollama
│   └── 📁 scripts/              # Règles IDS générées
│
├── 📁 Interface_web/            # Interface centralisée
│   ├── 📁 orchestrator/         # Backend FastAPI
│   │   ├── app/
│   │   │   ├── main.py          # API REST
│   │   │   ├── models.py        # Modèles Pydantic/SQLAlchemy
│   │   │   ├── db.py            # Gestion base de données
│   │   │   └── 📁 services/     # Services métier
│   │   └── requirements.txt
│   └── 📁 frontend/             # Frontend React
│       ├── src/App.js           # Application principale
│       └── package.json
│
└── README.md                    # Ce fichier
```

---

## 📋 Prérequis

### Logiciels Requis

| Logiciel | Version | Description |
|----------|---------|-------------|
| **Python** | 3.10+ | Langage principal |
| **Node.js** | 18+ | Pour le frontend React |
| **Ollama** | Latest | Serveur LLM local |
| **Nmap** | 7.0+ | Scanner de vulnérabilités (optionnel) |

### Modèles LLM Recommandés

| Modèle | Utilisation | Commande |
|--------|-------------|----------|
| **Mistral** | Usage général | `ollama pull mistral` |
| **Codestral** | Génération de code | `ollama pull codestral` |
| **Llama3** | Alternative | `ollama pull llama3` |

### Optionnel

- **Suricata** : Pour tester les règles IDS générées
- **GPU NVIDIA** : Accélère la génération (CUDA)

---

## 🚀 Installation Rapide

### Étape 1 : Cloner le dépôt

```powershell
git clone <url-du-depot>
cd 52
```

### Étape 2 : Installer Ollama

```powershell
# Windows (winget)
winget install Ollama.Ollama

# Télécharger un modèle
ollama pull mistral
ollama pull codestral  # Recommandé pour le code
```

### Étape 3 : Installer Nmap

```powershell
winget install Insecure.Nmap
# Vérifier l'installation
nmap --version
```

### Étape 4 : Installer les dépendances Python

```powershell
# Module Attaque (avec RAG)
cd Attaque_LLM
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Module IDS
cd ..\IDS_LLM
pip install requests

# Orchestrateur (Interface_web)
cd ..\Interface_web\orchestrator
pip install -r requirements.txt
```

### Étape 5 : Installer le Frontend React

```powershell
cd ..\frontend
npm install
```

---

## 🎓 Tutoriel : Prise en Main

Ce tutoriel vous guide pas à pas pour utiliser chaque module du projet.

### 📘 Scénario 1 : Générer un Exploit (Mode CLI)

**Objectif** : Générer un script d'exploitation pour la vulnérabilité Heartbleed (CVE-2014-0160)

#### Étape 1 : Démarrer Ollama

```powershell
# Dans un terminal séparé
ollama serve
```

#### Étape 2 : Lancer le générateur d'exploits

```powershell
cd Attaque_LLM
.\venv\Scripts\Activate.ps1
python main.py
```

#### Étape 3 : Suivre le workflow interactif

```
============================================================
🔐 Générateur de Scripts d'Exploitation CVE
⚠️  Usage éducatif et éthique uniquement
============================================================

CVE à exploiter (ex: CVE-2014-0160): CVE-2014-0160

Adresse IP de la cible (ex: 192.168.1.10): 192.168.56.101

🎯 Mode: Détection Heartbleed directe avec Nmap

Options de scan:
  1. Détection automatique des ports SSL/TLS (recommandé)
  2. Spécifier manuellement les ports

Votre choix (1/2, Entrée=1): 1
```

#### Étape 4 : Sélectionner le modèle LLM

```
📋 Modèles disponibles (2):
   1. mistral:latest
   2. codestral:latest

Choisissez un modèle (numéro ou nom, Entrée pour le 1er): 2
```

#### Étape 5 : Récupérer le script généré

Le script est automatiquement sauvegardé dans `Attaque_LLM/scripts/`:

```
✅ Script sauvegardé: scripts/exploit_CVE_2014_0160_20251127_143022.py
```

---

### 📗 Scénario 2 : Générer des Règles IDS (Mode CLI)

**Objectif** : Créer des règles Suricata pour détecter une exploitation Heartbleed

#### Étape 1 : Lancer le générateur IDS

```powershell
cd IDS_LLM
python main.py
```

#### Étape 2 : Suivre le workflow

```
============================================================
🔐 Générateur de Scripts de règles IDS
============================================================

CVE à défendre (ex: CVE-2014-0160): CVE-2014-0160

📋 Modèles disponibles (2):
   1. mistral:latest
   2. codestral:latest

Choisissez un modèle: 1

🔄 Génération des règles IDS pour CVE-2014-0160...

✅ Script sauvegardé: ./IDS_LLM/scripts/ids_CVE_2014_0160_20251127_144500.txt
```

#### Étape 3 : Intégrer dans Suricata (optionnel)

```bash
sudo cp scripts/ids_CVE_*.txt /etc/suricata/rules/custom.rules
sudo suricatasc -c reload-rules
```

---

### 📙 Scénario 3 : Utiliser l'Interface Web (Mode Orchestré)

**Objectif** : Piloter la génération offensive/défensive via l'interface graphique

#### Étape 1 : Démarrer le backend (orchestrateur)

```powershell
cd Interface_web\orchestrator
uvicorn app.main:app --reload --port 8000
```

Vous devriez voir :
```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete.
```

#### Étape 2 : Démarrer le frontend React

```powershell
# Dans un nouveau terminal
cd Interface_web\frontend
npm start
```

L'application s'ouvre automatiquement sur `http://localhost:3000`

#### Étape 3 : Créer un scénario

1. **Renseigner la CVE** : Entrez `CVE-2021-44228` (Log4Shell)
2. **Activer le RAG** : Cochez la case "🔍 Utiliser le RAG" pour enrichir le contexte
3. **Générer** : Cliquez sur "Générer script & règles IDS"

#### Étape 4 : Affiner avec le feedback LLM

Si les scripts générés ne conviennent pas :

1. Dans la section "Demander un raffinement au LLM"
2. Décrivez les modifications souhaitées :
   ```
   Ajoute une gestion d'erreurs pour les connexions timeout.
   Les règles IDS doivent aussi détecter les variantes obfusquées.
   ```
3. Cliquez sur "Envoyer feedback au LLM"

#### Étape 5 : Valider et exécuter

1. Cochez les cases de validation humaine pour le script et les règles
2. Cliquez sur "Évaluer la qualité du code" pour obtenir un score
3. Cliquez sur "Exécuter la simulation sur le lab"

---

### 📕 Scénario 4 : Utiliser le RAG (Enrichissement Contextuel)

**Objectif** : Améliorer la qualité des exploits générés avec des données NVD

#### Étape 1 : Initialiser la base RAG

Le RAG utilise les fichiers JSON du NVD (National Vulnerability Database). Au premier lancement, la base vectorielle est créée automatiquement :

```powershell
cd Attaque_LLM
python -c "from rag_engine import initialize_knowledge_base; initialize_knowledge_base()"
```

```
🔄 Initialisation du RAG (Ingestion des données)...
📂 Lecture et ingestion de CVE_info_rag/nvdcve-2.0-2025.json...
📄 15234 CVEs trouvées
🧠 Vectorisation de 45000 documents (patience)...
✅ Base de connaissances créée et sauvegardée.
```

#### Étape 2 : Tester la recherche

```python
from rag_engine import get_cve_context

context = get_cve_context("CVE-2021-44228")
print(context)
```

#### Étape 3 : Le RAG enrichit automatiquement les prompts

Quand vous utilisez `llm_generator_rag.py`, le contexte NVD est automatiquement ajouté au prompt envoyé au LLM, améliorant la précision des scripts générés.

---

## 📦 Modules Détaillés

### 🔴 Attaque_LLM - Génération d'Exploits

**Fonctionnalités :**
- ✅ Génération d'exploits Python via LLM (Ollama)
- ✅ Scan Nmap automatique des ports vulnérables
- ✅ Détection automatique des ports SSL/TLS
- ✅ Support de 8+ CVE majeures avec scripts NSE
- ✅ RAG pour enrichissement contextuel (ChromaDB)
- ✅ API REST pour intégration avec l'orchestrateur

**CVE Supportées :**

| CVE | Vulnérabilité | Ports | Script NSE |
|-----|---------------|-------|------------|
| CVE-2014-0160 | Heartbleed | SSL/TLS auto | ssl-heartbleed ✅ |
| CVE-2017-0144 | EternalBlue | 445, 139 | smb-vuln-ms17-010 ✅ |
| CVE-2021-44228 | Log4Shell | 8080, 443 | - |
| CVE-2017-5638 | Apache Struts | 8080, 80 | http-vuln-cve2017-5638 ✅ |
| CVE-2019-0708 | BlueKeep | 3389 | rdp-vuln-ms12-020 ✅ |
| CVE-2014-6271 | Shellshock | 80, 443 | http-shellshock ✅ |

➡️ [Documentation complète](./Attaque_LLM/README.md)

---

### 🛡️ IDS_LLM - Génération de Règles IDS

**Fonctionnalités :**
- ✅ Génération de règles Suricata via LLM
- ✅ Support multi-modèles Ollama
- ✅ Règles génériques couvrant les variantes d'exploitation
- ✅ Commentaires explicatifs automatiques
- ✅ Compatible avec toutes les CVE

**Format de sortie :**
```suricata
# Règles IDS pour CVE-2014-0160 (Heartbleed)
alert tls any any -> any any (
    msg:"HEARTBLEED Exploitation Attempt";
    flow:established,to_server;
    content:"|18 03|"; depth:2;
    sid:1000001; rev:1;
    reference:cve,2014-0160;
)
```

➡️ [Documentation complète](./IDS_LLM/README.md)

---

### 🌐 Interface_web - Orchestrateur

**Fonctionnalités :**
- ✅ Interface React moderne (dark mode)
- ✅ Backend FastAPI avec API REST
- ✅ Création et gestion de scénarios
- ✅ Génération couplée attaque/défense
- ✅ Boucle de feedback pour raffinement LLM
- ✅ Évaluation automatique de la qualité du code
- ✅ Simulation d'exécution (mock)
- ✅ Option RAG intégrée

**Endpoints API :**

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| POST | `/scenarios` | Créer un scénario |
| GET | `/scenarios` | Lister les scénarios |
| POST | `/scenarios/{id}/generate` | Générer script + IDS |
| POST | `/scenarios/{id}/refine` | Raffiner avec feedback |
| POST | `/scenarios/{id}/evaluate` | Évaluer la qualité |
| PUT | `/scenarios/{id}/override` | Modifier manuellement |
| POST | `/runs/{id}/execute` | Exécuter la simulation |

➡️ [Documentation complète](./Interface_web/README.md)

---

## 🔧 Technologies

| Catégorie | Technologies |
|-----------|-------------|
| **IA / LLM** | Ollama, Mistral, Codestral, LangChain |
| **RAG** | ChromaDB, HuggingFace Embeddings (all-MiniLM-L6-v2) |
| **Sécurité** | Nmap, NSE Scripts, Suricata |
| **Backend** | Python 3.10+, FastAPI, SQLAlchemy, Pydantic |
| **Frontend** | React 19, JavaScript |
| **Base de données** | SQLite (orchestrateur), ChromaDB (RAG) |

---

## 🔧 Dépannage

### Problèmes courants

#### ❌ "Impossible de se connecter à Ollama"
```powershell
# Vérifier qu'Ollama tourne
ollama serve

# Vérifier les modèles installés
ollama list
```

#### ❌ "Model not found"
```powershell
ollama pull mistral
ollama pull codestral
```

#### ❌ "Nmap non trouvé"
```powershell
# Installer Nmap
winget install Insecure.Nmap

# Vérifier le PATH
nmap --version
```

#### ❌ "Erreur RAG : module not found"
```powershell
pip install langchain-huggingface langchain-chroma langchain-core
```

#### ❌ "Le frontend ne démarre pas"
```powershell
cd Interface_web\frontend
npm install
npm start
```

#### ❌ "CORS error sur l'API"
Vérifiez que le backend tourne sur le port 8000 :
```powershell
uvicorn app.main:app --reload --port 8000
```

---

## ⚖️ Considérations Éthiques

### ⚠️ Avertissement Important

Ce projet a été développé dans un cadre **strictement éducatif** pour comprendre les mécanismes d'attaque et de défense en cybersécurité.

### Règles d'Usage

✅ **AUTORISÉ** :
- Environnements contrôlés (VMs, labs isolés)
- Recherche académique
- Formation en sécurité
- Tests sur systèmes avec autorisation écrite

❌ **INTERDIT** :
- Attaques sur systèmes sans autorisation
- Utilisation malveillante
- Distribution à des fins illégales
- Tests sur systèmes de production

---

## 🔗 Ressources

### Intelligence Artificielle
- [Ollama](https://ollama.ai/) - Serveur LLM local
- [Mistral AI](https://mistral.ai/) - Modèles LLM
- [LangChain](https://python.langchain.com/) - Framework RAG
- [ChromaDB](https://www.trychroma.com/) - Base vectorielle

### Cybersécurité
- [CVE Database (MITRE)](https://cve.mitre.org/)
- [NVD (NIST)](https://nvd.nist.gov/) - Données CVE pour le RAG
- [Nmap](https://nmap.org/)
- [Suricata](https://suricata.io/)

### Documentation des modules
- [📕 Attaque_LLM](./Attaque_LLM/README.md)
- [📗 IDS_LLM](./IDS_LLM/README.md)
- [📘 Interface_web](./Interface_web/README.md)

---

## 👥 Équipe

**Groupe 52** - Promotion 2025  
Projet de Recherche Appliquée (PRAPP)

---

*Dernière mise à jour : Novembre 2025*
