 Orchestrator PRAPP
Assistant de Pentest · LLM + IDS (Version Mock – Développement Local)

Ce projet contient :

un backend FastAPI qui orchestre la génération de scripts d’attaque et de règles IDS (mock)

un frontend React jouant le rôle d’interface utilisateur

un flux complet Human-In-The-Loop (validation humaine obligatoire avant exécution)

Ce prototype permet au groupe PRAPP de travailler en agile avant l’intégration finale :

Proxmox (VM Attaque / VM Cible / IDS Snort)

Exécution SSH réelle

LLM sur GPU (serveur distant)

Scans Nmap automatisés

 1. Structure du projet
Orchestrator/
│
├── app/
│   ├── main.py
│   ├── models.py
│   ├── db.py
│   ├── services/
│   │      ├── llm_service.py
│   │      └── orchestrator_service.py
│
├── frontend/
│   ├── src/
│   │   └── App.js
│
├── requirements.txt
├── env/                  # créé localement (non versionné normalement)
└── README.md

 2. Prérequis

Python ≥ 3.10

Node.js ≥ 18 (recommandé : Node 20+)

npm (installé avec Node)

Windows / macOS / Linux

 3. Installation du Backend FastAPI
3.1. Aller dans le dossier
cd Orchestrator

3.2. Créer un environnement virtuel
python -m venv env

3.3. Activer l’environnement

Windows PowerShell :

env\Scripts\activate


Linux / macOS :

source env/bin/activate

3.4. Installer les dépendances
pip install -r requirements.txt

▶ 4. Lancer le backend FastAPI
uvicorn app.main:app --reload


Attendu :

Uvicorn running on http://127.0.0.1:8000
Application startup complete.

Vérifier le backend

 http://127.0.0.1:8000/docs

(Swagger doit apparaître)

 5. Installation du Frontend React
5.1. Aller dans le dossier du frontend
cd frontend

5.2. Installer les dépendances
npm install

▶ 6. Lancer le frontend
npm start


Le navigateur s’ouvre sur :

 http://localhost:3000

 7. Communication Frontend ↔ Backend

Dans App.js :

const API_BASE = "http://127.0.0.1:8000";

 IMPORTANT — CORS dans FastAPI

Dans app/main.py, ceci doit être présent juste après la création de app :

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

‍ 8. Utilisation (Flux complet)

Lancer backend

Lancer frontend

Saisir une CVE (ex : CVE-2021-1234)

Cliquer sur Générer script & règles IDS

Modifier si besoin (Human-in-the-loop)

Cocher :

“Script validé par un humain”

“Règles IDS validées par un humain”

Cliquer sur Exécuter la simulation (mock)

Voir les logs mockés

 9. Tests rapides
Backend seul :
curl http://127.0.0.1:8000/scenarios

Frontend → Backend :

vérifier l’absence de "Failed to fetch".

 10. Dépannage
"Failed to fetch" dans le frontend → 3 causes possibles :

Backend non lancé

CORS manquant

Mauvaise URL API_BASE

Swagger ne s’affiche pas

Port déjà pris → essayer :

uvicorn app.main:app --reload --port 8001

 11. Contribution

Les routes du backend doivent rester stables

Le frontend doit fonctionner même avec des résultats mock

Toujours tester la génération + validation + exécution

 12. Licence & contexte

Projet académique — Module
PRAPP – IA générative & Cybermenaces
Version : Mock architecture – Pré-intégration Proxmox