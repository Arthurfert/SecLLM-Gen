# Interface Web - Orchestrateur PRAPP

##  Description

L'Interface Web est le **centre de commande** du projet PRAPP. Elle permet de piloter les modules d'attaque et de défense via une interface graphique moderne et intuitive, tout en offrant des fonctionnalités avancées comme le raffinement par LLM et l'évaluation automatique de la qualité du code.

##  Fonctionnalités

###  Gestion des Scénarios
- Création de scénarios basés sur des CVE
- Support du RAG (Retrieval-Augmented Generation) pour enrichir le contexte
- Instructions personnalisées pour le LLM

###  Génération Automatique
- Script d'attaque Python généré par LLM
- Règles IDS Suricata générées simultanément
- Boucle de feedback pour affiner les résultats

###  Évaluation de Qualité
- Score global sur 100
- Score détaillé pour le script d'attaque
- Score détaillé pour les règles IDS
- Feedback explicatif du LLM

###  Exécution Contrôlée
- Validation humaine obligatoire avant exécution
- Simulation sur environnement de lab (mock)
- Logs d'exécution détaillés

---

##  Architecture

```
Interface_web/
├──  orchestrator/          # Backend Python (FastAPI)
│   ├── requirements.txt      # Dépendances Python
│   └──  app/
│       ├── main.py           # API REST
│       ├── models.py         # Modèles Pydantic/SQLAlchemy
│       ├── db.py             # Gestion SQLite
│       └──  services/
│           ├── llm_service.py          # Interface Ollama
│           ├── orchestrator_service.py # Logique métier
│           ├── attacker_client.py      # Client module Attaque
│           ├── ids_client.py           # Client module IDS
│           └── code_evaluator.py       # Évaluateur de qualité
│
└──  frontend/              # Frontend React
    ├── package.json          # Dépendances NPM
    └──  src/
        ├── App.js            # Application principale
        ├── App.css           # Styles
        └── index.js          # Point d'entrée
```

---

##  Prérequis

### Backend (Orchestrator)
- **Python 3.10+**
- **Ollama** avec un modèle installé (mistral, codestral)
- **SQLite** (inclus dans Python)

### Frontend
- **Node.js 18+**
- **npm** ou **yarn**

---

##  Installation

### 1. Backend (Orchestrator)

```powershell
cd Interface_web\orchestrator

# Créer l'environnement virtuel
python -m venv venv
.\venv\Scripts\Activate.ps1

# Installer les dépendances
pip install -r requirements.txt
```

### 2. Frontend React

```powershell
cd Interface_web\frontend

# Installer les dépendances
npm install
```

---

## ▶ Lancement

### Étape 1 : Démarrer Ollama

```powershell
ollama serve
```

### Étape 2 : Démarrer le Backend

```powershell
cd Interface_web\orchestrator
.\venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --port 8000
```

Vérifiez que l'API répond :
```
http://127.0.0.1:8000/docs  # Documentation Swagger
```

### Étape 3 : Démarrer le Frontend

```powershell
cd Interface_web\frontend
npm start
```

L'application s'ouvre automatiquement sur `http://localhost:3000`

---

##  Guide d'Utilisation

### Étape 1 : Définir le Scénario

1. **Identifiant CVE** : Entrez la CVE à exploiter (ex: `CVE-2021-44228`)

2. **Instructions LLM** (optionnel) : Personnalisez la génération
   ```
   Utilise Python 3 uniquement.
   Évite les dépendances externes.
   Cible un serveur Apache 2.4.
   ```

3. **Option RAG** : Cochez " Utiliser le RAG" pour enrichir le contexte avec les données NVD

4. Cliquez sur **"Générer script & règles IDS"**

### Étape 2 : Validation et Raffinement

#### Modification manuelle
- Éditez directement le script d'attaque ou les règles IDS dans les zones de texte
- Cliquez sur **"Enregistrer les modifications"**

#### Raffinement par LLM
Si les scripts ne conviennent pas :

1. Décrivez les modifications dans la zone de feedback :
   ```
   Le script ne gère pas les erreurs de timeout.
   Ajoute une vérification du certificat SSL.
   Les règles IDS doivent détecter les payloads encodés en base64.
   ```

2. Cliquez sur **"Envoyer feedback au LLM"**

3. Le LLM régénère les scripts en tenant compte de vos retours

### Étape 2.5 : Évaluation de Qualité

1. Cliquez sur **"Évaluer la qualité du code"**

2. Consultez les scores :
   - **Score Global** : Note moyenne sur 100
   - **Script d'Attaque** : Qualité du code offensif
   - **Règles IDS** : Qualité des règles défensives

3. Lisez les feedbacks détaillés pour améliorer les scripts

### Étape 3 : Exécution

1. **Validation obligatoire** : Cochez les deux cases :
   -  Script d'attaque relu et validé par un humain
   -  Règles IDS relues et validées par un humain

2. Cliquez sur **"Exécuter la simulation sur le lab"**

3. Consultez les logs d'exécution :
   ```
   Attack success: True
   Detected by IDS: True
   
   Logs:
   [ATTACK] Connexion à la cible...
   [IDS] Règle sid:1000001 déclenchée
   ```

---

##  API REST

### Endpoints Disponibles

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/scenarios` | Créer un nouveau scénario |
| `GET` | `/scenarios` | Lister tous les scénarios |
| `POST` | `/scenarios/{id}/generate` | Générer script + IDS |
| `POST` | `/scenarios/{id}/refine` | Raffiner avec feedback |
| `POST` | `/scenarios/{id}/evaluate` | Évaluer la qualité |
| `GET` | `/scenarios/{id}/evaluation` | Récupérer l'évaluation |
| `PUT` | `/scenarios/{id}/override` | Modifier manuellement |
| `POST` | `/runs/{id}/execute` | Exécuter la simulation |
| `GET` | `/runs` | Lister les exécutions |

### Exemples d'utilisation

#### Créer un scénario
```bash
curl -X POST http://127.0.0.1:8000/scenarios \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2021-44228",
    "target_description": "Serveur Apache avec Log4j",
    "nmap_output": "8080/tcp open http",
    "use_rag": true
  }'
```

#### Générer les scripts
```bash
curl -X POST http://127.0.0.1:8000/scenarios/1/generate \
  -H "Content-Type: application/json" \
  -d '{
    "llm_instructions": "Utilise uniquement des requêtes HTTP GET"
  }'
```

#### Raffiner avec feedback
```bash
curl -X POST http://127.0.0.1:8000/scenarios/1/refine \
  -H "Content-Type: application/json" \
  -d '{
    "current_attack_script": "...",
    "current_ids_rules": "...",
    "feedback": "Ajoute une gestion des erreurs SSL"
  }'
```

---

##  Interface Utilisateur

### Palette de Couleurs (Dark Mode)

| Élément | Couleur |
|---------|---------|
| Background | `#050816` |
| Cards | `#0b1120` |
| Texte principal | `#e5e7eb` |
| Texte secondaire | `#9ca3af` |
| Accent primaire | `#22c55e` → `#6366f1` (gradient) |
| Accent warning | `#f59e0b` → `#ef4444` (gradient) |
| Erreur | `#ef4444` |
| Succès | `#4ade80` |

### États des Badges

| Badge | Couleur | Signification |
|-------|---------|---------------|
| En attente | Gris | Action non réalisée |
| Généré | Bleu | Scripts générés |
| Validé | Vert | Validation humaine OK |
| Évalué | Violet | Qualité évaluée |
| Simulation réalisée | Violet | Exécution terminée |

---

##  Configuration

### Variables d'environnement

Créez un fichier `.env` dans `orchestrator/` :

```env
# API Ollama
OLLAMA_HOST=http://localhost:11434

# Base de données
DATABASE_URL=sqlite:///./prapp.db

# Mode debug
DEBUG=true
```

### Configuration CORS

Par défaut, le CORS est ouvert pour le développement :

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restreindre en production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

##  Dépannage

### Le backend ne démarre pas

```powershell
# Vérifier les dépendances
pip install -r requirements.txt

# Vérifier le port
netstat -ano | findstr :8000
```

### Erreur CORS

Assurez-vous que :
1. Le backend tourne sur le port 8000
2. Le frontend fait les requêtes vers `http://127.0.0.1:8000`

### "Scenario not found"

La base de données SQLite est créée au premier démarrage. Si elle est corrompue :

```powershell
# Supprimer la base et redémarrer
Remove-Item orchestrator/prapp.db
uvicorn app.main:app --reload
```

### Le LLM ne répond pas

```powershell
# Vérifier Ollama
ollama serve
ollama list

# Tester une requête
ollama run mistral "Hello"
```

---

##  Structure des Modèles de Données

### ScenarioIn (Entrée)
```json
{
  "cve_id": "CVE-2021-44228",
  "target_description": "Description de la cible",
  "nmap_output": "Résultat du scan Nmap",
  "use_rag": true
}
```

### ScenarioOut (Sortie)
```json
{
  "id": 1,
  "cve_id": "CVE-2021-44228",
  "target_description": "...",
  "nmap_output": "...",
  "attack_script": "#!/usr/bin/env python3...",
  "ids_rules": "alert http any any...",
  "created_at": "2025-11-27T14:30:00"
}
```

### GenerationResult
```json
{
  "attack_script": "...",
  "ids_rules": "..."
}
```

### CodeEvaluationOut
```json
{
  "overall_score": 75,
  "attack_script_score": 80,
  "ids_rules_score": 70,
  "attack_feedback": "Le script est bien structuré...",
  "ids_feedback": "Les règles couvrent les cas principaux..."
}
```

---

##  Évolutions Futures

- [ ] Intégration Proxmox pour VMs dynamiques
- [ ] Exécution réelle des exploits (non mockée)
- [ ] Dashboard de statistiques
- [ ] Export des rapports en PDF
- [ ] Authentification utilisateur
- [ ] Multi-utilisateurs avec rôles

---

##  Ressources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [React Documentation](https://react.dev/)
- [Ollama API Reference](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [Pydantic Documentation](https://docs.pydantic.dev/)

---

*Module Interface_web - Projet PRAPP 2025*
