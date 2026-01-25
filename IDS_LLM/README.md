# IDS_LLM - Générateur de Règles IDS Automatiques

## Description

Ce module utilise l'**intelligence artificielle générative** (Ollama) pour créer automatiquement des **règles IDS (Intrusion Detection System)** pour **Suricata** basées sur des vulnérabilités CVE.

## Fonctionnalités

-  Génération automatique de règles Suricata via LLM
-  Détection multi-modèles Ollama (sélection interactive)
-  Règles génériques couvrant toutes les variantes d'exploitation
-  Commentaires explicatifs dans les règles générées
-  Sauvegarde automatique avec timestamp
-  Support de multiples CVE

## Prérequis

### Logiciels
- **Ollama** : Serveur LLM local (`ollama serve`)
- **Modèle LLM** : Au moins un modèle installé (ex: `ollama pull mistral`)
- **Python 3.10+**
- **Suricata** (optionnel, pour tester les règles générées)

### Dépendances Python
- `requests` : Communication avec l'API Ollama

## Installation

```powershell
# Depuis le dossier racine du projet
cd IDS_LLM

# Créer un environnement virtuel (optionnel mais recommandé)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Installer les dépendances
pip install requests
```

## Utilisation

### 1. Démarrer Ollama

```powershell
ollama serve
```

Laissez cette fenêtre ouverte en arrière-plan.

### 2. Exécuter le générateur

```powershell
python main.py
```

### 3. Interface Interactive

Le programme vous guidera à travers :

1. **Choix de la CVE** à détecter (ex: CVE-2014-0160 pour Heartbleed)
2. **Sélection du modèle LLM** parmi ceux installés localement
3. **Génération automatique** des règles IDS
4. **Sauvegarde** dans `scripts/ids_CVE_XXXX_XXXXXXXX.txt`

## Exemple d'Utilisation

```
============================================================
 Générateur de Scripts de règles IDS
============================================================

CVE à défendre (ex: CVE-2014-0160): CVE-2014-0160

 Récupération des modèles Ollama disponibles...

 Modèles disponibles (2):
   1. mistral:latest
   2. codestral:latest

Choisissez un modèle (numéro ou nom, Entrée pour le 1er): 1
Modèle sélectionné: mistral:latest

 Génération des règles IDS pour CVE-2014-0160...

============================================================
 Script généré
============================================================

 Script sauvegardé: ./IDS_LLM/scripts/ids_CVE_2014_0160_20251119_143022.txt
```

## Structure des Règles Générées

Les règles IDS générées suivent le format **Suricata** :

```suricata
# Règles IDS pour CVE-2014-0160
# Généré le 2025-11-19 14:30:22

# Détection de tentative d'exploitation Heartbleed (CVE-2014-0160)
alert tls any any -> any any (msg:"HEARTBLEED Exploitation Attempt"; \
    flow:established,to_server; \
    content:"|18 03|"; depth:2; \
    content:"|01|"; distance:1; within:1; \
    byte_test:2,>,16384,3; \
    classtype:attempted-admin; \
    sid:1000001; rev:1; \
    reference:cve,2014-0160;)

# Détection de réponse Heartbleed anormale
alert tls any any -> any any (msg:"HEARTBLEED Response Anomaly"; \
    flow:established,to_client; \
    content:"|18 03|"; depth:2; \
    byte_test:2,>,16384,3; \
    classtype:successful-admin; \
    sid:1000002; rev:1; \
    reference:cve,2014-0160;)
```

## Prompt LLM Utilisé

Le générateur utilise un prompt optimisé pour obtenir des règles précises :

```
En tant qu'analyste de sécurité défensif expérimenté, je souhaite obtenir 
des règles IDS pour Suricata. Mon objectif est de pouvoir détecter toute 
tentative d'exploitation provenant d'une machine virtuelle d'attaque.

Voici la CVE que je souhaite détecter : {cve}, vous devez donner l'ensemble 
complet des règles IDS pour Suricata qui garantissent la détection de cette 
exploitation.

Règles à suivre ABSOLUMENT :
- Réponds UNIQUEMENT avec les règles IDS commentées.
- AUCUNE phrase, explication ou justification.
- Les règles doivent être justes, complètes, utilisant les mots-clés 
  d'analyseur de protocole si disponibles pour une détection maximale.
- Les règles doivent être généralistes pour couvrir toutes les variantes 
  possibles de l'exploitation.
```

## Intégration avec Suricata

### 1. Copier les règles générées

```bash
sudo cp ./IDS_LLM/scripts/ids_CVE_*.txt /etc/suricata/rules/custom.rules
```

### 2. Activer les règles dans Suricata

Éditez `/etc/suricata/suricata.yaml` :

```yaml
rule-files:
  - custom.rules
```

### 3. Recharger Suricata

```bash
sudo suricatasc -c reload-rules
```

### 4. Vérifier les alertes

```bash
sudo tail -f /var/log/suricata/fast.log
```

## Structure du Module

```
IDS_LLM/
├── main.py              # Point d'entrée principal
├── llm_generator.py     # Génération via Ollama API
├── scripts/             # Règles IDS générées
└── README.md            # Cette documentation
```

## Workflow

```
┌──────────────┐
│   main.py    │
└──────┬───────┘
       │
       ▼
┌──────────────────┐
│ User Input       │
│ (CVE choice)     │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ llm_generator.py │
│                  │
│ get_available_   │
│ models()         │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ Model Selection  │
│ (User choice)    │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ llm_generator.py │
│                  │
│ generate_ids_    │◄──── Ollama API
│ script()         │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ save_script()    │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  scripts/        │
│  ids_CVE_*.txt   │
└──────────────────┘
```

## CVE Supportées

Le générateur peut créer des règles pour n'importe quelle CVE. Exemples testés :

- **CVE-2014-0160** : Heartbleed (OpenSSL)
- **CVE-2021-44228** : Log4Shell (Log4j)
- Et toute autre CVE...

## Dépannage

### Erreur "Impossible de se connecter à Ollama"
- Vérifiez qu'Ollama est en cours d'exécution : `ollama serve`
- Vérifiez que le port 11434 n'est pas bloqué

### Aucun modèle disponible
- Installez un modèle : `ollama pull mistral`
- Vérifiez les modèles installés : `ollama list`

### Règles générées incorrectes
- Essayez un modèle différent (ex: `codestral` pour du code)
- Vérifiez la syntaxe Suricata : `suricata -T -c /etc/suricata/suricata.yaml`

### Timeout de génération
- Augmentez le timeout dans `llm_generator.py` (ligne `timeout=560`)
- Utilisez un modèle plus léger

## Ressources

- [Suricata Documentation](https://suricata.readthedocs.io/)
- [Suricata Rule Format](https://suricata.readthedocs.io/en/latest/rules/intro.html)
- [Ollama API Reference](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [CVE Database](https://cve.mitre.org/)