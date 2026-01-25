# 52 - Générateur de Scripts d'Exploitation CVE

## Description

Ce projet est un outil éducatif de cybersécurité qui utilise **Ollama** avec le modèle **Mistral** pour générer des scripts d'exploitation de vulnérabilités CVE (Common Vulnerabilities and Exposures). 

 **AVERTISSEMENT** : Cet outil est destiné uniquement à des fins éducatives et de recherche en sécurité informatique. L'utilisation malveillante de cet outil est strictement interdite et illégale.

## Fonctionnalités

- Génération automatique de scripts d'exploitation basés sur des identifiants CVE
- **Détection automatique des ports SSL/TLS** pour Heartbleed (s'adapte à n'importe quel OS)
- **Détection de vulnérabilités avec scripts NSE Nmap** (ssl-heartbleed, smb-vuln-ms17-010, etc.)
- **Scan Nmap intégré** pour détecter les ports vulnérables sur la cible
- **Priorisation automatique** des ports réellement vulnérables
- **Base de données CVE** avec mapping automatique vers les ports sensibles
- Utilisation d'Ollama (API locale) pour des performances optimales
- Pas de téléchargement de modèle nécessaire (utilise Ollama)
- Génération rapide et efficace
- Sauvegarde automatique des scripts générés dans le dossier `scripts/`
- Interface simple et interactive en ligne de commande

## CVE supportées avec auto-détection des ports

Le script reconnaît automatiquement les CVE suivantes et leurs ports typiques :

| CVE | Service | Ports typiques | Script NSE |
|-----|---------|----------------|------------|
| CVE-2014-0160 | OpenSSL (Heartbleed) | Détection auto SSL/TLS* | ssl-heartbleed  |
| CVE-2017-0144 | SMB (EternalBlue) | 445, 139 | smb-vuln-ms17-010  |
| CVE-2021-44228 | Log4j | 8080, 443, 9200 | - |
| CVE-2017-5638 | Apache Struts | 8080, 80, 443 | http-vuln-cve2017-5638  |
| CVE-2019-0708 | RDP (BlueKeep) | 3389 | rdp-vuln-ms12-020  |
| CVE-2014-6271 | Bash (Shellshock) | 80, 443, 8080 | http-shellshock  |
| CVE-2012-1823 | PHP-CGI | 80, 443, 8080 | - |
| CVE-2015-1427 | Elasticsearch | 9200 | - |

 = Détection automatique de la vulnérabilité avec script NSE  
\* Pour Heartbleed, le système détecte automatiquement **tous les ports SSL/TLS ouverts** (pas de ports fixes) pour s'adapter à tous les OS et configurations

## Prérequis

### Logiciels
- **Ollama** : Doit être installé et en cours d'exécution
- **Modèle Mistral** : Déjà installé dans Ollama (`ollama pull mistral`)
- **Nmap** (optionnel) : Pour le scan automatique des ports vulnérables
- **Python 3.10+**
- Bibliothèque Python : `requests`

### Matériel
- CPU moderne (Ollama gère l'optimisation automatiquement), GPU si possible
- Espace disque : Minimal (~quelques Mo pour le projet)

## Installation

### 1. Installez Ollama (si ce n'est pas déjà fait)

```powershell
# Téléchargez depuis https://ollama.ai
# Ou utilisez winget sur windows
winget install Ollama.Ollama
```

### 2. Installez le modèle Mistral (si ce n'est pas déjà fait)

```powershell
ollama pull mistral
```

### 3. Installez Nmap (optionnel mais recommandé)

```powershell
# Téléchargez depuis https://nmap.org/download.html
# Ou utilisez winget
winget install Insecure.Nmap
```

Assurez-vous que Nmap est dans votre PATH.

### 3. Clonez ce dépôt

```bash
git clone <url-du-depot>
cd 52
```

### 4. Créez un environnement virtuel Python

```powershell
# Créez l'environnement avec Python
python -m venv venv

# Activez l'environnement
.\venv\Scripts\Activate.ps1
```

### 5. Installez les dépendances

```powershell
pip install -r ../requirements.txt
```

## Utilisation

### 1. Démarrez Ollama (si ce n'est pas déjà fait)

```powershell
ollama serve
```

Laissez cette fenêtre ouverte en arrière-plan.

### 2. Exécutez le script principal

Dans une nouvelle fenêtre PowerShell :

```powershell
# Activez l'environnement virtuel
.\venv\Scripts\Activate.ps1

# Exécutez le générateur
python main.py
```

### 3. Entrez le CVE à exploiter

Lorsque le script vous demande le CVE, entrez-le (ex: `CVE-2014-0160` pour Heartbleed).

Si vous appuyez sur Entrée sans saisir de CVE, le script utilisera CVE-2014-0160 par défaut.

### 4. Entrez l'adresse IP cible

Le script vous demandera l'adresse IP de la machine à tester (ex: `192.168.1.10`).

### 5. Scan automatique des ports (si Nmap est installé)

Si la CVE est reconnue dans la base de données, le script propose de scanner automatiquement les ports vulnérables :

- **Oui (o)** : Lance un scan Nmap sur les ports typiques de cette CVE
  - Si un **script NSE** est disponible, il sera utilisé pour détecter la vulnérabilité
  - Les ports **réellement vulnérables** sont **priorisés automatiquement** 
  - Les ports non vulnérables sont marqués 
- **Non (N)** : Vous pourrez entrer manuellement le port

Si des ports ouverts sont détectés, le script vous propose de choisir lequel exploiter.

### Exemple d'utilisation complète

```
============================================================
 Générateur de Scripts d'Exploitation CVE
  Usage éducatif et éthique uniquement
============================================================

CVE à exploiter (ex: CVE-2014-0160): CVE-2014-0160

Adresse IP de la cible (ex: 192.168.1.10): 192.168.1.50

 Mode: Détection Heartbleed directe avec Nmap

Options de scan:
  1. Détection automatique des ports SSL/TLS (recommandé)
  2. Spécifier manuellement les ports

Votre choix (1/2, Entrée=1): 1

 Détection des ports SSL/TLS sur 192.168.1.50...
   Plage de ports: 1-10000
    Port SSL/TLS détecté: 443 (https)
    Port SSL/TLS détecté: 8443 (ssl/http)

 2 port(s) SSL/TLS détectés: 443, 8443

 Test Heartbleed sur 192.168.1.50...
   Ports testés: 443, 8443
   Script NSE: ssl-heartbleed
   Commande: nmap -p 443,8443 -sV -T4 --script ssl-heartbleed --open 192.168.1.50

 Ports ouverts détectés:
   • Port 443: https (open)  VULNÉRABLE
     └─ |   State: VULNERABLE

 Résultat détaillé du script ssl-heartbleed:
   | ssl-heartbleed:
   |   VULNERABLE:
   |   The Heartbleed Bug is a serious vulnerability...

 1 port(s) VULNÉRABLE(S) détecté(s) !
 Port vulnérable sélectionné automatiquement: 443

 Cible: 192.168.1.50:443

 Génération du script d'exploitation pour CVE-2014-0160...

============================================================
 Script généré
============================================================

 Script sauvegardé: scripts/exploit_CVE_2014_0160_20251117_143022.py
```

### Exemple sans scan Nmap

```
CVE à exploiter (ex: CVE-2014-0160): CVE-2021-44228
Adresse IP de la cible (ex: 192.168.1.10): 10.0.0.5

 CVE détectée: Log4j
   Ports typiques: 8080, 443, 9200

 Voulez-vous scanner ces ports avec Nmap? (o/N): N
Port de la cible (ex: 8080): 8080

 Cible: 10.0.0.5:8080

 Génération du script d'exploitation pour CVE-2021-44228...
```

### CVE non reconnue

Si vous entrez une CVE qui n'est pas dans la base de données :

```
CVE à exploiter (ex: CVE-2014-0160): CVE-2024-1234
Adresse IP de la cible (ex: 192.168.1.10): 192.168.1.100

  CVE CVE-2024-1234 non reconnue dans la base de données
Port de la cible (ex: 80): 443

 Cible: 192.168.1.100:443
```

## Avantages d'Ollama vs Hugging Face

 **Performances** : Beaucoup plus rapide (optimisé pour votre machine)  
 **Pas de téléchargement** : Pas besoin de télécharger 15 GB à chaque fois  
 **Moins de RAM** : Ollama gère la mémoire de façon optimale  
 **Simple** : API REST facile à utiliser  
 **Local** : Tout reste sur votre machine  

## Structure du projet

```
52/
├── main.py                # Script principal
├── llm_generator.py       # Appels API au LLM (ollama)
├── nmap_scanner.py        # Scanner des ports vulnérabless (nmap)
├── cve_database.py        # BDD des ports vulnérables classiques et des scripts NSE
├── README.md              # Documentation
├── requirements.txt       # Dépendances Python (requests uniquement)
└── scripts/               # Dossier contenant les scripts générés
```

## Workflow

```
┌─────────────┐
│   main.py   │
└──────┬──────┘
       │
       ├─────────────────────────────────────┐
       │                                     │
       ▼                                     ▼
┌──────────────────┐              ┌─────────────────┐
│ cve_database.py  │              │  User Input     │
│                  │              │  (CVE, IP)      │
│ get_cve_info()   │              └─────────────────┘
│ is_heartbleed()  │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ nmap_scanner.py  │
│                  │
│ scan_*()         │◄──── Nmap CLI
│ parse_*()        │
└──────┬───────────┘
       │
       │ (résultats scan)
       │
       ▼
┌──────────────────┐
│ main.py          │
│                  │
│ select_port()    │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ llm_generator.py │
│                  │
│ generate_*()     │◄──── Ollama API
│ save_script()    │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  scripts/        │
│  exploit_*.py    │
└──────────────────┘
```

## Dépannage

### Erreur "Impossible de se connecter à Ollama"
- Vérifiez qu'Ollama est en cours d'exécution : `ollama serve`
- Vérifiez que le port 11434 n'est pas bloqué

### Erreur "Model not found"
- Installez le modèle Mistral : `ollama pull mistral`
- Vérifiez les modèles installés : `ollama list`

### Nmap non trouvé
- Installez Nmap : https://nmap.org/download.html
- Ajoutez Nmap au PATH système
- Vérifiez avec : `nmap --version`

### Scan Nmap ne détecte aucun port
- Vérifiez que l'IP cible est accessible : `ping <IP>`
- Vérifiez les permissions (admin requis pour certains scans)
- Les ports peuvent être filtrés par un firewall
- Utilisez l'option manuelle pour entrer le port directement

### Timeout
- Augmentez le timeout dans `attack.py` (ligne avec `timeout=120`)
- Vérifiez que votre machine a suffisamment de ressources

## Ressources complémentaires

- [Ollama Documentation](https://ollama.ai/)
- [Ollama API Reference](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [Mistral AI](https://mistral.ai/)
- [Base de données CVE](https://cve.mitre.org/)

