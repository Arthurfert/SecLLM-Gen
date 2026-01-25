"""
Module de génération de scripts d'exploitation avec LLM (Ollama)
"""
import requests
import os
from datetime import datetime

OLLAMA_API_URL = "http://localhost:11434/api/generate"


def generate_exploit_script(cve: str, target_ip: str = None, target_port: int = None, model_name: str = "codestral") -> str:
    """
    Génère un script d'exploitation pour une CVE donnée en utilisant Ollama.
    Utilise une approche en 3 étapes :
    1. Meta-Prompting : Génération d'un prompt technique
    2. Génération : Création du script via le prompt
    3. Auto-correction : Vérification et correction du code généré
    
    Args:
        cve: L'identifiant CVE (ex: CVE-2014-0160)
        target_ip: IP cible (optionnel)
        target_port: Port cible (optionnel)
        model_name: Nom du modèle LLM à utiliser (optionnel, défaut "codestral")
    
    Returns:
        str: Le script Python généré
    """
    # Etape 1: Génération du prompt optimisé (Meta-Prompting)
    print(f" Etape 1/3: Analyse de la CVE et génération du prompt optimisé...")
    
    meta_prompt = f"""You are a prompt engineering expert.
GOAL: Write a highly technical prompt to instruct an AI to write a Python exploit for {cve}.
IMPORTANT: DO NOT WRITE THE PYTHON CODE YOURSELF. WRITE THE PROMPT TEXT.

Context:
- Vulnerability: {cve}
- Target: {target_ip if target_ip else 'TARGET_IP'}:{target_port if target_port else 'TARGET_PORT'}
- Library: scapy

The prompt you write must enforce these rules:
1. Output raw Python code only (no markdown).
2. Use 'scapy' for packet crafting.
3. Define variables for IP and PORT.
4. Respect TCP/IP protocol standards.
5. Include comments explaining the exploit.

Reply ONLY with the prompt text."""

    payload_meta = {
        "model": model_name,
        "prompt": meta_prompt,
        "stream": False,
        "options": {
            "temperature": 0.7,
            "max_tokens": 500
        }
    }

    optimized_prompt = ""
    try:
        response_meta = requests.post(OLLAMA_API_URL, json=payload_meta, timeout=500)
        response_meta.raise_for_status()
        optimized_prompt = response_meta.json().get("response", "").strip()
        
        # Vérification basique si le LLM a échoué et donné du code
        if "def " in optimized_prompt or "import " in optimized_prompt:
            print(" Le LLM a généré du code au lieu d'un prompt. Adaptation...")
            optimized_prompt = f"Refactor and fix this code to be a working exploit for {cve}:\n\n{optimized_prompt}"
        else:
            print(f" Prompt généré :\n{optimized_prompt}\n")
        
    except Exception as e:
        print(f" Erreur Meta-Prompting: {e}")
        print("Utilisation du prompt par défaut.")
        target_info = ""
        if target_ip and target_port:
            target_info = f"\nTarget information:\n    - IP: {target_ip}\n    - Port: {target_port}\n"
            
        optimized_prompt = f"""Generate a python script to exploit the {cve} vulnerability.
{target_info}
Use 'scapy'. Output raw Python code only. No markdown."""

    # Etape 2: Génération du script
    print(f" Etape 2/3: Génération du script d'exploitation...")
    
    payload_exploit = {
        "model": model_name,
        "prompt": optimized_prompt,
        "stream": False,
        "options": {
            "temperature": 0.7,
            "top_p": 0.9,
            "max_tokens": 2000
        }
    }
    
    generated_script = ""
    try:
        response = requests.post(OLLAMA_API_URL, json=payload_exploit, timeout=560)
        response.raise_for_status()
        generated_script = response.json().get("response", "")
    except Exception as e:
        print(f" Erreur Génération: {e}")
        return None

    if not generated_script:
        return None

    # Etape 3: Auto-correction
    print(f" Etape 3/3: Vérification et correction du script...")
    
    correction_prompt = f"""You are a senior security researcher and python expert.
Review the following Python exploit script for {cve}.
Fix any syntax errors, missing imports, or logical flaws.
Ensure 'scapy' is used correctly.
Ensure TARGET_IP and TARGET_PORT are defined.

SCRIPT TO REVIEW:
{generated_script}

Output ONLY the corrected raw Python code. No markdown, no explanations."""

    payload_correction = {
        "model": model_name,
        "prompt": correction_prompt,
        "stream": False,
        "options": {
            "temperature": 0.2, # Plus bas pour la correction
            "max_tokens": 2000
        }
    }

    try:
        response_corr = requests.post(OLLAMA_API_URL, json=payload_correction, timeout=560)
        response_corr.raise_for_status()
        final_script = response_corr.json().get("response", "")
        return final_script
    except Exception as e:
        print(f" Erreur Correction: {e}")
        return generated_script # Retourner le script non corrigé en cas d'erreur


def save_script(cve: str, content: str, target_ip: str = None, target_port: int = None) -> str:
    """
    Sauvegarde le script généré dans le dossier scripts/.
    
    Args:
        cve: L'identifiant CVE
        content: Le contenu du script
        target_ip: IP cible (optionnel)
        target_port: Port cible (optionnel)
    
    Returns:
        str: Le chemin du fichier sauvegardé
    """
    # Créer le dossier scripts s'il n'existe pas
    os.makedirs("./Attaque_LLM/scripts", exist_ok=True)
    
    # Nettoyer le script - Supprimer tout ce qui est hors des blocs de code markdown
    content = content.strip()
    
    # Chercher le premier ``` et le dernier ```
    first_backticks = content.find("```")
    last_backticks = content.rfind("```")
    
    if first_backticks != -1 and last_backticks != -1 and first_backticks != last_backticks:
        # Extraire le contenu entre les deux ```
        code_block = content[first_backticks:last_backticks + 3]
        lines = code_block.splitlines()
        
        # Supprimer la première ligne (```python ou ```) et la dernière (```)
        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        
        content = "\n".join(lines)
    
    # Nettoyage final
    content = content.strip()
    
    # Générer un nom de fichier avec timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"./Attaque_LLM/scripts/exploit_{cve.replace('-', '_')}_{timestamp}.py"
    
    # Créer le header
    header = f"""# Script d'exploitation pour {cve}
# Généré le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
#  AVERTISSEMENT: Usage éducatif uniquement
"""
    
    if target_ip and target_port:
        header += f"# Cible: {target_ip}:{target_port}\n"
    
    header += "\n"
    
    # Sauvegarder
    with open(filename, "w", encoding="utf-8") as f:
        f.write(header)
        f.write(content)
    
    return filename


def get_available_models() -> list:
    """
    Récupère la liste des modèles Ollama disponibles localement.
    
    Returns:
        list: Liste des noms de modèles disponibles
    """
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        response.raise_for_status()
        
        data = response.json()
        models = [model['name'] for model in data.get('models', [])]
        return models
    except requests.exceptions.ConnectionError:
        print("  Impossible de se connecter à Ollama")
        return []
    except Exception as e:
        print(f"  Erreur lors de la récupération des modèles: {e}")
        return []


def check_ollama_connection() -> bool:
    """
    Vérifie si Ollama est accessible.
    
    Returns:
        bool: True si Ollama répond, False sinon
    """
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        return response.status_code == 200
    except:
        return False
