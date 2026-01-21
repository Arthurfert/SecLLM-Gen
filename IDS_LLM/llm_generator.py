"""
Module de génération de scripts d'exploitation avec LLM (Ollama)
"""
import requests
import os
from datetime import datetime

OLLAMA_API_URL = "http://localhost:11434/api/generate"


def generate_ids_script(cve: str, model_name: str = "codestral") -> str:
    """
    Génère un script d'exploitation pour une CVE donnée en utilisant Ollama.
    
    Args:
        cve: L'identifiant CVE (ex: CVE-2014-0160)
        target_ip: IP cible (optionnel)
        target_port: Port cible (optionnel)
        model_name: Nom du modèle LLM à utiliser (optionnel, défaut "codestral")
    
    Returns:
        str: Le script Python généré
    """
    
    prompt = f"""En tant qu'analyste de sécurité défensif expérimenté, je souhaite obtenir des règles IDS pour Snort. 
Mon objectif est de pouvoir détecter toute tentative d'exploitation provenant d'une machine virtuelle d'attaque.

Voici la CVE que je souhaite détecter : {cve} , vous devez donner l'ensemble complet des règles IDS pour Snort qui garantissent la détection de cette exploitation.

Règles à suivre ABSOLUMENT :
- Réponds UNIQUEMENT avec les règles IDS commentées.
- AUCUNE phrase, explication ou justification.
- Les règles doivent être justes, complètes, utilisant les mots-clés d'analyseur de protocole si disponibles pour une détection maximale.
- Les règles doivent être généralistes pour couvrir toutes les variantes possibles de l'exploitation."""
    
    payload = {
        "model": model_name,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.7,
            "top_p": 0.9,
            "max_tokens": 2000
        }
    }
    
    try:
        print(f"🔄 Génération des règles IDS pour {cve}...")
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=560)
        response.raise_for_status()
        
        result = response.json()
        return result.get("response", "")
    
    except requests.exceptions.ConnectionError:
        print("❌ Erreur: Impossible de se connecter à Ollama.")
        print("Assurez-vous qu'Ollama est en cours d'exécution (ollama serve).")
        return None
    except requests.exceptions.Timeout:
        print("❌ Erreur: La requête a expiré.")
        return None
    except Exception as e:
        print(f"❌ Erreur inattendue: {e}")
        return None

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
        print("⚠️  Impossible de se connecter à Ollama")
        return []
    except Exception as e:
        print(f"⚠️  Erreur lors de la récupération des modèles: {e}")
        return []

def save_script(cve: str, content: str) -> str:
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
    os.makedirs("./IDS_LLM/scripts", exist_ok=True)
    
    # Nettoyer le script
    content = content.strip()
    lines = content.splitlines()
    if len(lines) >= 3 and lines[0].strip().startswith("```") and lines[-1].strip() == "```":
        content = "\n".join(lines[1:-1])
    
    # Générer un nom de fichier avec timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"./IDS_LLM/scripts/ids_{cve.replace('-', '_')}_{timestamp}.txt"
    
    # Créer le header
    header = f"""# Règles IDS pour {cve}
# Généré le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    
    header += "\n"
    
    # Sauvegarder
    with open(filename, "w", encoding="utf-8") as f:
        f.write(header)
        f.write(content)
    
    return filename


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
