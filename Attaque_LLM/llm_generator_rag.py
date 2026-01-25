import requests
import os
from datetime import datetime
# ### MODIF RAG : Import du moteur
from rag_engine import get_cve_context, initialize_knowledge_base

OLLAMA_API_URL = "http://localhost:11434/api/generate"

# ### MODIF RAG : Initialisation automatique de la base de connaissances au chargement du module
# Cela garantit que le RAG est prêt avant toute utilisation
_rag_initialized = False

def _ensure_rag_initialized():
    """Initialise le RAG une seule fois au premier appel."""
    global _rag_initialized
    if not _rag_initialized:
        print(" Vérification/Initialisation de la base RAG...")
        initialize_knowledge_base()
        _rag_initialized = True

def generate_exploit_script(cve: str, target_ip: str = None, target_port: int = None, model_name: str = "codestral") -> str:
    """
    Génère un script d'exploitation pour une CVE donnée en utilisant Ollama.
    Utilise une approche en 3 étapes enrichie par le RAG :
    1. Meta-Prompting : Génération d'un prompt technique (enrichi par le contexte RAG)
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
    # ### MODIF RAG : S'assurer que le RAG est initialisé
    _ensure_rag_initialized()
    
    # ### MODIF RAG : Récupération du contexte
    print(f" Etape 0/3: Recherche d'infos RAG pour {cve}...")
    cve_context = get_cve_context(cve)
    
    # Préparer le bloc de contexte RAG
    rag_context_block = ""
    if cve_context:
        print(" Contexte RAG trouvé et sera injecté dans le meta-prompt.")
        clean_context = cve_context.replace('\n', ' ').replace('\r', '').strip()
        rag_context_block = f"""
VULNERABILITY TECHNICAL DETAILS (from NVD Database):
{clean_context}

Use these technical details to create a more accurate and specific prompt."""
    else:
        print(" Pas de contexte RAG trouvé (le LLM devra se baser sur ses connaissances).")

    # Construire les infos de cible
    target_info = f"{target_ip if target_ip else 'TARGET_IP'}:{target_port if target_port else 'TARGET_PORT'}"

    # ===========================================
    # Etape 1: Meta-Prompting (enrichi par RAG)
    # ===========================================
    print(f" Etape 1/3: Analyse de la CVE et génération du prompt optimisé...")
    
    meta_prompt = f"""You are a prompt engineering expert specialized in cybersecurity.

GOAL: Write a highly technical and detailed prompt to instruct an AI to write a Python exploit for {cve}.

IMPORTANT: 
- DO NOT WRITE THE PYTHON CODE YOURSELF
- WRITE ONLY THE PROMPT TEXT that will be used to generate the exploit
{rag_context_block}

Context for your prompt:
- Vulnerability: {cve}
- Target: {target_info}
- Library to use: scapy (for packet crafting)

Your prompt must enforce these rules:
1. Output raw Python code only (no markdown, no explanations)
2. Use 'scapy' library for all packet crafting operations
3. Define TARGET_IP and TARGET_PORT variables at the top of the script
4. Respect TCP/IP protocol standards (TCP handshake, etc.)
5. Include detailed comments explaining each step of the exploit
6. Handle errors and network timeouts appropriately
7. The script must be complete, functional, and ready to run

Reply ONLY with the prompt text. Do not include any other explanation."""

    payload_meta = {
        "model": model_name,
        "prompt": meta_prompt,
        "stream": False,
        "options": {
            "temperature": 0.7,
            "max_tokens": 800
        }
    }

    optimized_prompt = ""
    try:
        response_meta = requests.post(OLLAMA_API_URL, json=payload_meta, timeout=500)
        response_meta.raise_for_status()
        optimized_prompt = response_meta.json().get("response", "").strip()
        
        # Vérification si le LLM a généré du code au lieu d'un prompt
        if optimized_prompt.startswith("```") or "def " in optimized_prompt[:100] or "import " in optimized_prompt[:50]:
            print(" Le LLM a généré du code au lieu d'un prompt. Adaptation...")
            optimized_prompt = f"""Refactor and improve this code to be a complete working exploit for {cve}.
Ensure it uses scapy, defines TARGET_IP and TARGET_PORT, and includes proper error handling.

Code to improve:
{optimized_prompt}

Output ONLY the corrected Python code."""
        else:
            print(f" Prompt optimisé généré ({len(optimized_prompt)} caractères)")
        
    except Exception as e:
        print(f" Erreur Meta-Prompting: {e}")
        print("   Utilisation d'un prompt par défaut enrichi par le RAG...")
        
        # Prompt de fallback enrichi par le RAG
        optimized_prompt = f"""You are a senior security researcher and Python expert.

TASK: Write a complete Python exploit script for {cve}.
{rag_context_block}

Target: {target_info}

REQUIREMENTS:
1. Output raw Python code only (no markdown)
2. Use the scapy library for packet crafting
3. Define TARGET_IP and TARGET_PORT variables at the top
4. Respect TCP/IP protocol standards (TCP handshake, etc.)
5. Include comments explaining each step
6. Handle errors and responses appropriately
7. The script must be complete and functional

OUTPUT: Provide ONLY the Python code."""

    # ===========================================
    # Etape 2: Génération du script
    # ===========================================
    print(f" Etape 2/3: Génération du script d'exploitation...")
    
    payload_exploit = {
        "model": model_name,
        "prompt": optimized_prompt,
        "stream": False,
        "options": {
            "temperature": 0.6,
            "top_p": 0.9,
            "max_tokens": 2500
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
        print(" Le LLM n'a pas généré de script.")
        return None

    # ===========================================
    # Etape 3: Auto-correction
    # ===========================================
    print(f" Etape 3/3: Vérification et correction du script...")
    
    correction_prompt = f"""You are a senior security researcher and Python expert.

Review the following Python exploit script for {cve}.
Fix any syntax errors, missing imports, or logical flaws.

CHECKS TO PERFORM:
- Ensure 'scapy' is imported and used correctly
- Ensure TARGET_IP and TARGET_PORT are defined at the top
- Ensure proper TCP/IP protocol handling
- Fix any Python syntax errors
- Add missing error handling if needed

SCRIPT TO REVIEW:
{generated_script}

Output ONLY the corrected raw Python code. No markdown, no explanations."""

    payload_correction = {
        "model": model_name,
        "prompt": correction_prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "max_tokens": 2500
        }
    }

    try:
        response_corr = requests.post(OLLAMA_API_URL, json=payload_correction, timeout=560)
        response_corr.raise_for_status()
        final_script = response_corr.json().get("response", "")
        return final_script
    except Exception as e:
        print(f" Erreur Correction: {e}")
        return generated_script  # Retourner le script non corrigé en cas d'erreur

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
