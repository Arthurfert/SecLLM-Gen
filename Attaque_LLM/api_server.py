#!/usr/bin/env python3
"""
API REST pour exposer le générateur d'exploits
Version 2.0 avec support des instructions LLM et du raffinement
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import uvicorn
import requests

from llm_generator import generate_exploit_script, check_ollama_connection
from llm_generator_rag import generate_exploit_script as generate_exploit_script_rag
from cve_database import get_cve_info

app = FastAPI(title="CVE Exploit Generator API", version="2.0")

OLLAMA_API_URL = "http://localhost:11434/api/generate"

# ==================== Modèles Pydantic ====================

class ExploitRequest(BaseModel):
    cve_id: str
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    llm_instructions: Optional[str] = None  # NOUVEAU
    model_name: Optional[str] = "qwen3:8b"
    use_rag: Optional[bool] = False  # Option pour utiliser le RAG

class ExploitResponse(BaseModel):
    cve_id: str
    attack_script: str
    success: bool
    error: Optional[str] = None

class IDSRulesRequest(BaseModel):
    cve_id: str
    attack_script: str
    model_name: Optional[str] = "codestral"

class IDSRulesResponse(BaseModel):
    cve_id: str
    ids_rules: str
    success: bool
    error: Optional[str] = None

class RefineRequest(BaseModel):
    cve_id: str
    current_attack_script: str
    current_ids_rules: str
    feedback: str
    nmap_output: Optional[str] = None
    target_description: Optional[str] = None
    model_name: Optional[str] = "codestral"

class RefineResponse(BaseModel):
    cve_id: str
    attack_script: str
    ids_rules: str
    success: bool
    error: Optional[str] = None

# ==================== Endpoints ====================

@app.get("/health")
def health_check():
    """Vérifie que l'API et Ollama sont accessibles"""
    ollama_status = check_ollama_connection()
    return {
        "status": "healthy" if ollama_status else "degraded",
        "ollama_available": ollama_status,
        "version": "2.0"
    }

@app.post("/generate/exploit", response_model=ExploitResponse)
def generate_exploit(request: ExploitRequest):
    """
    Génère un script d'exploitation pour une CVE donnée
    Supporte maintenant les instructions LLM personnalisées et le RAG
    """
    try:
        # Vérifier la connexion Ollama
        if not check_ollama_connection():
            raise HTTPException(
                status_code=503, 
                detail="Ollama n'est pas accessible. Assurez-vous qu'il est lancé."
            )
        
        # Si RAG activé, utiliser le générateur avec RAG
        if request.use_rag:
            print(f"🔍 Mode RAG activé pour {request.cve_id}")
            script_content = generate_exploit_script_rag(
                cve=request.cve_id,
                target_ip=request.target_ip,
                target_port=request.target_port,
                model_name=request.model_name
            )
            
            if not script_content:
                raise HTTPException(
                    status_code=500,
                    detail="Échec de la génération du script d'exploitation avec RAG"
                )
            
            # Nettoyer les balises markdown si présentes
            script_content = _clean_markdown(script_content)
            
            return ExploitResponse(
                cve_id=request.cve_id,
                attack_script=script_content,
                success=True
            )
        
        # Mode standard sans RAG
        # Récupérer les infos de la CVE si disponible
        cve_info = get_cve_info(request.cve_id)
        
        # Utiliser le port par défaut si non fourni
        target_port = request.target_port
        if not target_port and cve_info:
            target_port = cve_info["ports"][0]
        
        # Construire le prompt avec les instructions personnalisées
        target_info = ""
        if request.target_ip and target_port:
            target_info = f"""
Target information:
    - IP: {request.target_ip}
    - Port: {target_port}
"""
        
        # Ajouter les instructions personnalisées si présentes
        custom_instructions = ""
        if request.llm_instructions:
            custom_instructions = f"""

IMPORTANT - Additional instructions from the user:
{request.llm_instructions}

You MUST follow these additional instructions while generating the exploit.
"""
        
        prompt = f"""
{custom_instructions}

You are a senior security researcher and python expert.
GOAL: Write a Python exploit for {request.cve_id}.

Context:
- Vulnerability: {request.cve_id}
- Target: {target_info}
- Library: scapy

The prompt you write must enforce these rules:
1. Output raw Python code only (no markdown).
2. Use 'scapy' for packet crafting.
3. Define variables for IP and PORT.
4. Respect TCP/IP protocol standards.
5. Include comments explaining the exploit.
6. Handle the response appropriately.

Reply ONLY with the python code.
"""
        
        # Générer le script avec Ollama
        payload = {
            "model": request.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
                "max_tokens": 2000
            }
        }
        
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=500)
        response.raise_for_status()
        
        result = response.json()
        script_content = result.get("response", "")
        
        if not script_content:
            raise HTTPException(
                status_code=500,
                detail="Échec de la génération du script d'exploitation"
            )
        
        # Nettoyer les balises markdown si présentes
        script_content = _clean_markdown(script_content)
        
        return ExploitResponse(
            cve_id=request.cve_id,
            attack_script=script_content,
            success=True
        )
    
    except HTTPException:
        raise
    except Exception as e:
        return ExploitResponse(
            cve_id=request.cve_id,
            attack_script="",
            success=False,
            error=str(e)
        )

@app.post("/generate/ids-rules", response_model=IDSRulesResponse)
def generate_ids_rules(request: IDSRulesRequest):
    """
    Génère des règles IDS pour détecter une attaque
    """
    try:
        # Vérifier la connexion Ollama
        if not check_ollama_connection():
            raise HTTPException(
                status_code=503,
                detail="Ollama n'est pas accessible"
            )
        
        # Créer un prompt pour générer les règles IDS
        prompt = f"""Generate Snort IDS detection rules for the following attack:

CVE ID: {request.cve_id}
Attack Script (excerpt):
{request.attack_script[:500]}

Please provide IDS rules in Snort format that can detect this type of attack.
Include rules for:
- Network traffic patterns
- Malicious payloads
- Exploit signatures

Rules you must ABSOLUTELY follow:
- Provide ONLY the IDS rules in valid Snort format
- DO NOT include explanations or additional text
- Use comments (#) to explain each rule
- Rules must be functional and ready to deploy
"""
        
        payload = {
            "model": request.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
                "max_tokens": 1500
            }
        }
        
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=500)
        response.raise_for_status()
        
        result = response.json()
        ids_rules = result.get("response", "")
        
        if not ids_rules:
            raise HTTPException(
                status_code=500,
                detail="Échec de la génération des règles IDS"
            )
        
        # Nettoyer les balises markdown
        ids_rules = _clean_markdown(ids_rules)
        
        return IDSRulesResponse(
            cve_id=request.cve_id,
            ids_rules=ids_rules,
            success=True
        )
    
    except HTTPException:
        raise
    except Exception as e:
        return IDSRulesResponse(
            cve_id=request.cve_id,
            ids_rules="",
            success=False,
            error=str(e)
        )

@app.post("/generate/refine", response_model=RefineResponse)
def refine_scripts(request: RefineRequest):
    """
    NOUVEAU: Raffine les scripts d'attaque et règles IDS selon le feedback humain
    """
    try:
        # Vérifier la connexion Ollama
        if not check_ollama_connection():
            raise HTTPException(
                status_code=503,
                detail="Ollama n'est pas accessible"
            )
        
        # Construire le contexte
        context = ""
        if request.target_description:
            context += f"\nTarget Description: {request.target_description}"
        if request.nmap_output:
            context += f"\nNmap Output: {request.nmap_output[:300]}"
        
        # Prompt pour raffiner le script d'attaque
        attack_prompt = f"""You are a penetration testing expert. Refine the following exploit script based on user feedback.

CVE ID: {request.cve_id}
{context}

CURRENT ATTACK SCRIPT:
```python
{request.current_attack_script}
```

USER FEEDBACK:
{request.feedback}

Please provide an IMPROVED version of the attack script that addresses the user's feedback.

Rules you must ABSOLUTELY follow:
- Provide ONLY the improved Python code
- DO NOT include explanations or additional text outside the code
- Use comments in the code to explain changes
- The code must be functional and ready to run
- Address all points mentioned in the user feedback
"""
        
        # Générer le script d'attaque raffiné
        payload_attack = {
            "model": request.model_name,
            "prompt": attack_prompt,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
                "max_tokens": 2000
            }
        }
        
        response_attack = requests.post(OLLAMA_API_URL, json=payload_attack, timeout=500)
        response_attack.raise_for_status()
        refined_attack = response_attack.json().get("response", "")
        
        if not refined_attack:
            raise HTTPException(status_code=500, detail="Échec du raffinement du script d'attaque")
        
        refined_attack = _clean_markdown(refined_attack)
        
        # Prompt pour raffiner les règles IDS
        ids_prompt = f"""You are an IDS/IPS expert. Refine the following IDS detection rules based on user feedback.

CVE ID: {request.cve_id}

REFINED ATTACK SCRIPT (excerpt):
{refined_attack[:500]}

CURRENT IDS RULES:
{request.current_ids_rules}

USER FEEDBACK:
{request.feedback}

Please provide IMPROVED IDS rules that address the user's feedback and can detect the refined attack script.

Rules you must ABSOLUTELY follow:
- Provide ONLY the improved IDS rules in Snort/Suricata format
- DO NOT include explanations or additional text
- Use comments (#) to explain changes
- Rules must be functional and ready to deploy
- Address all points mentioned in the user feedback
"""
        
        payload_ids = {
            "model": request.model_name,
            "prompt": ids_prompt,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
                "max_tokens": 1500
            }
        }
        
        response_ids = requests.post(OLLAMA_API_URL, json=payload_ids, timeout=500)
        response_ids.raise_for_status()
        refined_ids = response_ids.json().get("response", "")
        
        if not refined_ids:
            raise HTTPException(status_code=500, detail="Échec du raffinement des règles IDS")
        
        refined_ids = _clean_markdown(refined_ids)
        
        return RefineResponse(
            cve_id=request.cve_id,
            attack_script=refined_attack,
            ids_rules=refined_ids,
            success=True
        )
    
    except HTTPException:
        raise
    except Exception as e:
        return RefineResponse(
            cve_id=request.cve_id,
            attack_script="",
            ids_rules="",
            success=False,
            error=str(e)
        )

@app.get("/cve/supported")
def list_supported_cves():
    """Liste les CVE supportées dans la base de données"""
    from cve_database import list_supported_cves
    return {
        "supported_cves": list_supported_cves()
    }

# ==================== Fonctions utilitaires ====================

def _clean_markdown(content: str) -> str:
    """Nettoie les balises markdown du contenu généré"""
    content = content.strip()
    lines = content.splitlines()
    if len(lines) >= 3 and lines[0].strip().startswith("```") and lines[-1].strip() == "```":
        content = "\n".join(lines[1:-1])
    return content

# ==================== Démarrage ====================

if __name__ == "__main__":
    print("🚀 Démarrage de l'API CVE Exploit Generator v2.0")
    print("📍 URL: http://0.0.0.0:8001")
    print("📚 Documentation: http://0.0.0.0:8001/docs")
    print()
    print("🆕 Nouvelles fonctionnalités:")
    print("   - Support des instructions LLM personnalisées")
    print("   - Endpoint /generate/refine pour le raffinement itératif")
    print()
    
    # Vérifier Ollama au démarrage
    if check_ollama_connection():
        print("✅ Ollama est accessible")
    else:
        print("⚠️  ATTENTION: Ollama n'est pas accessible !")
        print("   Lancez 'ollama serve' avant d'utiliser l'API")
    
    uvicorn.run(app, host="0.0.0.0", port=8001)