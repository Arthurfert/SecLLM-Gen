"""
Service d'évaluation de code par LLM
"""
import requests
import logging
from typing import Tuple

class CodeEvaluator:
    """Évalue la qualité des scripts d'attaque et règles IDS avec un LLM"""
    
    def __init__(self, ollama_url: str, model_name: str):
        self.ollama_url = ollama_url
        self.model_name = model_name
        self.timeout = 500
    
    def evaluate_attack_script(self, script: str, cve_id: str) -> Tuple[int, str]:
        """
        Évalue un script d'attaque
        
        Returns:
            (score sur 100, feedback détaillé)
        """
        prompt = f"""Évalue ce script d'attaque pour {cve_id} sur une échelle de 0-100.
Considère : syntaxe, sécurité, efficacité, documentation.
Réponds avec SCORE=X et FEEDBACK=...
Sois honnête dans ton évaluation.

Script:
{script[:500]}
"""
        try:
            logging.info(f"Évaluation script d'attaque pour {cve_id} avec Ollama")
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={"model": self.model_name, "prompt": prompt, "stream": False},
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            text = data.get("response", "")
            
            score = self._extract_score(text)
            feedback = self._extract_feedback(text)
            return score, feedback
        except Exception as e:
            logging.error(f"Erreur évaluation Ollama: {e}")
            return 50, "Évaluation indisponible"
    
    def evaluate_ids_rules(self, rules: str, cve_id: str) -> Tuple[int, str]:
        """
        Évalue des règles IDS
        
        Returns:
            (score sur 100, feedback détaillé)
        """
        prompt = f"""Évalue ces règles IDS pour {cve_id} sur une échelle de 0-100.
Considère : syntaxe Suricata/Snort, couverture détection, faux positifs.
Réponds avec SCORE=X et FEEDBACK=...
Sois honnête dans ton évaluation.

Règles:
{rules[:500]}
"""
        try:
            logging.info(f"Évaluation règles IDS pour {cve_id} avec Ollama")
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={"model": self.model_name, "prompt": prompt, "stream": False},
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            text = data.get("response", "")
            
            score = self._extract_score(text)
            feedback = self._extract_feedback(text)
            return score, feedback
        except Exception as e:
            logging.error(f"Erreur évaluation Ollama: {e}")
            return 50, "Évaluation indisponible"
    
    def _extract_score(self, text: str) -> int:
        """Extrait le score d'une réponse LLM"""
        try:
            if "SCORE=" in text:
                score_str = text.split("SCORE=")[1].split()[0]
                score = int(score_str)
                return max(0, min(100, score))
        except:
            pass
        return 50
    
    def _extract_feedback(self, text: str) -> str:
        """Extrait le feedback d'une réponse LLM"""
        try:
            if "FEEDBACK=" in text:
                return text.split("FEEDBACK=")[1].strip()
        except:
            pass
        return "Pas de feedback disponible"