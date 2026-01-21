from typing import Optional, Dict, Any
from app.services.code_evaluator import CodeEvaluator
import requests
import logging
import os

class LLMService:
    def __init__(self):
        # URL de l'API du camarade (configurable via variable d'environnement)
        self.llm_api_url = os.getenv("LLM_API_URL", "http://localhost:8001")
        self.timeout = 500  # Les LLM peuvent être lents
        self.model_name = os.getenv("LLM_MODEL", "codestral")
        # Évaluateur de code (utilise Ollama directement)
        ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.evaluator = CodeEvaluator(ollama_url, self.model_name)
    
    def generate_attack_script(
        self, 
        cve_id: str, 
        nmap_output: str, 
        target_description: str,
        llm_instructions: Optional[str] = None,
        use_rag: bool = False  # Option pour utiliser le RAG
    ) -> str:
        """
        Génère un script d'attaque en appelant l'API du LLM
        """
        try:
            logging.info(f"Appel API LLM pour générer script d'attaque pour {cve_id} (instructions présentées: {'oui' if llm_instructions else 'non'}, RAG: {'oui' if use_rag else 'non'})")
            
            response = requests.post(
                f"{self.llm_api_url}/generate/exploit",
                json={
                    "cve_id": cve_id,
                    "nmap_output": nmap_output,
                    "target_description": target_description,
                    "llm_instructions": llm_instructions,
                    "model_name": self.model_name,
                    "use_rag": use_rag
                },
                timeout=self.timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            if data.get("success") and data.get("attack_script"):
                logging.info(f"Script d'attaque généré avec succès pour {cve_id}")
                return data["attack_script"]
            else:
                error_msg = data.get("error", "Erreur inconnue")
                logging.error(f"Échec génération script: {error_msg}")
                return self._get_fallback_attack_script(cve_id, llm_instructions)
            
        except requests.exceptions.ConnectionError:
            logging.error(f"Impossible de se connecter à l'API LLM sur {self.llm_api_url}")
            return self._get_fallback_attack_script(cve_id, llm_instructions)
        except requests.exceptions.Timeout:
            logging.error("Timeout lors de l'appel API LLM")
            return self._get_fallback_attack_script(cve_id, llm_instructions)
        except Exception as e:
            logging.error(f"Erreur inattendue lors de l'appel LLM: {e}")
            return self._get_fallback_attack_script(cve_id, llm_instructions)

    def generate_ids_rules(self, cve_id: str, attack_script: str) -> str:
        """
        Génère des règles IDS en appelant l'API du LLM
        """
        try:
            logging.info(f"Appel API LLM pour générer règles IDS pour {cve_id}")
            
            response = requests.post(
                f"{self.llm_api_url}/generate/ids-rules",
                json={
                    "cve_id": cve_id,
                    "attack_script": attack_script,
                    "model_name": self.model_name
                },
                timeout=self.timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            if data.get("success") and data.get("ids_rules"):
                logging.info(f"Règles IDS générées avec succès pour {cve_id}")
                return data["ids_rules"]
            else:
                error_msg = data.get("error", "Erreur inconnue")
                logging.error(f"Échec génération IDS: {error_msg}")
                return self._get_fallback_ids_rules(cve_id)
            
        except requests.exceptions.ConnectionError:
            logging.error(f"Impossible de se connecter à l'API LLM sur {self.llm_api_url}")
            return self._get_fallback_ids_rules(cve_id)
        except requests.exceptions.Timeout:
            logging.error("Timeout lors de l'appel API LLM")
            return self._get_fallback_ids_rules(cve_id)
        except Exception as e:
            logging.error(f"Erreur inattendue lors de l'appel LLM: {e}")
            return self._get_fallback_ids_rules(cve_id)
    
    def _get_fallback_attack_script(self, cve_id: str, llm_instructions: Optional[str] = None) -> str:
        """Fallback mock si le LLM n'est pas accessible"""
        instructions_text = f"\n# Instructions LLM fournies:\n# {llm_instructions}\n" if llm_instructions else ""
        return f"""# FALLBACK: Attack script for {cve_id}
# (LLM API unavailable, using mock data){instructions_text}

echo "Simulated exploit for {cve_id}"
# Replace TARGET_IP and TARGET_PORT with actual values
"""
    
    def _get_fallback_ids_rules(self, cve_id: str) -> str:
        """Fallback mock si le LLM n'est pas accessible"""
        return f"""# FALLBACK: IDS rules for {cve_id}
# (LLM API unavailable, using mock data)
alert tcp any any -> any any (msg:"Simulated detection for {cve_id}"; sid:1000001; rev:1;)
"""
    
    # Méthode pour le raffinement
    def refine_scripts(
        self,
        cve_id: str,
        current_attack_script: str,
        current_ids_rules: str,
        feedback: str,
        nmap_output: str,
        target_description: str
    ) -> tuple[str, str]:
        """
        Appelle l'API LLM pour raffiner les scripts selon le feedback humain.
        Retourne (attack_script, ids_rules). En cas d'échec, retourne des fallbacks.
        """
        try:
            logging.info(f"Appel API LLM pour raffiner scripts pour {cve_id}")
            response = requests.post(
                f"{self.llm_api_url}/generate/refine",
                json={
                    "cve_id": cve_id,
                    "current_attack_script": current_attack_script,
                    "current_ids_rules": current_ids_rules,
                    "feedback": feedback,
                    "nmap_output": nmap_output,
                    "target_description": target_description,
                    "model_name": self.model_name
                },
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            if data.get("success") and data.get("attack_script") and data.get("ids_rules"):
                logging.info(f"Raffinement LLM réussi pour {cve_id}")
                return data["attack_script"], data["ids_rules"]
            else:
                error_msg = data.get("error", "Erreur inconnue")
                logging.error(f"Échec raffinement LLM: {error_msg}")
                return self._get_fallback_attack_script(cve_id), self._get_fallback_ids_rules(cve_id)

        except requests.exceptions.ConnectionError:
            logging.error(f"Impossible de se connecter à l'API LLM sur {self.llm_api_url}")
            return self._get_fallback_attack_script(cve_id), self._get_fallback_ids_rules(cve_id)
        except requests.exceptions.Timeout:
            logging.error("Timeout lors de l'appel API LLM pour raffinement")
            return self._get_fallback_attack_script(cve_id), self._get_fallback_ids_rules(cve_id)
        except Exception as e:
            logging.error(f"Erreur inattendue lors du raffinement LLM: {e}")
            return self._get_fallback_attack_script(cve_id), self._get_fallback_ids_rules(cve_id)

    def evaluate_code(
        self, 
        attack_script: str, 
        ids_rules: str, 
        cve_id: str
    ) -> Dict[str, Any]:
        """
        Évalue la qualité du code généré
        
        Returns:
            Dict avec scores et feedbacks
        """
        logging.info(f"Évaluation du code pour {cve_id}")
        
        # Évaluer le script d'attaque
        attack_score, attack_feedback = self.evaluator.evaluate_attack_script(
            attack_script, cve_id
        )
        
        # Évaluer les règles IDS
        ids_score, ids_feedback = self.evaluator.evaluate_ids_rules(
            ids_rules, cve_id
        )
        
        # Calculer le score global
        overall_score = (attack_score + ids_score) // 2
        
        return {
            "attack_script_score": attack_score,
            "ids_rules_score": ids_score,
            "overall_score": overall_score,
            "attack_feedback": attack_feedback,
            "ids_feedback": ids_feedback
        }

