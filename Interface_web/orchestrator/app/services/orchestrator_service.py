from sqlalchemy.orm import Session
from app import models
from app.services.llm_service import LLMService
from app.services.attacker_client import AttackerClient
from app.services.ids_client import IDSClient

class OrchestratorService:
    def __init__(self, llm_service: LLMService):
        self.llm = llm_service
        self.attacker = AttackerClient()
        self.ids = IDSClient()

    def create_scenario(self, session: Session, scenario_in: models.ScenarioIn) -> models.Scenario:
        scenario = models.Scenario(
            cve_id=scenario_in.cve_id,
            target_description=scenario_in.target_description,
            nmap_output=scenario_in.nmap_output,
            llm_instructions=scenario_in.llm_instructions,  #  AJOUTÉ
            use_rag=scenario_in.use_rag,  # Option RAG
        )
        session.add(scenario)
        session.commit()
        session.refresh(scenario)
        return scenario

    def list_scenarios(self, session: Session):
        return session.query(models.Scenario).all()

    def generate_for_scenario(self, session: Session, scenario_id: int):
        scenario = session.query(models.Scenario).filter(models.Scenario.id == scenario_id).first()
        if scenario is None:
            return None

        attack_script = self.llm.generate_attack_script(
            cve_id=scenario.cve_id,
            nmap_output=scenario.nmap_output,
            target_description=scenario.target_description,
            llm_instructions=scenario.llm_instructions,  #  AJOUTÉ
            use_rag=scenario.use_rag,  # Option RAG
        )
        ids_rules = self.llm.generate_ids_rules(
            cve_id=scenario.cve_id,
            attack_script=attack_script,
        )

        scenario.attack_script = attack_script
        scenario.ids_rules = ids_rules
        session.commit()
        session.refresh(scenario)

        from app.models import ScenarioOut, GenerationResult
        return GenerationResult(
            scenario=ScenarioOut.model_validate(scenario),
            attack_script=attack_script,
            ids_rules=ids_rules,
        )
    
    #  NOUVELLE méthode pour le raffinement
    def refine_scenario(
        self, 
        session: Session, 
        scenario_id: int, 
        refine_request: models.RefineRequest
    ):
        scenario = session.query(models.Scenario).filter(models.Scenario.id == scenario_id).first()
        if scenario is None:
            return None
        
        refined_script, refined_rules = self.llm.refine_scripts(
            cve_id=scenario.cve_id,
            current_attack_script=refine_request.current_attack_script,
            current_ids_rules=refine_request.current_ids_rules,
            feedback=refine_request.feedback,
            nmap_output=scenario.nmap_output,
            target_description=scenario.target_description
        )
        
        scenario.attack_script = refined_script
        scenario.ids_rules = refined_rules
        session.commit()
        session.refresh(scenario)
        
        from app.models import RefineResult
        return RefineResult(
            attack_script=refined_script,
            ids_rules=refined_rules
        )

    def execute_run(self, session: Session, scenario_id: int):
        scenario = session.query(models.Scenario).filter(models.Scenario.id == scenario_id).first()
        if scenario is None or not scenario.attack_script or not scenario.ids_rules:
            return None

        # 1) Déployer règles IDS (mock)
        self.ids.deploy_rules(scenario.ids_rules)

        # 2) Exécuter l'attaque (mock)
        exec_result = self.attacker.run_script(scenario.attack_script)

        # 3) Demander au "IDS" s'il a détecté
        ids_result = self.ids.analyze_traffic()

        run = models.Run(
            scenario_id=scenario.id,
            attack_success=exec_result.success,
            detected_by_ids=ids_result.detected,
            raw_logs=f"ATTACK LOGS:\n{exec_result.logs}\n\nIDS LOGS:\n{ids_result.logs}",
        )
        session.add(run)
        session.commit()
        session.refresh(run)
        return run

    def list_runs(self, session: Session):
        return session.query(models.Run).all()
    
    def evaluate_scenario_code(self, session: Session, scenario_id: int):
        """Évalue la qualité du code d'un scénario"""
        scenario = session.query(models.Scenario).filter(
            models.Scenario.id == scenario_id
        ).first()
        
        if scenario is None or not scenario.attack_script or not scenario.ids_rules:
            return None
        
        # Évaluer avec le LLM
        eval_data = self.llm.evaluate_code(
            attack_script=scenario.attack_script,
            ids_rules=scenario.ids_rules,
            cve_id=scenario.cve_id
        )
        
        # Sauvegarder l'évaluation
        evaluation = models.CodeEvaluation(
            scenario_id=scenario.id,
            **eval_data
        )
        session.add(evaluation)
        session.commit()
        session.refresh(evaluation)
        
        return evaluation