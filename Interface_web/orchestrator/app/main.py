from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app import models
from app.services.llm_service import LLMService
from app.services.orchestrator_service import OrchestratorService
from app.db import db_init, db_session
from pydantic import BaseModel
import logging
from typing import List

# configure logging
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Pentest Orchestrator")

#CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # pour le dev, on ouvre tout
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

llm_service = LLMService()
orchestrator = OrchestratorService(llm_service=llm_service)

@app.on_event("startup")
def startup():
    db_init()

# global exception handler to log and return a generic 500
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logging.exception("Unhandled exception for %s %s", request.method, request.url)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

@app.post("/scenarios", response_model=models.ScenarioOut)  # Sans List[]
def create_scenario(scenario_in: models.ScenarioIn):
    logging.info("POST /scenarios called")
    session = db_session()
    try:
        scenario = orchestrator.create_scenario(session, scenario_in)
        return models.ScenarioOut.model_validate(scenario)  # Sans []
    finally:
        session.close()

@app.get("/scenarios", response_model=List[models.ScenarioOut])
def list_scenarios():
    logging.info("GET /scenarios called")
    session = db_session()
    try:
        scenarios = orchestrator.list_scenarios(session)
        return scenarios
    finally:
        session.close()

@app.post("/scenarios/{scenario_id}/generate", response_model=models.GenerationResult)
def generate_for_scenario(scenario_id: int):
    session = db_session()
    try:
        # vérification préalable que le scénario existe
        scenario = session.query(models.Scenario).filter(models.Scenario.id == scenario_id).first()
        if scenario is None:
            raise HTTPException(status_code=404, detail="Scenario not found")

        result = orchestrator.generate_for_scenario(session, scenario_id)
        if result is None:
            # génération invalide / échec explicite
            raise HTTPException(status_code=404, detail="Generation failed or scenario not found")
        return result
    finally:
        session.close()

# Nouvelle route pour le raffinement

@app.post("/scenarios/{scenario_id}/refine", response_model=models.RefineResult)
def refine_scenario(scenario_id: int, refine_request: models.RefineRequest):
    logging.info(f"POST /scenarios/{scenario_id}/refine called")
    session = db_session()
    try:
        result = orchestrator.refine_scenario(session, scenario_id, refine_request)
        if result is None:
            raise HTTPException(status_code=404, detail="Scenario not found")
        return result
    finally:
        session.close()

@app.post("/scenarios/{scenario_id}/evaluate", response_model=models.CodeEvaluationOut)
def evaluate_scenario(scenario_id: int):
    logging.info(f"POST /scenarios/{scenario_id}/evaluate called")
    session = db_session()
    try:
        evaluation = orchestrator.evaluate_scenario_code(session, scenario_id)
        if evaluation is None:
            raise HTTPException(status_code=404, detail="Scenario not found or not generated")
        return evaluation
    finally:
        session.close()

@app.post("/runs/{scenario_id}/execute", response_model=models.RunOut)
def execute_run(scenario_id: int):
    session = db_session()
    try:
        run = orchestrator.execute_run(session, scenario_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Scenario not found or not generated")
        return run
    finally:
        session.close()

@app.get("/runs", response_model=List[models.RunOut])
def list_runs():
    logging.info("GET /runs called")
    session = db_session()
    try:
        runs = orchestrator.list_runs(session)
        return runs
    finally:
        session.close()

@app.post("/scenarios/{scenario_id}/evaluate", response_model=models.CodeEvaluationOut)
def evaluate_scenario_code(scenario_id: int):
    """Évalue la qualité du code généré pour un scénario"""
    logging.info(f"POST /scenarios/{scenario_id}/evaluate called")
    session = db_session()
    try:
        evaluation = orchestrator.evaluate_scenario_code(session, scenario_id)
        if evaluation is None:
            raise HTTPException(
                status_code=404, 
                detail="Scenario not found or code not generated"
            )
        return evaluation
    finally:
        session.close()

@app.get("/scenarios/{scenario_id}/evaluation", response_model=models.CodeEvaluationOut)
def get_scenario_evaluation(scenario_id: int):
    """Récupère la dernière évaluation d'un scénario"""
    logging.info(f"GET /scenarios/{scenario_id}/evaluation called")
    session = db_session()
    try:
        evaluation = session.query(models.CodeEvaluation).filter(
            models.CodeEvaluation.scenario_id == scenario_id
        ).order_by(models.CodeEvaluation.created_at.desc()).first()
        
        if evaluation is None:
            raise HTTPException(status_code=404, detail="No evaluation found")
        
        return evaluation
    finally:
        session.close()
    


class OverrideIn(BaseModel):
    attack_script: str
    ids_rules: str

@app.put("/scenarios/{scenario_id}/override", response_model=models.ScenarioOut)
def override_scenario(scenario_id: int, override: OverrideIn):
    logging.info(f"PUT /scenarios/{scenario_id}/override called")
    session = db_session()
    try:
        scenario = session.query(models.Scenario).filter(models.Scenario.id == scenario_id).first()
        if scenario is None:
            raise HTTPException(status_code=404, detail="Scenario not found")
        scenario.attack_script = override.attack_script
        scenario.ids_rules = override.ids_rules
        session.commit()
        session.refresh(scenario)
        out = models.ScenarioOut.model_validate(scenario)  # ← Corrigé ici
        return out
    finally:
        session.close()

# --- FICHIER : main.py (orchestrateur) ---
# Ce fichier expose l'API FastAPI et organise les sections suivantes :
# 1) Imports et configuration (CORS, logging)
# 2) Instanciation des services (LLMService, OrchestratorService)
# 3) Evénements lifecycle (startup -> db_init)
# 4) Handler global d'exceptions (log + réponse 500 générique)
# 5) Endpoints principaux :
#    - POST /scenarios : création d'un scénario (ScenarioIn -> ScenarioOut)
#    - GET  /scenarios : liste des scénarios
#    - POST /scenarios/{id}/generate : génération attack_script + ids_rules via LLM
#    - POST /scenarios/{id}/refine : raffinement des scripts via LLM (feedback loop)
#    - PUT  /scenarios/{id}/override : override manuel attack_script / ids_rules
#    - POST /runs/{id}/execute : exécution simulée (mock attacker / IDS)
#    - GET  /runs : liste des runs
# 6) Utilisation prudente des sessions DB : ouverture/try/finally/close pour éviter fuites

