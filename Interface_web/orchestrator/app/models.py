from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.orm import declarative_base

Base = declarative_base()

# ORM

class Scenario(Base):
    __tablename__ = "scenarios"
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50))
    target_description = Column(Text)
    nmap_output = Column(Text)
    llm_instructions = Column(Text, nullable=True) # Ajouté pour stocker les instructions LLM
    use_rag = Column(Boolean, default=False)  # Option pour utiliser le RAG
    attack_script = Column(Text, nullable=True)
    ids_rules = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Run(Base):
    __tablename__ = "runs"
    id = Column(Integer, primary_key=True, index=True)
    scenario_id = Column(Integer)
    executed_at = Column(DateTime, default=datetime.utcnow)
    attack_success = Column(Boolean)
    detected_by_ids = Column(Boolean)
    raw_logs = Column(Text)


# Pydantic
class ScenarioIn(BaseModel):
    cve_id: str
    target_description: str
    nmap_output: str
    llm_instructions: Optional[str] = None # Ajouté pour les instructions LLM
    use_rag: Optional[bool] = False  # Option pour utiliser le RAG

class ScenarioOut(BaseModel):
    id: int
    cve_id: str
    target_description: str
    nmap_output: str
    llm_instructions: Optional[str] = None  # Ajouté pour les instructions LLM
    use_rag: Optional[bool] = False  # Option pour utiliser le RAG
    attack_script: Optional[str] = None
    ids_rules: Optional[str] = None
    created_at: datetime

    # corrected for Pydantic v2
    model_config = {"from_attributes": True}


class GenerationResult(BaseModel):
    scenario: ScenarioOut
    attack_script: str
    ids_rules: str

class RunOut(BaseModel):
    id: int
    scenario_id: int
    executed_at: datetime
    attack_success: bool
    detected_by_ids: bool
    raw_logs: str

    # corrected for Pydantic v2
    model_config = {"from_attributes": True}

# Modèles pour le raffinement
class RefineRequest(BaseModel):
    current_attack_script: str
    current_ids_rules: str
    feedback: str

class RefineResult(BaseModel):
    attack_script: str
    ids_rules: str

# ORM
class CodeEvaluation(Base):
    __tablename__ = "code_evaluations"
    id = Column(Integer, primary_key=True, index=True)
    scenario_id = Column(Integer)
    attack_script_score = Column(Integer)  # Score sur 100
    ids_rules_score = Column(Integer)  # Score sur 100
    overall_score = Column(Integer)  # Moyenne
    attack_feedback = Column(Text)  # Feedback détaillé
    ids_feedback = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

# Pydantic
class CodeEvaluationOut(BaseModel):
    id: int
    scenario_id: int
    attack_script_score: int
    ids_rules_score: int
    overall_score: int
    attack_feedback: str
    ids_feedback: str
    created_at: datetime
    
    model_config = {"from_attributes": True}

class EvaluationRequest(BaseModel):
    attack_script: str
    ids_rules: str
    cve_id: str
