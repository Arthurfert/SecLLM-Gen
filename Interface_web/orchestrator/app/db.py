from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models import Base

engine = create_engine("sqlite:///./orchestrator.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def db_init():
    Base.metadata.create_all(bind=engine)

def db_session():
    return SessionLocal()
