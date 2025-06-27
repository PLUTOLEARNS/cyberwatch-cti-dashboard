"""
Database models initialization
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import config

engine = create_engine(config.Config.DATABASE_URI)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))

Base = declarative_base()
Base.query = db_session.query_property()

def init_db():
    """Initialize the database by creating all tables"""
    # Import all models here to ensure they are registered properly
    import models.threat_intel
    Base.metadata.create_all(bind=engine)
