import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.automap import automap_base
from sqlalchemy import MetaData

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    echo=True,  # logs SQL (disable in production)
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Reflection base
Base = automap_base()
metadata = MetaData()

